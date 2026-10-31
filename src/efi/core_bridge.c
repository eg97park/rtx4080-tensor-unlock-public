/* SPDX-License-Identifier: GPL-2.0-only
 * UEFI bridge to the unmodified pinned gpu-unlock-ada transaction.
 * No AD104 board constants or Linux device installation are reused.
 */
#include "private_board_pins.h" /* Local reviewed digests; intentionally not distributed. */
#include "core_bridge.h"
#include "unlock_610.h"
#include "sha256.h"
#include <stdarg.h>
#include <crypto/sha2.h>
#include "firmware_pins_610.h"
EFI_STATUS EFIAPI RtxCoreValidateAssets(const RTX_CORE_ASSET assets[5]){
    static const char *const names[]={"gpu-unlock/610.43.03/gsp_ga10x.bin",
        "gpu-unlock/610.43.03/booter_load_ad102.bin","gpu-unlock/610.43.03/gsp_boot_ad102.bin",
        "gpu-unlock/610.43.03/gsp_boot_desc_ad102.bin","gpu-unlock/610.43.03/v67-ad102-610.43.03-four-plm.bin"};
    if(!assets)return EFI_INVALID_PARAMETER;
    for(UINTN i=0;i<5;i++){
        const RTX_CORE_ASSET *a=NULL;
        for(UINTN j=0;j<5;j++){
            if(!assets[j].Name || !assets[j].Firmware.data || !assets[j].Firmware.size || assets[j].Firmware.size>(128u<<20))return EFI_INVALID_PARAMETER;
            if(!strcmp(assets[j].Name,names[i])){if(a)return EFI_COMPROMISED_DATA;a=&assets[j];}
        }
        if(!a)return EFI_NOT_FOUND;
        UINT8 digest[32];GuSha256(a->Firmware.data,a->Firmware.size,digest);BOOLEAN matched=FALSE;
        for(UINTN j=0;j<ARRAY_SIZE(firmware_pins);j++)if(!strcmp(names[i],firmware_pins[j].name)){
            if(memcmp(digest,firmware_pins[j].digest,32))return EFI_SECURITY_VIOLATION;
            matched=TRUE;break;
        }
        if(!matched)return EFI_NOT_FOUND;
    }
    return EFI_SUCCESS;
}
struct RTX_CORE_POOL {RTX_CORE_POOL *Next;UINTN Bytes;BOOLEAN Ambiguous;UINT64 Align;};
struct RTX_CORE_DMA {RTX_DMA_BUFFER Buffer;UINTN Requested;BOOLEAN Released;};
static RTX_CORE *current;
static EFI_STATUS latch(EFI_STATUS s){return current?RtxDeviceLatch(current->Device,s):EFI_NOT_READY;}
static BOOLEAN valid(struct pci_dev *p){return current && p==&current->Pci;}
static BOOLEAN dev_valid(struct device *d){return current && d==&current->Pci.dev;}
static void character(char ch){
    if(current->LogBytes+1<sizeof(current->Log)){current->Log[current->LogBytes++]=ch;current->Log[current->LogBytes]=0;}
    else current->LogTruncated=TRUE;
}
/* Only pinned core formats. Memory only: no firmware callbacks/file IO while
 * device state may be unknown. Unsupported formats stop this record explicitly. */
void RtxCoreLog(const char *format,...){
    if(!current || !format)return;
    current->LogCalls++;current->LastLogFormat=format;va_list args;va_start(args,format);
    while(*format){
        if(*format!='%'){character(*format++);continue;}format++;
        if(*format=='%'){character(*format++);continue;}
        BOOLEAN alternate=FALSE,zero=FALSE;unsigned width=0,length=0;
        if(*format=='#'){alternate=TRUE;format++;}
        if(*format=='0'){zero=TRUE;format++;}
        while(*format>='0' && *format<='9'){width=width*10+(unsigned)(*format++-'0');if(width>32)goto rejected;}
        if(*format=='l'){length=1;format++;if(*format=='l'){length=2;format++;}}
        else if(*format=='z'){length=3;format++;}
        char kind=*format;if(!kind)goto rejected;format++;
        if(kind=='s' && !length){const char *s=va_arg(args,const char *);if(!s)s="(null)";while(*s)character(*s++);continue;}
        if(kind!='x' && kind!='u' && kind!='d')goto rejected;
        UINT64 v;BOOLEAN negative=FALSE;
        if(kind=='d'){
            INT64 signed_value=length==2?va_arg(args,long long):length==1?va_arg(args,long):length==3?va_arg(args,ptrdiff_t):va_arg(args,int);
            negative=signed_value<0;v=negative?(UINT64)0-(UINT64)signed_value:(UINT64)signed_value;
        }else v=length==2?va_arg(args,unsigned long long):length==1?va_arg(args,unsigned long):length==3?va_arg(args,size_t):va_arg(args,unsigned int);
        char digits[32];unsigned n=0,base=kind=='x'?16:10;
        BOOLEAN prefix=alternate && kind=='x' && v;
        do{digits[n++]="0123456789abcdef"[v%base];v/=base;}while(v);
        unsigned count=n+(negative?1:0)+(prefix?2:0);
        if(!zero)while(width>count){character(' ');width--;}
        if(negative)character('-');
        if(prefix){character('0');character('x');}
        if(zero)while(width>count){character('0');width--;}
        while(n)character(digits[--n]);
    }
    va_end(args);return;
rejected:
    current->LogFormatRejected=TRUE;va_end(args);
}
static void *allocate(size_t n){
    if(!current || current->Device->Fault || !n || n>(128u<<20) || current->PoolBytes>(256u<<20)-n)return NULL;
    RTX_CORE_POOL *p=NULL;EFI_STATUS s=current->Device->Bs->AllocatePool(EfiLoaderData,sizeof(*p)+n,(VOID **)&p);
    if(s!=EFI_SUCCESS || !p){if(p){current->Retained=TRUE;current->AmbiguousPool=p;}
        latch(s==EFI_SUCCESS?EFI_OUT_OF_RESOURCES:s);return NULL;}
    p->Next=current->Pools;p->Bytes=n;p->Ambiguous=FALSE;current->Pools=p;current->PoolBytes+=n;
    memset(p+1,0,n);return p+1;
}
void RtxCoreFree(void *p){
    if(!p || !current)return;
    if(current->Retained || current->Device->Fault)return;
    RTX_CORE_POOL **link=&current->Pools;
    while(*link && (void *)(*link+1)!=p)link=&(*link)->Next;
    if(!*link){latch(EFI_COMPROMISED_DATA);return;}
    RTX_CORE_POOL *node=*link,*next=node->Next;UINTN n=node->Bytes;
    EFI_STATUS s=current->Device->Bs->FreePool(node);
    if(s!=EFI_SUCCESS){current->Retained=TRUE;latch(s);return;}
    *link=next;current->PoolBytes-=n;
}
void *kzalloc(size_t n,int f){(void)f;return allocate(n);}
void *kvmalloc(size_t n,int f){(void)f;return allocate(n);}
void *kvcalloc(size_t n,size_t size,int f){(void)f;if(!size || n>SIZE_MAX/size)return NULL;return allocate(n*size);}
void *devres_open_group(struct device *d,void *id,int f){(void)f;if(!dev_valid(d) || id || d->scope)return NULL;d->scope=true;return &d->scope;}
int devres_release_group(struct device *d,void *group){if(!dev_valid(d) || group!=&d->scope || !d->scope)return -EINVAL;d->scope=false;return 0;}
int request_firmware(const struct firmware **out,const char *name,struct device *d){
    if(!out || !name || !dev_valid(d))return -EINVAL;
    *out=NULL;
    for(unsigned i=0;i<5;i++)if(current->Assets[i].Name && !strcmp(current->Assets[i].Name,name)){
        if(!current->Assets[i].Firmware.data || !current->Assets[i].Firmware.size)return -ENOENT;
        *out=&current->Assets[i].Firmware;return 0;}
    return -ENOENT;
}
void release_firmware(const struct firmware *f){(void)f;/* Immutable caller-owned bytes, never DMA addresses. */}
void __module_get(void *m){(void)m;if(current)current->Retained=TRUE;}
void sha256(const u8 *data,size_t bytes,u8 out[32]){GuSha256(data,bytes,out);}
void usleep_range(unsigned long a,unsigned long b){(void)b;if(current)(void)RtxDeviceStall(current->Device,a);}
ktime_t ktime_get(void){return current?current->Device->Ticks:0;}
static BOOLEAN offset(const void *p,UINT32 *off){
    if(!current)return FALSE;
    UINTN address=(UINTN)p;UINT64 base=current->Device->Lease->HeldBoard.BarBase;
    if(address<base || address-base>0xffffffffu){latch(EFI_INVALID_PARAMETER);return FALSE;}
    *off=(UINT32)(address-base);return TRUE;
}
u32 readl(const void *p){UINT32 off=0,v=0xffffffffu;if(offset(p,&off))(void)RtxDeviceRead(current->Device,off,&v);return v;}
void writel(u32 v,void *p){UINT32 off=0;if(offset(p,&off))(void)RtxDeviceWrite(current->Device,off,v);}
void RtxCoreCopyIo(void *out,const void *in,size_t n){
    UINT32 off=0;if(!out || !offset(in,&off))return;
    memset(out,0,n);
    if(off!=0x300000 || n!=1024*1024){latch(EFI_ACCESS_DENIED);return;}
    if(RtxDeviceProm(current->Device,out,n)!=EFI_SUCCESS)return;
    static const u8 pin[]={RTX_REVIEWED_PROM_SHA256_BYTES};
    _Static_assert(sizeof(pin)==32,"Reviewed SHA-256 pin must contain 32 bytes");
    u8 digest[32];GuSha256(out,n,digest);
    if(memcmp(pin,digest,32)){memset(out,0,n);latch(EFI_SECURITY_VIOLATION);}
}
static UINTN dma_slot(void *cpu){return ((UINTN)cpu>>12)&(RTX_CORE_DMA_SLOTS-1);}
void *dma_alloc_coherent(struct device *d,size_t n,dma_addr_t *address,int flags){
    (void)flags;if(!dev_valid(d) || !address || !d->dma_mask || *d->dma_mask!=0xffffffffu || d->coherent_dma_mask!=0xffffffffu)return NULL;
    if(current->DmaCount>=RTX_CORE_DMA_SLOTS/2){latch(EFI_OUT_OF_RESOURCES);return NULL;}
    RTX_CORE_DMA *record=allocate(sizeof(*record));if(!record)return NULL;
    EFI_STATUS s=RtxDmaAllocate(current->Device->Arena,&record->Buffer,n);
    if(s!=EFI_SUCCESS){latch(s);return NULL;}
    record->Requested=n;UINTN slot=dma_slot(record->Buffer.Cpu);
    while(current->Dma[slot])slot=(slot+1)&(RTX_CORE_DMA_SLOTS-1);
    current->Dma[slot]=record;current->DmaCount++;*address=record->Buffer.Device;return record->Buffer.Cpu;
}
void dma_free_coherent(struct device *d,size_t n,void *cpu,dma_addr_t address){
    if(!dev_valid(d) || !cpu){latch(EFI_INVALID_PARAMETER);return;}
    UINTN slot=dma_slot(cpu);
    for(UINTN i=0;i<RTX_CORE_DMA_SLOTS;i++,slot=(slot+1)&(RTX_CORE_DMA_SLOTS-1)){
        RTX_CORE_DMA *r=current->Dma[slot];if(!r)break;
        if(r->Buffer.Cpu==cpu){
            if(r->Released || r->Requested!=n || r->Buffer.Device!=address){latch(EFI_COMPROMISED_DATA);return;}
            r->Released=TRUE;return; /* defer until fresh verified containment */
        }
    }
    latch(EFI_NOT_FOUND);
}
int dma_set_mask(struct device *d,u64 mask){if(!dev_valid(d) || !d->dma_mask || mask!=0xffffffffu)return -EINVAL;*d->dma_mask=mask;return 0;}
int dma_set_coherent_mask(struct device *d,u64 mask){if(!dev_valid(d) || mask!=0xffffffffu)return -EINVAL;d->coherent_dma_mask=mask;return 0;}
void dma_wmb(void){
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    if(!current || current->Device->Fault)return;
    RTX_DEVICE *d=current->Device;if(d->Busy || d->ConfigUnavailable){latch(EFI_ACCESS_DENIED);return;}
    d->Busy=TRUE;EFI_STATUS s=d->Lease->Pci->Flush(d->Lease->Pci);d->Busy=FALSE;if(s!=EFI_SUCCESS)latch(s);
}
int pci_read_config_word(struct pci_dev *p,int off,u16 *v){if(!valid(p))return -EINVAL;return RtxDeviceConfigRead(current->Device,(UINT32)off,2,v)==EFI_SUCCESS?0:-EIO;}
int pci_read_config_dword(struct pci_dev *p,int off,u32 *v){if(!valid(p))return -EINVAL;return RtxDeviceConfigRead(current->Device,(UINT32)off,4,v)==EFI_SUCCESS?0:-EIO;}
int pci_write_config_word(struct pci_dev *p,int off,u16 value){
    if(!valid(p) || off!=4 || value!=(UINT16)current->Device->Saved[1]){latch(EFI_ACCESS_DENIED);return -EIO;}
    return RtxDeviceClearMaster(current->Device)==EFI_SUCCESS?0:-EIO;
}
int pcie_capability_read_word(struct pci_dev *p,int off,u16 *v){return valid(p)?pci_read_config_word(p,current->Device->Pcie+off,v):-EINVAL;}
int pcie_capability_read_dword(struct pci_dev *p,int off,u32 *v){return valid(p)?pci_read_config_dword(p,current->Device->Pcie+off,v):-EINVAL;}
int pci_is_pcie(struct pci_dev *p){return valid(p) && current->Device->Pcie;}
int pci_select_bars(struct pci_dev *p,int r){return valid(p) && r==IORESOURCE_MEM?1:0;}
int pci_request_region(struct pci_dev *p,int bar,const char *name){(void)name;return valid(p) && !bar && current->Device->Lease->Phase==RtxLeaseHeld?0:-EBUSY;}
void pci_release_region(struct pci_dev *p,int bar){if(!valid(p) || bar)latch(EFI_INVALID_PARAMETER);/* lease stays held */}
int aperture_remove_conflicting_pci_devices(struct pci_dev *p,const char *name){(void)name;return valid(p) && current->Device->Lease->AfterClaim.IntelPathObserved?0:-EBUSY;}
int pci_enable_device_mem(struct pci_dev *p){(void)p;latch(EFI_ACCESS_DENIED);return -EOPNOTSUPP;}
void pci_disable_device(struct pci_dev *p){(void)p;latch(EFI_ACCESS_DENIED);}
resource_size_t pci_resource_len(struct pci_dev *p,int bar){return valid(p) && !bar?current->Device->Lease->HeldBoard.BarBytes:0;}
void *pci_iomap(struct pci_dev *p,int bar,unsigned long n){return valid(p) && !bar && !n?(void *)(UINTN)current->Device->Lease->HeldBoard.BarBase:NULL;}
void pci_iounmap(struct pci_dev *p,void *addr){if(!valid(p) || (UINTN)addr!=current->Device->Lease->HeldBoard.BarBase)latch(EFI_INVALID_PARAMETER);}
int pci_save_state(struct pci_dev *p){
    if(!valid(p))return -EINVAL;
    for(UINTN i=0;i<64;i++){u32 v=0;if(pci_read_config_dword(p,(int)i*4,&v) || v!=current->Device->Saved[i]){latch(EFI_NOT_READY);return -EIO;}}
    return 0;
}
void pci_restore_state(struct pci_dev *p){if(valid(p))(void)RtxDeviceRestore(current->Device);else latch(EFI_INVALID_PARAMETER);}
void pci_set_master(struct pci_dev *p){if(valid(p))(void)RtxDeviceEnableMaster(current->Device);else latch(EFI_INVALID_PARAMETER);}
void pci_clear_master(struct pci_dev *p){if(valid(p))(void)RtxDeviceClearMaster(current->Device);else latch(EFI_INVALID_PARAMETER);}
int pcie_flr(struct pci_dev *p){return valid(p) && RtxDeviceFlr(current->Device)==EFI_SUCCESS?0:-EIO;}
struct pci_dev *pci_dev_get(struct pci_dev *p){if(!valid(p))return NULL;p->refs++;return p;}
void pci_dev_put(struct pci_dev *p){if(!valid(p) || p->refs<=1){latch(EFI_INVALID_PARAMETER);return;}p->refs--;}
EFI_STATUS EFIAPI RtxCoreRun(RTX_CORE *c,RTX_DEVICE *d,const RTX_CORE_ASSET assets[5]){
    if(!c || !d || !assets || !d->Bs || !d->Bs->AllocatePool || !d->Bs->FreePool || d->Fault || !d->Lease || d->Lease->Phase!=RtxLeaseHeld ||
       !d->Arena || d->Arena->Phase!=RtxDmaCold || !RtxDmaIsEmpty(d->Arena))return EFI_NOT_READY;
    if(current || c->Attempted || c->Pools || c->DmaCount)return EFI_ALREADY_STARTED;
    c->Attempted=TRUE;c->Device=d;c->Assets=assets;c->StreamingMask=0xffffffffu;
    c->Status=RtxCoreValidateAssets(assets);
    if(c->Status!=EFI_SUCCESS){c->CleanupComplete=TRUE;return c->Status;}
    c->Pci=(struct pci_dev){.vendor=0x10de,.device=0x2704,.current_state=PCI_D0,.pm_cap=d->Pm,.refs=1};
    c->Pci.dev.dma_mask=&c->StreamingMask;c->Pci.dev.coherent_dma_mask=0xffffffffu;current=c;
    struct gpu_unlock_610_shared shared={0};
    c->CoreResult=gpu_unlock_610_load_shared(&c->Pci,&shared);
    if(!c->CoreResult)c->CoreResult=gpu_unlock_610_unlock(&c->Pci,&shared);
    gpu_unlock_610_release_shared(&shared);
    if(d->MasterAttempted && !d->ClearAttempted && !d->ConfigUnavailable)(void)RtxDeviceClearMaster(d);
    EFI_STATUS s=d->Fault;
    if(!s && !c->Retained){
        for(UINTN i=0;i<RTX_CORE_DMA_SLOTS;i++)if(c->Dma[i] && !c->Dma[i]->Released){s=EFI_NOT_READY;break;}
        if(s==EFI_SUCCESS && d->Arena->Phase==RtxDmaDeviceMayAccess)s=RtxDmaConfirmStopped(d->Arena,RtxDeviceVerifyStop,d);
        if(s==EFI_SUCCESS)s=RtxDmaReleaseAll(d->Arena);
        if(s==EFI_SUCCESS){
            for(UINTN i=0;i<RTX_CORE_DMA_SLOTS;i++)if(c->Dma[i]){RtxCoreFree(c->Dma[i]);if(d->Fault){s=d->Fault;break;}c->Dma[i]=NULL;}
        }
        if(s==EFI_SUCCESS && (c->Pools || c->Pci.refs!=1 || c->Pci.dev.scope || c->Pci.dev.devres_head.count))s=EFI_NOT_READY;
    }else if(!s)s=EFI_NOT_READY;
    c->CleanupComplete=s==EFI_SUCCESS && RtxDmaIsEmpty(d->Arena);
    c->Retained=!c->CleanupComplete;
    if(c->CleanupComplete && c->CoreResult==0)s=RtxDeviceVerifyReadyToBoot(d);
    c->UnlockReported=c->CleanupComplete && s==EFI_SUCCESS && c->CoreResult==0 && d->Verified;
    c->Status=s!=EFI_SUCCESS?s:c->CoreResult?EFI_ABORTED:!c->UnlockReported?EFI_NOT_READY:EFI_SUCCESS;
    current=NULL;return c->Status;
}
