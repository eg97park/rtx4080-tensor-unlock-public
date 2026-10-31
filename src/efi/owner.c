/* SPDX-License-Identifier: GPL-2.0-only */
#include "private_board_pins.h" /* Local reviewed digests; intentionally not distributed. */
#include "owner.h"
#include <Protocol/PciIo.h>
#include <Protocol/GraphicsOutput.h>
#include <Protocol/SimpleTextOut.h>
#include "sha256.h"

static EFI_GUID pci_guid=EFI_PCI_IO_PROTOCOL_GUID;
static EFI_GUID binding_guid=EFI_DRIVER_BINDING_PROTOCOL_GUID;
static EFI_GUID loaded_guid=EFI_LOADED_IMAGE_PROTOCOL_GUID;
static EFI_GUID gop_guid=EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID;
static EFI_GUID text_guid=EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL_GUID;
static EFI_GUID private_guid={0xfe47349a,0x7f0d,0x4641,{0x82,0x2b,0x34,0xba,0xa2,0x8e,0xcd,0xd0}};
/* SHA of the exact ROM driver's immutable .text bytes. The pinned PE has no
 * relocations in this range; tools/inspect_nvidia_gop.py verifies that fact.
 * No session address, mutable mapped-image hash or opaque handle is pinned. */
static const UINT8 text_sha[]={RTX_REVIEWED_GOP_TEXT_SHA256_BYTES};
    _Static_assert(sizeof(text_sha)==32,"Reviewed SHA-256 pin must contain 32 bytes");
enum {Pci=1,Binding=2,Loaded=4,Gop=8,Text=16,Private=32};
static BOOLEAN same(const VOID *a,const VOID *b,UINTN n) {
    const UINT8 *x=a,*y=b;
    for(UINTN i=0;i<n;i++)if(x[i]!=y[i])return FALSE;
    return TRUE;
}
static UINT32 flag(const EFI_GUID *g) {
    if(same(g,&pci_guid,16))return Pci;
    if(same(g,&binding_guid,16))return Binding;
    if(same(g,&loaded_guid,16))return Loaded;
    if(same(g,&gop_guid,16))return Gop;
    if(same(g,&text_guid,16))return Text;
    if(same(g,&private_guid,16))return Private;
    return 0;
}
static EFI_STATUS exact(EFI_STATUS s) {return EFI_ERROR(s)?s:EFI_DEVICE_ERROR;}
static UINTN index_of(const RTX_OWNER_WORKSPACE *w,EFI_HANDLE h) {
    for(UINTN i=0;i<w->NodeCount;i++)if(w->Nodes[i].Handle==h)return i;
    return MAX_UINTN;
}
static BOOLEAN valid_mode(UINT32 a) {return a==1 || a==2 || a==4 || a==8 || a==16 || a==32 || a==48;}
static EFI_STATUS release(EFI_BOOT_SERVICES *bs,VOID **p) {
    if(!*p)return EFI_SUCCESS;
    EFI_STATUS s=bs->FreePool(*p);
    if(s!=EFI_SUCCESS)return exact(s);
    *p=NULL;return EFI_SUCCESS;
}
static EFI_STATUS identity(EFI_BOOT_SERVICES *bs,EFI_HANDLE h,UINT32 id,UINT32 subsystem) {
    EFI_PCI_IO_PROTOCOL *pci=NULL;
    EFI_STATUS s=bs->HandleProtocol(h,&pci_guid,(VOID **)&pci);
    if(s!=EFI_SUCCESS)return exact(s);
    if(!pci || !pci->Pci.Read)return EFI_COMPROMISED_DATA;
    UINT32 config[64];
    s=pci->Pci.Read(pci,EfiPciIoWidthUint32,0,64,config);
    if(s!=EFI_SUCCESS)return exact(s);
    if(config[0]!=id || (subsystem && config[11]!=subsystem))return EFI_SECURITY_VIOLATION;
    return EFI_SUCCESS;
}
static EFI_STATUS collect(EFI_BOOT_SERVICES *bs,RTX_OWNER_WORKSPACE *w,RTX_OWNER_STATE *out) {
    EFI_HANDLE *handles=NULL;UINTN count=0;
    EFI_STATUS s=bs->LocateHandleBuffer(AllHandles,NULL,NULL,&count,&handles);
    out->Unreleased[0]=handles;
    if(s!=EFI_SUCCESS)return exact(s);
    if(!handles || !count || count>RTX_OWNER_MAX_HANDLES)return EFI_BAD_BUFFER_SIZE;
    for(UINTN i=0;i<count;i++) {
        if(!handles[i] || index_of(w,handles[i])!=MAX_UINTN)return EFI_COMPROMISED_DATA;
        w->Nodes[w->NodeCount++].Handle=handles[i];
    }
    s=release(bs,&out->Unreleased[0]);if(s!=EFI_SUCCESS)return s;
    for(UINTN i=0;i<count;i++) {
        EFI_GUID **protocols=NULL;UINTN total=0;
        s=bs->ProtocolsPerHandle(w->Nodes[i].Handle,&protocols,&total);
        out->Unreleased[1]=protocols;
        if(s!=EFI_SUCCESS)return exact(s);
        if(!protocols || !total || total>128)return EFI_BAD_BUFFER_SIZE;
        for(UINTN j=0;j<total;j++) {
            if(!protocols[j])return EFI_COMPROMISED_DATA;
            for(UINTN k=0;k<j;k++)if(same(protocols[j],protocols[k],16))return EFI_COMPROMISED_DATA;
            w->Nodes[i].Flags|=flag(protocols[j]);
            EFI_OPEN_PROTOCOL_INFORMATION_ENTRY *entries=NULL;UINTN n=0;
            s=bs->OpenProtocolInformation(w->Nodes[i].Handle,protocols[j],&entries,&n);
            out->Unreleased[2]=entries;
            if(s!=EFI_SUCCESS)return exact(s);
            if(n>256 || (n && !entries) || n>RTX_OWNER_MAX_OPENS-w->OpenCount)return EFI_BAD_BUFFER_SIZE;
            for(UINTN k=0;k<n;k++) {
                EFI_OPEN_PROTOCOL_INFORMATION_ENTRY *e=&entries[k];
                if(!valid_mode(e->Attributes) || !e->OpenCount)return EFI_COMPROMISED_DATA;
                for(UINTN a=0;a<k;a++)
                    if(e->AgentHandle==entries[a].AgentHandle && e->ControllerHandle==entries[a].ControllerHandle &&
                       e->Attributes==entries[a].Attributes)return EFI_COMPROMISED_DATA;
                w->Opens[w->OpenCount++]=(RTX_OWNER_OPEN){i,*protocols[j],*e};
            }
            s=release(bs,&out->Unreleased[2]);if(s!=EFI_SUCCESS)return s;
        }
        s=release(bs,&out->Unreleased[1]);if(s!=EFI_SUCCESS)return s;
    }
    for(UINTN i=0;i<count;i++)if(w->Nodes[i].Flags&Binding) {
        EFI_DRIVER_BINDING_PROTOCOL *b=NULL;
        s=bs->HandleProtocol(w->Nodes[i].Handle,&binding_guid,(VOID **)&b);
        if(s!=EFI_SUCCESS)return exact(s);
        if(!b || b->DriverBindingHandle!=w->Nodes[i].Handle)return EFI_COMPROMISED_DATA;
        UINTN image=index_of(w,b->ImageHandle);
        if(image==MAX_UINTN || !(w->Nodes[image].Flags&Loaded))return EFI_COMPROMISED_DATA;
        w->Nodes[i].Binding=b;w->Nodes[i].Image=b->ImageHandle;
    }
    return EFI_SUCCESS;
}
static EFI_STATUS driver_identity(EFI_BOOT_SERVICES *bs,RTX_OWNER_NODE *owner,RTX_OWNER_STATE *out) {
    EFI_LOADED_IMAGE_PROTOCOL *loaded=NULL;
    EFI_STATUS s=bs->HandleProtocol(owner->Image,&loaded_guid,(VOID **)&loaded);
    if(s!=EFI_SUCCESS)return exact(s);
    if(!loaded || !loaded->ImageBase || loaded->ImageSize!=0x277a0 ||
       loaded->DeviceHandle!=out->Target || owner->Image!=owner->Handle)return EFI_SECURITY_VIOLATION;
    UINTN base=(UINTN)loaded->ImageBase;
    if(base>MAX_UINTN-0x277a0)return EFI_COMPROMISED_DATA;
    EFI_DRIVER_BINDING_PROTOCOL *b=owner->Binding;
    if((UINTN)b!=base+0x21b60 || b->Version!=0x70009 ||
       (UINTN)b->Supported!=base+0x3c8 || (UINTN)b->Start!=base+0x704 ||
       (UINTN)b->Stop!=base+0x6ec || b->ImageHandle!=owner->Image ||
       b->DriverBindingHandle!=owner->Handle)return EFI_SECURITY_VIOLATION;
    if(!same((VOID *)(base+0x21bd0),&private_guid,16))return EFI_SECURITY_VIOLATION;
    UINT8 hash[32];GuSha256((VOID *)(base+0x280),137439,hash);
    if(!same(hash,text_sha,32))return EFI_SECURITY_VIOLATION;
    out->ImageBase=base;out->CodeIdentityMatched=TRUE;return EFI_SUCCESS;
}
static EFI_STATUS analyze(RTX_OWNER_WORKSPACE *w,RTX_OWNER_STATE *out,BOOLEAN stopped,EFI_HANDLE lease) {
    UINTN target=index_of(w,out->Target),intel=index_of(w,out->Intel),console=index_of(w,out->Console);
    UINTN owner=index_of(w,out->Driver);
    if(target==MAX_UINTN || intel==MAX_UINTN || console==MAX_UINTN || owner==MAX_UINTN ||
       target==intel || target==console || !(w->Nodes[target].Flags&Pci) ||
       (w->Nodes[target].Flags&(Gop|Text)) || !(w->Nodes[intel].Flags&Pci) ||
       !(w->Nodes[console].Flags&Text))return EFI_SECURITY_VIOLATION;
    if(stopped && (w->Nodes[target].Flags&Private))return EFI_ACCESS_DENIED;
    UINTN opaque_count=0,owner_count=0,lease_count=0;
    for(UINTN i=0;i<w->OpenCount;i++) {
        RTX_OWNER_OPEN *o=&w->Opens[i];EFI_OPEN_PROTOCOL_INFORMATION_ENTRY *e=&o->Entry;
        UINTN agent=index_of(w,e->AgentHandle),child=index_of(w,e->ControllerHandle);
        UINT32 a=e->Attributes;
        if(e->ControllerHandle && child==MAX_UINTN)return EFI_COMPROMISED_DATA;
        if(e->AgentHandle && agent==MAX_UINTN) {
            if(stopped || o->Node!=target || a!=2 || e->AgentHandle!=(EFI_HANDLE)w->Nodes[owner].Binding ||
               e->ControllerHandle!=out->Target || e->OpenCount!=1 ||
               !same(&o->Protocol,&private_guid,16))return EFI_COMPROMISED_DATA;
            opaque_count++;
        }
        if(a==8 || a==16 || a==48) {
            if(agent==MAX_UINTN || !(w->Nodes[agent].Flags&Binding) || child==MAX_UINTN)
                return EFI_COMPROMISED_DATA;
        }
        if(a==32 && agent==MAX_UINTN)return EFI_COMPROMISED_DATA;
        /* This board has no NVIDIA child handles. Any newly attached child,
         * console user or additional exclusive/driver owner requires review. */
        if(o->Node==target) {
            if(a==8 || a==32 || a==48)return EFI_ACCESS_DENIED;
            if(a==16) {
                EFI_HANDLE expected=stopped?lease:out->Driver;
                if(!expected || e->AgentHandle!=expected || e->ControllerHandle!=out->Target ||
                   e->OpenCount!=1 || !same(&o->Protocol,&pci_guid,16))return EFI_ACCESS_DENIED;
                if(stopped)lease_count++;else owner_count++;
            }
        }
        /* A driver's GET of its own LoadedImage with no controller is
         * self-inspection, observed here with count 1. It is not another
         * device. All other cross-controller owner/image references fail. */
        BOOLEAN self_image=o->Node==owner && e->AgentHandle==out->Driver &&
            !e->ControllerHandle && a==2 && e->OpenCount==1 && same(&o->Protocol,&loaded_guid,16);
        if((e->AgentHandle==out->Driver || (agent!=MAX_UINTN && w->Nodes[agent].Image==out->Image)) &&
           !self_image && (stopped || o->Node!=target || e->ControllerHandle!=out->Target))return EFI_ACCESS_DENIED;
        if(a==8) {
            if(child==o->Node)return EFI_COMPROMISED_DATA;
            w->Nodes[child].Indegree++;
        }
        /* Contradictory owners of the same protocol must not disappear when
         * calculating reachability. */
        if(a==16 || a==32 || a==48)for(UINTN j=0;j<i;j++) {
            RTX_OWNER_OPEN *p=&w->Opens[j];UINT32 pa=p->Entry.Attributes;
            if((pa==16 || pa==32 || pa==48) && p->Node==o->Node &&
               same(&p->Protocol,&o->Protocol,16))return EFI_COMPROMISED_DATA;
        }
    }
    if(opaque_count!=(stopped?0u:1u) || owner_count!=(stopped?0u:1u) ||
       lease_count!=(lease?1u:0u))return EFI_SECURITY_VIOLATION;
    for(UINTN i=0;i<w->NodeCount;i++)
        if(i!=owner && w->Nodes[i].Image==out->Image)return EFI_ACCESS_DENIED;
    /* Iterative topological walk and Intel descendant closure, bounded by the
     * captured graph limits; no recursive firmware-stack growth. */
    UINTN head=0,tail=0;
    for(UINTN i=0;i<w->NodeCount;i++)if(!w->Nodes[i].Indegree)w->Queue[tail++]=i;
    w->Nodes[intel].IntelReachable=TRUE;BOOLEAN gop=FALSE;
    while(head<tail) {
        UINTN p=w->Queue[head++];
        if(w->Nodes[p].IntelReachable && (w->Nodes[p].Flags&Gop))gop=TRUE;
        for(UINTN j=0;j<w->OpenCount;j++) {
            RTX_OWNER_OPEN *o=&w->Opens[j];
            if(o->Node!=p || o->Entry.Attributes!=8)continue;
            UINTN child=index_of(w,o->Entry.ControllerHandle);
            if(w->Nodes[p].IntelReachable)w->Nodes[child].IntelReachable=TRUE;
            if(!--w->Nodes[child].Indegree)w->Queue[tail++]=child;
        }
    }
    if(head!=w->NodeCount)return EFI_COMPROMISED_DATA;
    if(w->Nodes[target].IntelReachable || !w->Nodes[console].IntelReachable || !gop)return EFI_ACCESS_DENIED;
    out->IntelPathObserved=TRUE;out->OpaqueBindingReferenceObserved=!stopped;
    out->TargetDriverGone=stopped;out->LeaseObserved=lease!=NULL;return EFI_SUCCESS;
}
static EFI_STATUS inspect(EFI_SYSTEM_TABLE *st,EFI_HANDLE target,EFI_HANDLE intel,
    const RTX_OWNER_STATE *before,EFI_HANDLE lease,RTX_OWNER_WORKSPACE *w,RTX_OWNER_STATE *out)
{
    if(!out)return EFI_INVALID_PARAMETER;
    out->InspectionComplete=FALSE;
    for(UINTN i=0;i<3;i++)if(out->Unreleased[i])return EFI_ALREADY_STARTED;
    *out=(RTX_OWNER_STATE){0};
    if(!st || !w || !target || !intel || target==intel || !st->BootServices ||
       !st->ConsoleOutHandle || !st->ConOut)return EFI_INVALID_PARAMETER;
    EFI_BOOT_SERVICES *bs=st->BootServices;
    if(!bs->LocateHandleBuffer || !bs->ProtocolsPerHandle || !bs->OpenProtocolInformation ||
       !bs->HandleProtocol || !bs->FreePool)return EFI_INVALID_PARAMETER;
    *w=(RTX_OWNER_WORKSPACE){0};
    out->Target=target;out->Intel=intel;out->Console=st->ConsoleOutHandle;out->ConsoleInterface=st->ConOut;
    EFI_STATUS s=identity(bs,target,0x270410de,0x15007377);if(s!=EFI_SUCCESS)return s;
    s=identity(bs,intel,0x7d678086,0);if(s!=EFI_SUCCESS)return s;
    s=collect(bs,w,out);if(s!=EFI_SUCCESS)return s;
    /* Select the BY_DRIVER owner, never an arbitrary address inside an image.
     * After Stop keep checking that original image instead of unloading it. */
    if(before)out->Driver=before->Driver;
    else for(UINTN i=0;i<w->OpenCount;i++) {
        RTX_OWNER_OPEN *o=&w->Opens[i];
        if(w->Nodes[o->Node].Handle==target && same(&o->Protocol,&pci_guid,16) && o->Entry.Attributes==16) {
            if(out->Driver)return EFI_ACCESS_DENIED;
            out->Driver=o->Entry.AgentHandle;
        }
    }
    UINTN owner=index_of(w,out->Driver);
    if(owner==MAX_UINTN || !(w->Nodes[owner].Flags&Binding))return EFI_SECURITY_VIOLATION;
    out->Image=w->Nodes[owner].Image;
    s=driver_identity(bs,&w->Nodes[owner],out);if(s!=EFI_SUCCESS)return s;
    if(before && (out->Image!=before->Image || out->ImageBase!=before->ImageBase ||
       out->Console!=before->Console || out->ConsoleInterface!=before->ConsoleInterface))return EFI_NOT_READY;
    s=analyze(w,out,before!=NULL,lease);if(s!=EFI_SUCCESS)return s;
    /* Read the selected interfaces again. Changes abort; no automatic retry.
     * This still does not make the entire earlier graph atomic. */
    VOID *p=NULL;
    s=bs->HandleProtocol(out->Console,&text_guid,&p);
    if(s!=EFI_SUCCESS)return exact(s);
    if(p!=out->ConsoleInterface || st->ConsoleOutHandle!=out->Console ||
       st->ConOut!=out->ConsoleInterface)return EFI_NOT_READY;
    p=NULL;s=bs->HandleProtocol(out->Driver,&binding_guid,&p);
    if(s!=EFI_SUCCESS)return exact(s);
    if(p!=w->Nodes[owner].Binding)return EFI_NOT_READY;
    s=driver_identity(bs,&w->Nodes[owner],out);if(s!=EFI_SUCCESS)return s;
    s=identity(bs,target,0x270410de,0x15007377);if(s!=EFI_SUCCESS)return s;
    s=identity(bs,intel,0x7d678086,0);if(s!=EFI_SUCCESS)return s;
    out->InspectionComplete=TRUE;return EFI_SUCCESS;
}
EFI_STATUS EFIAPI RtxOwnerInspect(EFI_SYSTEM_TABLE *st,EFI_HANDLE target,EFI_HANDLE intel,
    RTX_OWNER_WORKSPACE *w,RTX_OWNER_STATE *out)
{
    return inspect(st,target,intel,NULL,NULL,w,out);
}
EFI_STATUS EFIAPI RtxOwnerInspectAfterStop(EFI_SYSTEM_TABLE *st,const RTX_OWNER_STATE *before,
    EFI_HANDLE lease,RTX_OWNER_WORKSPACE *w,RTX_OWNER_STATE *out)
{
    if(!out)return EFI_INVALID_PARAMETER;
    if(out==before)return EFI_INVALID_PARAMETER;
    out->InspectionComplete=FALSE;
    if(!before || !before->InspectionComplete || before->TargetDriverGone ||
       !before->CodeIdentityMatched || !before->OpaqueBindingReferenceObserved ||
       !before->IntelPathObserved || lease==before->Driver)return EFI_INVALID_PARAMETER;
    return inspect(st,before->Target,before->Intel,before,lease,w,out);
}
