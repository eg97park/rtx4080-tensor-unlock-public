/* SPDX-License-Identifier: GPL-2.0-only. CPU-only service simulation. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#undef NULL
#include "handoff.h"
#include "sha256.h"
static EFI_BOOT_SERVICES bs;
static EFI_SIMPLE_FILE_SYSTEM_PROTOCOL fs;
static EFI_FILE_PROTOCOL root,file;
static EFI_LOADED_IMAGE_PROTOCOL child;
static EFI_HANDLE volume=(VOID *)1,parent=(VOID *)2,child_handle=(VOID *)3;
static UINT8 esp[4096],contents[1024];
static UINTN position;
static RTX_BOOT_PIN pin;
static RTX_HANDOFF state;
static VOID *allocs[8];static unsigned alloc_count,steps,fail_at,mode,loads,starts;
static EFI_STATUS injected;
static EFI_STATUS step(void){return ++steps==fail_at?injected:EFI_SUCCESS;}
static VOID *alloc(UINTN size){assert(alloc_count<8);VOID *p=malloc(size);assert(p);allocs[alloc_count++]=p;return p;}
static EFI_STATUS EFIAPI pool(EFI_MEMORY_TYPE type,UINTN n,VOID **p){assert(type==EfiLoaderData);*p=alloc(n);return step();}
static EFI_STATUS EFIAPI release(VOID *p){EFI_STATUS s=step();if(s!=EFI_SUCCESS)return s;unsigned i=0;while(i<alloc_count && allocs[i]!=p)i++;assert(i<alloc_count);free(p);allocs[i]=allocs[--alloc_count];return s;}
static EFI_STATUS EFIAPI locate(EFI_LOCATE_SEARCH_TYPE t,EFI_GUID *g,VOID *k,UINTN *n,EFI_HANDLE **out){
    (void)g;assert(t==ByProtocol && !k);*n=mode==1?2:1;*out=alloc(*n*sizeof(**out));for(UINTN i=0;i<*n;i++)(*out)[i]=volume;return step();}
static EFI_STATUS EFIAPI protocol(EFI_HANDLE h,EFI_GUID *g,VOID **out){
    if(h==child_handle)*out=&child;
    else {assert(h==volume);*out=g->Data1==0x09576e91?(VOID *)esp:(VOID *)&fs;}
    return step();}
static EFI_STATUS EFIAPI open_volume(EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *f,EFI_FILE_PROTOCOL **out){assert(f==&fs);*out=&root;return step();}
static EFI_STATUS EFIAPI open_file(EFI_FILE_PROTOCOL *r,EFI_FILE_PROTOCOL **out,CHAR16 *name,UINT64 m,UINT64 a){
    static CHAR16 expected[]=L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi";
    assert(r==&root && !memcmp(name,expected,sizeof(expected)) && m==EFI_FILE_MODE_READ && !a);*out=&file;return step();}
static EFI_STATUS EFIAPI set_position(EFI_FILE_PROTOCOL *f,UINT64 pos){assert(f==&file);position=pos==MAX_UINT64?sizeof(contents):(UINTN)pos;return step();}
static EFI_STATUS EFIAPI get_position(EFI_FILE_PROTOCOL *f,UINT64 *pos){assert(f==&file);*pos=mode==2?32:position;return step();}
static EFI_STATUS EFIAPI read_file(EFI_FILE_PROTOCOL *f,UINTN *n,VOID *out){
    assert(f==&file);if(position==sizeof(contents)){*n=mode==4?1:0;return step();}
    assert(position==0 && *n==sizeof(contents));memcpy(out,contents,*n);position+=*n;if(mode==3)(*n)--;return step();}
static EFI_STATUS EFIAPI close_file(EFI_FILE_PROTOCOL *f){assert(f==&file || f==&root);return step();}
static EFI_STATUS EFIAPI load(BOOLEAN boot,EFI_HANDLE p,EFI_DEVICE_PATH_PROTOCOL *path,VOID *bytes,UINTN size,EFI_HANDLE *out){
    assert(!boot && p==parent && path==state.Path && bytes==state.Bytes && size==sizeof(contents));
    assert(!memcmp(bytes,contents,size));*out=child_handle;loads++;return step();}
static EFI_STATUS EFIAPI start(EFI_HANDLE h,UINTN *n,CHAR16 **data){assert(h==child_handle && !n && !data);starts++;return step();}
static void setup(unsigned m){
    while(alloc_count)free(allocs[--alloc_count]); /* CPU test heap only */
    mode=m;steps=fail_at=loads=starts=0;injected=EFI_DEVICE_ERROR;position=0;
    memset(&state,0,sizeof(state));memset(esp,0,sizeof(esp));
    const UINT8 path[]={1,1,6,0,0,1,0x7f,0xff,4,0};memcpy(esp,path,sizeof(path));
    memset(contents,0x43,sizeof(contents));pin=(RTX_BOOT_PIN){esp,sizeof(path),{0}};GuSha256(contents,sizeof(contents),pin.FileSha256);
    fs=(EFI_SIMPLE_FILE_SYSTEM_PROTOCOL){.OpenVolume=open_volume};
    root=(EFI_FILE_PROTOCOL){.Open=open_file,.Close=close_file};
    file=(EFI_FILE_PROTOCOL){.SetPosition=set_position,.GetPosition=get_position,.Read=read_file,.Close=close_file};
    bs=(EFI_BOOT_SERVICES){.LocateHandleBuffer=locate,.HandleProtocol=protocol,.AllocatePool=pool,.FreePool=release,.LoadImage=load,.StartImage=start};
    child=(EFI_LOADED_IMAGE_PROTOCOL){.ParentHandle=parent,.DeviceHandle=volume};
    if(m==5)pin.FileSha256[0]^=1;
    if(m==6)child.DeviceHandle=parent;
    if(m==7)child.ParentHandle=volume;
    if(m==8)child.LoadOptionsSize=2;
    if(m==9)child.LoadOptions=&child;
}
int main(void){
    setup(0);assert(RtxHandoffPrepare(&bs,&pin,&state)==EFI_SUCCESS && state.Verified);
    assert(!state.File && !state.Root && !state.Handles && !loads && !starts);
    unsigned prepare_steps=steps;assert(RtxHandoffPrepare(&bs,&pin,&state)==EFI_ALREADY_STARTED);
    assert(RtxHandoffLoad(&bs,parent,&state)==EFI_SUCCESS && state.Loaded && loads==1);
    unsigned load_steps=steps;assert(RtxHandoffLoad(&bs,parent,&state)==EFI_ALREADY_STARTED);
    assert(RtxHandoffStart(&bs,&state)==EFI_DEVICE_ERROR && starts==1);
    assert(RtxHandoffStart(&bs,&state)==EFI_ALREADY_STARTED);
    unsigned cases=1;
    for(unsigned i=1;i<=load_steps;i++)for(unsigned warning=0;warning<2;warning++){
        setup(0);fail_at=i;injected=warning?EFI_WARN_UNKNOWN_GLYPH:EFI_DEVICE_ERROR;
        EFI_STATUS s=RtxHandoffPrepare(&bs,&pin,&state);
        if(i<=prepare_steps)assert(s!=EFI_SUCCESS && !state.Verified && !loads);
        else {assert(s==EFI_SUCCESS);assert(RtxHandoffLoad(&bs,parent,&state)!=EFI_SUCCESS && !state.Loaded);}
        assert(!starts);assert(RtxHandoffStart(&bs,&state)==EFI_NOT_READY);cases++;
    }
    for(unsigned m=1;m<=9;m++){
        setup(m);EFI_STATUS s=RtxHandoffPrepare(&bs,&pin,&state);
        if(m<=5)assert(s!=EFI_SUCCESS && !state.Verified && !loads);
        else {assert(s==EFI_SUCCESS);assert(RtxHandoffLoad(&bs,parent,&state)!=EFI_SUCCESS && !state.Loaded);}
        assert(!starts);cases++;
    }
    setup(0);assert(RtxHandoffPrepare(&bs,&pin,&state)==EFI_SUCCESS);((UINT8 *)state.Bytes)[0]^=1;
    assert(RtxHandoffLoad(&bs,parent,&state)==EFI_SECURITY_VIOLATION && !loads);cases++;
    setup(0);pin.EspPathBytes=5;assert(RtxHandoffPrepare(&bs,&pin,&state)==EFI_INVALID_PARAMETER && !steps);cases++;
    setup(0);while(alloc_count)free(allocs[--alloc_count]);
    printf("Windows handoff: %u CPU cases PASS; no actual EFI loaded/executed\n",cases);return 0;
}
