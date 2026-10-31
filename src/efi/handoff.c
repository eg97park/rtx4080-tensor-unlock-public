/* SPDX-License-Identifier: GPL-2.0-only */
#include "handoff.h"
#include <Protocol/DevicePath.h>
#include "sha256.h"
static EFI_GUID fs_guid=EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
static EFI_GUID path_guid=EFI_DEVICE_PATH_PROTOCOL_GUID;
static EFI_GUID loaded_guid=EFI_LOADED_IMAGE_PROTOCOL_GUID;
static const CHAR16 filename[]=L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi";
static BOOLEAN equal(const VOID *a,const VOID *b,UINTN n) {
    const UINT8 *x=a,*y=b;for(UINTN i=0;i<n;i++)if(x[i]!=y[i])return FALSE;return TRUE;
}
static EFI_STATUS fail(RTX_HANDOFF *h,EFI_STATUS s) {
    h->Failure=EFI_ERROR(s)?s:EFI_DEVICE_ERROR;return h->Failure;
}
/* Bounded, single-instance full path; reject an already appended file path. */
static UINTN path_size(const UINT8 *p) {
    if(!p)return 0;
    UINTN off=0;
    for(UINTN i=0;i<128;i++) {
        if(off>4092)return 0;
        UINTN n=p[off+2]|((UINTN)p[off+3]<<8);
        if(n<4 || n>4096-off)return 0;
        if(p[off]==0x7f)return n==4 && p[off+1]==0xff?off+4:0;
        if(p[off]==4 && p[off+1]==4)return 0;
        off+=n;
    }
    return 0;
}
EFI_STATUS EFIAPI RtxHandoffPrepare(EFI_BOOT_SERVICES *bs,const RTX_BOOT_PIN *pin,RTX_HANDOFF *h) {
    if(!h)return EFI_INVALID_PARAMETER;
    if(h->Attempted)return EFI_ALREADY_STARTED;
    if(!bs || !pin || !pin->EspPath || pin->EspPathBytes<4 || pin->EspPathBytes>4096 ||
       !bs->LocateHandleBuffer || !bs->HandleProtocol || !bs->AllocatePool || !bs->FreePool)
        return EFI_INVALID_PARAMETER;
    /* The supplied private pin is a trusted build input with its full length;
     * avoid reading past it even if a caller supplies a malformed final node. */
    UINTN off=0;
    while(off+4<=pin->EspPathBytes) {
        UINTN n=pin->EspPath[off+2]|((UINTN)pin->EspPath[off+3]<<8);
        if(n<4 || n>pin->EspPathBytes-off)return EFI_INVALID_PARAMETER;
        if(pin->EspPath[off]==0x7f)break;
        off+=n;
    }
    if(off+4!=pin->EspPathBytes || path_size(pin->EspPath)!=pin->EspPathBytes)return EFI_INVALID_PARAMETER;
    h->Attempted=TRUE;UINTN count=0;
    EFI_STATUS s=bs->LocateHandleBuffer(ByProtocol,&fs_guid,NULL,&count,&h->Handles);
    if(s!=EFI_SUCCESS)return fail(h,s);
    if(!h->Handles || !count || count>4096)return fail(h,EFI_COMPROMISED_DATA);
    for(UINTN i=0;i<count;i++) {
        EFI_DEVICE_PATH_PROTOCOL *p=NULL;
        s=bs->HandleProtocol(h->Handles[i],&path_guid,(VOID **)&p);
        if(s!=EFI_SUCCESS || !p)return fail(h,s);
        UINTN n=path_size((UINT8 *)p);
        if(!n)return fail(h,EFI_COMPROMISED_DATA);
        if(n==pin->EspPathBytes && equal(p,pin->EspPath,n)) {
            if(h->Volume)return fail(h,EFI_ACCESS_DENIED);
            h->Volume=h->Handles[i];
        }
    }
    s=bs->FreePool(h->Handles);if(s!=EFI_SUCCESS)return fail(h,s);h->Handles=NULL;
    if(!h->Volume)return fail(h,EFI_NOT_FOUND);
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *fs=NULL;
    s=bs->HandleProtocol(h->Volume,&fs_guid,(VOID **)&fs);
    if(s!=EFI_SUCCESS || !fs || !fs->OpenVolume)return fail(h,s);
    s=fs->OpenVolume(fs,&h->Root);
    if(s!=EFI_SUCCESS || !h->Root || !h->Root->Open)return fail(h,s);
    s=h->Root->Open(h->Root,&h->File,(CHAR16 *)filename,EFI_FILE_MODE_READ,0);
    if(s!=EFI_SUCCESS || !h->File || !h->File->Read || !h->File->SetPosition ||
       !h->File->GetPosition || !h->File->Close || !h->Root->Close)return fail(h,s);
    s=h->File->SetPosition(h->File,MAX_UINT64);if(s!=EFI_SUCCESS)return fail(h,s);
    UINT64 size=0;s=h->File->GetPosition(h->File,&size);if(s!=EFI_SUCCESS)return fail(h,s);
    if(size<512 || size>16*1024*1024)return fail(h,EFI_BAD_BUFFER_SIZE);
    h->Size=(UINTN)size;s=h->File->SetPosition(h->File,0);if(s!=EFI_SUCCESS)return fail(h,s);
    s=bs->AllocatePool(EfiLoaderData,h->Size,&h->Bytes);
    if(s!=EFI_SUCCESS || !h->Bytes)return fail(h,s);
    UINTN read=h->Size;s=h->File->Read(h->File,&read,h->Bytes);
    if(s!=EFI_SUCCESS || read!=h->Size)return fail(h,s);
    UINT8 extra=0;read=1;s=h->File->Read(h->File,&read,&extra);
    if(s!=EFI_SUCCESS || read)return fail(h,s);
    s=h->File->Close(h->File);if(s!=EFI_SUCCESS)return fail(h,s);h->File=NULL;
    s=h->Root->Close(h->Root);if(s!=EFI_SUCCESS)return fail(h,s);h->Root=NULL;
    UINT8 hash[32];GuSha256(h->Bytes,h->Size,hash);
    if(!equal(hash,pin->FileSha256,32))return fail(h,EFI_SECURITY_VIOLATION);
    for(UINTN i=0;i<32;i++)h->VerifiedHash[i]=hash[i];
    UINTN path_bytes=pin->EspPathBytes+4+sizeof(filename);
    s=bs->AllocatePool(EfiLoaderData,path_bytes,(VOID **)&h->Path);
    if(s!=EFI_SUCCESS || !h->Path)return fail(h,s);
    UINT8 *p=(UINT8 *)h->Path;
    for(UINTN i=0;i<pin->EspPathBytes-4;i++)p[i]=pin->EspPath[i];
    p+=pin->EspPathBytes-4;p[0]=4;p[1]=4;p[2]=(UINT8)(4+sizeof(filename));p[3]=0;
    for(UINTN i=0;i<sizeof(filename);i++)p[4+i]=((const UINT8 *)filename)[i];
    p+=4+sizeof(filename);p[0]=0x7f;p[1]=0xff;p[2]=4;p[3]=0;
    h->Verified=TRUE;return EFI_SUCCESS;
}
EFI_STATUS EFIAPI RtxHandoffLoad(EFI_BOOT_SERVICES *bs,EFI_HANDLE parent,RTX_HANDOFF *h) {
    if(!bs || !bs->LoadImage || !bs->HandleProtocol || !h || !parent)return EFI_INVALID_PARAMETER;
    if(h->LoadAttempted)return EFI_ALREADY_STARTED;
    if(h->Failure || !h->Verified || !h->Path || !h->Bytes || !h->Volume)return EFI_NOT_READY;
    UINT8 hash[32];GuSha256(h->Bytes,h->Size,hash);
    if(!equal(hash,h->VerifiedHash,32))return fail(h,EFI_SECURITY_VIOLATION);
    h->LoadAttempted=TRUE;
    EFI_STATUS s=bs->LoadImage(FALSE,parent,h->Path,h->Bytes,h->Size,&h->Child);
    if(s!=EFI_SUCCESS || !h->Child || h->Child==parent)return fail(h,s);
    EFI_LOADED_IMAGE_PROTOCOL *child=NULL;
    s=bs->HandleProtocol(h->Child,&loaded_guid,(VOID **)&child);
    if(s!=EFI_SUCCESS || !child || child->ParentHandle!=parent || child->DeviceHandle!=h->Volume ||
       child->LoadOptionsSize || child->LoadOptions)return fail(h,s);
    h->Loaded=TRUE;return EFI_SUCCESS;
}
EFI_STATUS EFIAPI RtxHandoffStart(EFI_BOOT_SERVICES *bs,RTX_HANDOFF *h) {
    if(!bs || !bs->StartImage || !h)return EFI_INVALID_PARAMETER;
    if(h->StartAttempted)return EFI_ALREADY_STARTED;
    if(h->Failure || !h->Loaded || !h->Child)return EFI_NOT_READY;
    h->StartAttempted=TRUE;
    EFI_STATUS s=bs->StartImage(h->Child,NULL,NULL);
    /* Even EFI_SUCCESS returning to us is NOT a successful Windows handoff. */
    return fail(h,s);
}
