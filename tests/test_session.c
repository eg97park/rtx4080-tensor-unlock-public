/* SPDX-License-Identifier: GPL-2.0-only. Orchestration mocks, not hardware. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#undef NULL
#include "session.h"
static RTX_SESSION *session;
static EFI_PCI_IO_PROTOCOL pci;
static unsigned calls,inject,policy,starts,stops;
static EFI_STATUS injected;
static unsigned journals;
static unsigned displays,display_fail,verifies;
static EFI_STATUS step(unsigned expected){assert(++calls==expected);return calls==inject?injected:EFI_SUCCESS;}
EFI_STATUS EFIAPI RtxCoreValidateAssets(const RTX_CORE_ASSET a[5]){assert(a);return step(1);}
EFI_STATUS EFIAPI RtxHandoffPrepare(EFI_BOOT_SERVICES *b,const RTX_BOOT_PIN *p,RTX_HANDOFF *h){assert(b && p && h);return step(2);}
EFI_STATUS EFIAPI RtxHandoffLoad(EFI_BOOT_SERVICES *b,EFI_HANDLE app,RTX_HANDOFF *h){assert(b && app && h);h->LoadAttempted=TRUE;return step(3);}
static EFI_STATUS EFIAPI handle(EFI_HANDLE h,EFI_GUID *g,VOID **out){assert(h && g && out);*out=&pci;return step(4);}
EFI_STATUS EFIAPI RtxBoardReadState(EFI_BOOT_SERVICES *b,EFI_PCI_IO_PROTOCOL *p,UINT64 bytes,UINT32 boot,RTX_BOARD_STATE *s){
    assert(b && p==&pci && bytes==84226048 && boot==36864 && s);return step(5);}
EFI_STATUS EFIAPI RtxLeaseAcquire(EFI_SYSTEM_TABLE *st,EFI_HANDLE app,EFI_HANDLE target,EFI_HANDLE intel,const RTX_BOARD_STATE *e,RTX_OWNER_WORKSPACE *w,RTX_LEASE *l){
    assert(st && app && target && intel && e && w && l && session->Handoff.LoadAttempted);stops++;
    l->StopAttempted=TRUE;l->Pci=&pci;l->Phase=RtxLeaseHeld;return step(6);}
BOOLEAN EFIAPI RtxLeaseMustRemainResident(const RTX_LEASE *l){return l->StopAttempted;}
EFI_STATUS EFIAPI RtxDmaInit(RTX_DMA_ARENA *a,EFI_PCI_IO_PROTOCOL *p){assert(a && p==&pci);a->Pci=p;return step(7);}
EFI_STATUS EFIAPI RtxDeviceInit(RTX_DEVICE *d,EFI_SYSTEM_TABLE *st,RTX_LEASE *l,RTX_DMA_ARENA *a,RTX_OWNER_WORKSPACE *w){
    assert(d && st && l && a && w);d->Arena=a;return step(8);}
EFI_STATUS EFIAPI RtxCoreRun(RTX_CORE *c,RTX_DEVICE *d,const RTX_CORE_ASSET a[5]){
    assert(c && d && a);c->CleanupComplete=policy!=1;c->Retained=policy==2;c->UnlockReported=policy!=3;return step(9);}
BOOLEAN EFIAPI RtxDmaIsEmpty(const RTX_DMA_ARENA *a){assert(a);return policy!=4;}
EFI_STATUS EFIAPI RtxDeviceVerifyReadyToBoot(RTX_DEVICE *d){assert(d);return step(10+verifies++);}
EFI_STATUS EFIAPI RtxHandoffStart(EFI_BOOT_SERVICES *b,RTX_HANDOFF *h){assert(b && h && (!policy || policy==7));assert(displays==4 && verifies==2);starts++;return step(12);}
EFI_STATUS EFIAPI RtxDisplayCheck(EFI_SYSTEM_TABLE *st,EFI_HANDLE intel,RTX_DISPLAY_GUARD *g,UINTN stage){
    assert(st && intel==(VOID *)3 && g==&session->Display && stage==displays++);
    assert(calls==(stage==0?3u:stage==1?6u:10u));
    assert(stage<2 || session->Core.CleanupComplete);
    return display_fail==stage+1?injected:EFI_SUCCESS;
}
static EFI_STATUS EFIAPI journal(VOID *p,const RTX_SESSION *s){
    assert(!p && s==session);journals++;
    assert((journals==1 && calls==3 && s->Phase==RtxSessionBootLoaded) ||
           (journals==2 && calls==10 && s->Phase==RtxSessionFinalCheck));
    return (policy==5 && journals==1) || (policy==6 && journals==2)?EFI_DEVICE_ERROR:EFI_SUCCESS;
}
int main(void){
    session=calloc(1,sizeof(*session));RTX_OWNER_WORKSPACE *w=calloc(1,sizeof(*w));assert(session && w);
    EFI_BOOT_SERVICES bs={.HandleProtocol=handle};EFI_SYSTEM_TABLE st={.BootServices=&bs};RTX_CORE_ASSET assets[5]={0};RTX_BOOT_PIN pin={0};
    unsigned cases=0;
    const RTX_SESSION_STEP failed_steps[]={RtxStepWindowsStart,RtxStepAssets,RtxStepBootPrepare,
        RtxStepBootLoad,RtxStepPciHandle,RtxStepEntryBoard,RtxStepLease,RtxStepDmaInit,
        RtxStepDeviceInit,RtxStepCore,RtxStepVerify,RtxStepReverify,RtxStepWindowsStart};
    for(unsigned i=0;i<=12;i++)for(unsigned kind=0;kind<3;kind++){
        memset(session,0,sizeof(*session));calls=starts=stops=policy=displays=verifies=0;inject=i;
        injected=kind==0?EFI_DEVICE_ERROR:kind==1?EFI_WARN_UNKNOWN_GLYPH:EFI_NOT_READY;
        EFI_STATUS r=RtxSessionRunApproved(session,&st,(VOID *)1,(VOID *)2,(VOID *)3,w,assets,&pin);
        assert(EFI_ERROR(r) && session->Attempted && session->MustRemainResident==(i==0 || i>=3));
        assert(starts==(i==0 || i==12) && stops==(i==0 || i>=6));
        assert(session->Step==failed_steps[i]);
        if(i && kind==2)assert(r==EFI_NOT_READY);
        if(!i)assert(r==EFI_ABORTED && session->Phase==RtxSessionStarting);
        unsigned before=calls;assert(RtxSessionRunApproved(session,&st,(VOID *)1,(VOID *)2,(VOID *)3,w,assets,&pin)==EFI_ALREADY_STARTED && calls==before);
        assert(session->Step==failed_steps[i]);cases++;
    }
    for(policy=1;policy<=4;policy++){
        memset(session,0,sizeof(*session));calls=starts=stops=inject=displays=verifies=0;
        assert(EFI_ERROR(RtxSessionRunApproved(session,&st,(VOID *)1,(VOID *)2,(VOID *)3,w,assets,&pin)));
        assert(calls==9 && !starts && session->MustRemainResident);cases++;
        assert(session->Step==RtxStepCorePostcondition);
    }
    for(policy=5;policy<=7;policy++){
        memset(session,0,sizeof(*session));session->Journal=journal;calls=starts=stops=inject=journals=displays=verifies=0;
        assert(EFI_ERROR(RtxSessionRunApproved(session,&st,(VOID *)1,(VOID *)2,(VOID *)3,w,assets,&pin)));
        assert(session->MustRemainResident && journals==(policy==5?1u:2u));
        assert(starts==(policy==7) && calls==(policy==5?3u:policy==6?10u:12u));cases++;
        assert(session->Step==(policy==5?RtxStepPreStopJournal:policy==6?RtxStepFinalJournal:RtxStepWindowsStart));
    }
    memset(session,0,sizeof(*session));session->Journal=journal;calls=starts=stops=policy=journals=displays=verifies=0;
    inject=11;injected=EFI_NOT_READY;
    assert(RtxSessionRunApproved(session,&st,(VOID *)1,(VOID *)2,(VOID *)3,w,assets,&pin)==EFI_NOT_READY);
    assert(!starts && session->Step==RtxStepReverify && session->MustRemainResident);cases++;
    const RTX_SESSION_STEP display_steps[]={RtxStepDisplayBefore,RtxStepDisplayLease,RtxStepDisplayCore,RtxStepDisplayStart};
    for(display_fail=1;display_fail<=4;display_fail++)for(unsigned kind=0;kind<3;kind++){
        memset(session,0,sizeof(*session));session->Journal=journal;
        calls=starts=stops=policy=journals=displays=verifies=inject=0;
        injected=kind==0?EFI_NOT_READY:kind==1?EFI_DEVICE_ERROR:EFI_WARN_UNKNOWN_GLYPH;
        assert(EFI_ERROR(RtxSessionRunApproved(session,&st,(VOID *)1,(VOID *)2,(VOID *)3,w,assets,&pin)));
        assert(!starts && session->Step==display_steps[display_fail-1] && session->MustRemainResident);
        assert(journals==(display_fail==1?0u:display_fail==4?2u:1u));
        assert(stops==(display_fail>1));cases++;
    }
    free(w);free(session);printf("UEFI session order/terminal failure: %u CPU cases PASS; all dependency responses synthetic\n",cases);return 0;
}
