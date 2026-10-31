// SPDX-License-Identifier: GPL-2.0-only
// CPU-only plan/readback tests. The runner replaces every native display API
// with a throwing stub before compiling the production sources.
using System;
using System.Collections.Generic;
using Ccd=RtxReadOnlyDisplayConfig;
using Isolation=RtxDisplayIsolation;

public static class DisplayIsolationHostTests {
    private static List<string> passed;
    private static void Check(string name,bool ok){if(!ok)throw new Exception(name);passed.Add(name);}
    private static void Reject(string name,Action action){
        bool failed=false;
        try{action();}catch(InvalidOperationException){failed=true;}
        Check(name,failed);
    }
    private static Ccd.NameResult Name(string name){return new Ccd.NameResult{Status=0,Name=name};}
    private static Ccd.Snapshot Pair(bool high){
        var s=new Ccd.Snapshot{QueryFlags=82,Paths=new Ccd.PathResult[2],Modes=new Ccd.Mode[6]};
        for(int n=0;n<2;n++){
            var luid=new Ccd.Luid{Low=(uint)(101+n)};
            uint target=(uint)(n==0?53304:0),index=(uint)(n*3);
            var native=new Ccd.Path{Flags=9,Source=new Ccd.Source{Adapter=luid,Id=0,ModeIndex=((index+1)<<16)|0xffff,Status=1},
                Target=new Ccd.Target{Adapter=luid,Id=target,ModeIndex=(index<<16)|(index+2),
                    Technology=(uint)(n==0?5:0xffffffff),Available=1,Rotation=1,Scaling=1,Scanline=1,Status=1,
                    Refresh=new Ccd.Rational{Numerator=(uint)(n==0&&high?133275000:59400000),Denominator=(uint)(n==0&&high?925600:990000)}}};
            string adapter=n==0?@"\\?\PCI#VEN_8086&DEV_7D67&FIXTURE":@"\\?\ROOT#BasicDisplay#0000#FIXTURE";
            s.Paths[n]=new Ccd.PathResult{Native=native,SourceModeIndex=index+1,TargetModeIndex=index,
                SourceAdapterName=Name(adapter),TargetAdapterName=Name(adapter),
                TargetName=new Ccd.NameResult{Status=0,Name="Odyssey G70D",MonitorPath=@"\\?\DISPLAY#SAME069#FIXTURE"}};
            s.Modes[index]=new Ccd.Mode{Type=2,Id=target,Adapter=luid,Raw0=(ulong)(high?133275000:59400000),Raw5=123};
            s.Modes[index+1]=new Ccd.Mode{Type=1,Id=0,Adapter=luid,SourceWidth=(uint)(n==0?3840:1920),
                SourceHeight=(uint)(n==0?2160:1080),SourceFormat=4,SourceX=n==0?0:3840};
            s.Modes[index+2]=new Ccd.Mode{Type=3,Id=target,Adapter=luid,Raw0=111,Raw1=222};
        }
        return s;
    }
    private static Ccd.Snapshot Single(bool high){
        var s=Pair(high);s.Paths=new Ccd.PathResult[]{s.Paths[0]};Array.Resize(ref s.Modes,3);return s;
    }
    private static void ChangeRejected(string name,Action<Ccd.Snapshot> change){
        var p=Isolation.Prepare(Pair(true));var after=Single(true);change(after);
        Reject(name,()=>Isolation.VerifyIntelRetained(p,after));
    }
    public static string[] Run(){
        passed=new List<string>();
        foreach(bool high in new bool[]{false,true}){
            var p=Isolation.Prepare(Pair(high));Check(high?"144 Hz pair":"60 Hz pair",!p.AlreadyIsolated);
            Isolation.VerifyIntelRetained(p,Single(high));Check(high?"144 Hz preserved":"60 Hz preserved",true);
            var one=Isolation.Prepare(Single(high));
            Check(high?"144 Hz no-op":"60 Hz no-op",one.AlreadyIsolated && Isolation.Validate(one,false)==0 && Isolation.Apply(one,false)==0);
        }
        // Confirm the native test boundary actually throws, never calls Windows.
        Reject("native boundary blocked",()=>Isolation.Apply(Isolation.Prepare(Pair(false)),false));
        ChangeRejected("refresh rate changed",s=>{s.Paths[0].Native.Target.Refresh.Numerator=59400000;s.Paths[0].Native.Target.Refresh.Denominator=990000;});
        ChangeRejected("target timings changed",s=>s.Modes[0].Raw0++);
        ChangeRejected("source pixel format changed",s=>s.Modes[1].SourceFormat=3);
        ChangeRejected("desktop image changed",s=>s.Modes[2].Raw1++);
        ChangeRejected("resolution changed",s=>s.Modes[1].SourceWidth=1920);
        ChangeRejected("rotation changed",s=>s.Paths[0].Native.Target.Rotation=2);
        ChangeRejected("monitor connector changed",s=>s.Paths[0].TargetName.MonitorPath+= "-OTHER");
        ChangeRejected("unexpected adapter",s=>s.Paths[0].SourceAdapterName=Name(@"\\?\PCI#VEN_10DE&DEV_2704&FIXTURE"));
        ChangeRejected("invalid desktop reference",s=>s.Paths[0].Native.Target.ModeIndex=0xffff);
        ChangeRejected("stale mode index metadata",s=>s.Paths[0].SourceModeIndex=0);
        ChangeRejected("zero refresh denominator",s=>s.Paths[0].Native.Target.Refresh.Denominator=0);
        var before=Pair(true);var plan=Isolation.Prepare(before);before.Modes[0].Raw0++;
        Isolation.VerifyIntelRetained(plan,Single(true));Check("plan owns mode snapshot",true);
        var reindexed=Single(true);var mode=reindexed.Modes[0];reindexed.Modes[0]=reindexed.Modes[1];reindexed.Modes[1]=mode;
        reindexed.Paths[0].SourceModeIndex=0;reindexed.Paths[0].Native.Source.ModeIndex=0xffff;
        reindexed.Paths[0].TargetModeIndex=1;reindexed.Paths[0].Native.Target.ModeIndex=0x10002;
        Isolation.VerifyIntelRetained(plan,reindexed);Check("equivalent reindexed mode table",true);
        Reject("duplicate display not removed",()=>Isolation.VerifyIntelRetained(plan,Pair(true)));
        return passed.ToArray();
    }
}
