// SPDX-License-Identifier: GPL-2.0-only
// A narrowly selected, temporary Windows desktop topology experiment.
// No driver uninstall/disable, registry persistence, reset, PCI/MMIO or reboot.
using System;
using System.Runtime.InteropServices;
using Ccd=RtxReadOnlyDisplayConfig;
public static class RtxDisplayIsolation {
    public sealed class Plan {
        public Ccd.Path[] Original, IntelOnly;
        public Ccd.Mode[] Modes;
        public string OriginalPathsBase64, OriginalModesBase64;
        public string IntelMonitorPath;
        public bool AlreadyIsolated;
    }
    [DllImport("user32.dll")] private static extern int SetDisplayConfig(uint paths,[In] Ccd.Path[] pathData,uint modes,[In] Ccd.Mode[] modeData,uint flags);
    private static string Bytes<T>(T[] values) where T:struct {
        int size=Marshal.SizeOf(typeof(T));byte[] bytes=new byte[checked(size*values.Length)];
        IntPtr p=Marshal.AllocHGlobal(size);
        try {
            for(int n=0;n<values.Length;n++){Marshal.StructureToPtr(values[n],p,false);Marshal.Copy(p,bytes,n*size,size);}
        } finally {Marshal.FreeHGlobal(p);}
        return Convert.ToBase64String(bytes);
    }
    private static bool Same(Ccd.Luid a,Ccd.Luid b){return a.Low==b.Low && a.High==b.High;}
    private static bool Is(Ccd.NameResult n,string prefix){return n!=null && n.Status==0 && n.Name!=null && n.Name.StartsWith(prefix,StringComparison.OrdinalIgnoreCase);}
    public static Plan Prepare(Ccd.Snapshot s) {
        if(s==null || s.QueryFlags!=82 || s.Paths==null || (s.Paths.Length!=1 && s.Paths.Length!=2) || s.Modes==null || s.Modes.Length<1 || s.Modes.Length>256)
            throw new InvalidOperationException("Expected Intel alone or the observed Intel/BasicDisplay pair");
        // CCD is priority ordered. Preserve the current Intel primary HDMI
        // path and its exact timings. No automatic mode selection/fallback.
        Ccd.PathResult intel=s.Paths[0],basic=s.Paths.Length==2?s.Paths[1]:null;
        if(intel==null || (s.Paths.Length==2 && basic==null))throw new InvalidOperationException("Missing display path");
        if(!Is(intel.SourceAdapterName,@"\\?\PCI#VEN_8086&DEV_7D67&") ||
           !Is(intel.TargetAdapterName,@"\\?\PCI#VEN_8086&DEV_7D67&") ||
           !Same(intel.Native.Source.Adapter,intel.Native.Target.Adapter) ||
           intel.Native.Target.Technology!=5 || intel.Native.Target.Available!=1 || intel.Native.Flags!=9 ||
           intel.Native.Target.Refresh.Numerator==0 || intel.Native.Target.Refresh.Denominator==0)
            throw new InvalidOperationException("Unexpected Intel HDMI path identity");
        if(basic!=null && (!Is(basic.SourceAdapterName,@"\\?\ROOT#BasicDisplay#0000#") ||
           !Is(basic.TargetAdapterName,@"\\?\ROOT#BasicDisplay#0000#") ||
           !Same(basic.Native.Source.Adapter,basic.Native.Target.Adapter) ||
           Same(intel.Native.Source.Adapter,basic.Native.Source.Adapter) ||
           basic.Native.Target.Available!=1 || basic.Native.Flags!=9))
            throw new InvalidOperationException("Unexpected Intel/BasicDisplay path identity");
        foreach(var p in s.Paths){
            if(p.TargetName==null || p.TargetName.Status!=0 || p.TargetName.Name!="Odyssey G70D" ||
               p.TargetName.MonitorPath==null || !p.TargetName.MonitorPath.StartsWith(@"\\?\DISPLAY#SAME069#",StringComparison.OrdinalIgnoreCase) ||
               p.SourceModeIndex!=(p.Native.Source.ModeIndex>>16) || p.TargetModeIndex!=(p.Native.Target.ModeIndex>>16) ||
               p.SourceModeIndex>=s.Modes.Length || p.TargetModeIndex>=s.Modes.Length)
                throw new InvalidOperationException("Unexpected monitor/mode reference");
            var sm=s.Modes[p.SourceModeIndex];var tm=s.Modes[p.TargetModeIndex];
            if(sm.Type!=1 || tm.Type!=2 || sm.Id!=p.Native.Source.Id || tm.Id!=p.Native.Target.Id ||
               !Same(sm.Adapter,p.Native.Source.Adapter) || !Same(tm.Adapter,p.Native.Target.Adapter))
                throw new InvalidOperationException("Mode association changed");
            uint desktop=p.Native.Target.ModeIndex&0xffff;
            if(desktop>=s.Modes.Length || s.Modes[desktop].Type!=3 || s.Modes[desktop].Id!=p.Native.Target.Id ||
               !Same(s.Modes[desktop].Adapter,p.Native.Target.Adapter))
                throw new InvalidOperationException("Desktop image association changed");
        }
        var source=s.Modes[intel.SourceModeIndex];
        if(source.SourceX!=0 || source.SourceY!=0 || source.SourceWidth!=3840 || source.SourceHeight!=2160)
            throw new InvalidOperationException("Unexpected primary geometry");
        if(basic!=null){
            var other=s.Modes[basic.SourceModeIndex];
            if(other.SourceX<3840 || other.SourceY!=0 || other.SourceWidth!=1920 || other.SourceHeight!=1080)
                throw new InvalidOperationException("Unexpected extended geometry");
        }
        var original=basic==null?new Ccd.Path[]{intel.Native}:new Ccd.Path[]{intel.Native,basic.Native};
        var modes=(Ccd.Mode[])s.Modes.Clone();
        return new Plan {Original=original,IntelOnly=new Ccd.Path[]{intel.Native},Modes=modes,
            AlreadyIsolated=basic==null,IntelMonitorPath=intel.TargetName.MonitorPath,
            OriginalPathsBase64=Bytes(original),OriginalModesBase64=Bytes(modes)};
    }
    private static bool SameMode(Ccd.Mode a,Ccd.Mode b){
        return a.Type==b.Type && a.Id==b.Id && Same(a.Adapter,b.Adapter) &&
            a.Raw0==b.Raw0 && a.Raw1==b.Raw1 && a.Raw2==b.Raw2 &&
            a.Raw3==b.Raw3 && a.Raw4==b.Raw4 && a.Raw5==b.Raw5;
    }
    public static void VerifyIntelRetained(Plan before,Ccd.Snapshot after){
        var plan=Prepare(after);
        if(!plan.AlreadyIsolated || !String.Equals(before.IntelMonitorPath,plan.IntelMonitorPath,StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Intel-only monitor readback failed");
        var a=before.IntelOnly[0];var b=plan.IntelOnly[0];
        if(!Same(a.Source.Adapter,b.Source.Adapter) || !Same(a.Target.Adapter,b.Target.Adapter) ||
           a.Source.Id!=b.Source.Id || a.Target.Id!=b.Target.Id || a.Flags!=b.Flags ||
           a.Target.Technology!=b.Target.Technology || a.Target.Rotation!=b.Target.Rotation ||
           a.Target.Scaling!=b.Target.Scaling || a.Target.Scanline!=b.Target.Scanline ||
           a.Target.Refresh.Numerator!=b.Target.Refresh.Numerator || a.Target.Refresh.Denominator!=b.Target.Refresh.Denominator ||
           (a.Source.ModeIndex&0xffff)!=(b.Source.ModeIndex&0xffff) ||
           !SameMode(before.Modes[a.Source.ModeIndex>>16],plan.Modes[b.Source.ModeIndex>>16]) ||
           !SameMode(before.Modes[a.Target.ModeIndex>>16],plan.Modes[b.Target.ModeIndex>>16]) ||
           !SameMode(before.Modes[a.Target.ModeIndex&0xffff],plan.Modes[b.Target.ModeIndex&0xffff]))
            throw new InvalidOperationException("Intel mode, timings or identity changed during isolation");
    }
    public static int Validate(Plan p,bool restore) {
        if(p.AlreadyIsolated)return 0; // no native call for an already single display
        var paths=restore?p.Original:p.IntelOnly;
        return SetDisplayConfig((uint)paths.Length,paths,(uint)p.Modes.Length,p.Modes,0x28060); // USE|VALIDATE|virtual awareness
    }
    public static int Apply(Plan p,bool restore) {
        if(p.AlreadyIsolated)return 0;
        var paths=restore?p.Original:p.IntelOnly;
        return SetDisplayConfig((uint)paths.Length,paths,(uint)p.Modes.Length,p.Modes,0x280a0); // USE|APPLY, NO SAVE/ALLOW_CHANGES
    }
}
