// SPDX-License-Identifier: GPL-2.0-only
// CCD metadata only. No SetDisplayConfig, device state change or GPU workload.
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

public static class RtxReadOnlyDisplayConfig {
    [StructLayout(LayoutKind.Sequential)] public struct Luid { public uint Low; public int High; }
    [StructLayout(LayoutKind.Sequential)] public struct Rational { public uint Numerator, Denominator; }
    [StructLayout(LayoutKind.Sequential)] public struct Source {
        public Luid Adapter; public uint Id, ModeIndex, Status;
    }
    [StructLayout(LayoutKind.Sequential)] public struct Target {
        public Luid Adapter; public uint Id, ModeIndex, Technology, Rotation, Scaling;
        public Rational Refresh; public uint Scanline; public int Available; public uint Status;
    }
    [StructLayout(LayoutKind.Sequential)] public struct Path {
        public Source Source; public Target Target; public uint Flags;
    }
    [StructLayout(LayoutKind.Explicit, Size=64)] public struct Mode {
        [FieldOffset(0)] public uint Type;
        [FieldOffset(4)] public uint Id;
        [FieldOffset(8)] public Luid Adapter;
        // Preserve the entire union, including target timings/desktop image.
        [FieldOffset(16)] public ulong Raw0;
        [FieldOffset(24)] public ulong Raw1;
        [FieldOffset(32)] public ulong Raw2;
        [FieldOffset(40)] public ulong Raw3;
        [FieldOffset(48)] public ulong Raw4;
        [FieldOffset(56)] public ulong Raw5;
        // Interpret these fields only when Type == SOURCE (1).
        [FieldOffset(16)] public uint SourceWidth;
        [FieldOffset(20)] public uint SourceHeight;
        [FieldOffset(24)] public uint SourceFormat;
        [FieldOffset(28)] public int SourceX;
        [FieldOffset(32)] public int SourceY;
    }
    public sealed class NameResult {
        public int Status; public string Name, MonitorPath;
    }
    public sealed class PathResult {
        public Path Native;
        public NameResult SourceName, SourceAdapterName, TargetAdapterName, TargetName;
        public uint SourceModeIndex, TargetModeIndex;
    }
    public sealed class Snapshot {
        public uint QueryFlags; public PathResult[] Paths; public Mode[] Modes;
        public string Note="Read-only active CCD paths. Source fields in Modes apply only to Type=1. LUIDs are boot-local.";
    }
    [DllImport("user32.dll")] private static extern int GetDisplayConfigBufferSizes(uint flags,out uint paths,out uint modes);
    [DllImport("user32.dll")] private static extern int QueryDisplayConfig(uint flags,ref uint paths,[Out] Path[] pathData,ref uint modes,[Out] Mode[] modeData,IntPtr topology);
    [DllImport("user32.dll")] private static extern int DisplayConfigGetDeviceInfo(IntPtr packet);
    private static NameResult Name(uint kind,Luid adapter,uint id) {
        int size=kind==1?84:kind==2?420:276;
        IntPtr packet=Marshal.AllocHGlobal(size);
        try {
            byte[] bytes=new byte[size];Marshal.Copy(bytes,0,packet,size);
            Marshal.WriteInt32(packet,0,(int)kind);Marshal.WriteInt32(packet,4,size);
            Marshal.WriteInt32(packet,8,unchecked((int)adapter.Low));Marshal.WriteInt32(packet,12,adapter.High);
            Marshal.WriteInt32(packet,16,unchecked((int)id));
            int result=DisplayConfigGetDeviceInfo(packet);
            var name=new NameResult {Status=result};
            if(result!=0)return name;
            Marshal.Copy(packet,bytes,0,size);
            int offset=kind==2?36:20,chars=kind==1?32:kind==2?64:128;
            name.Name=Encoding.Unicode.GetString(bytes,offset,chars*2).Split('\0')[0];
            if(kind==2)name.MonitorPath=Encoding.Unicode.GetString(bytes,164,256).Split('\0')[0];
            return name;
        } finally {Marshal.FreeHGlobal(packet);}
    }
    public static Snapshot Capture() {
        if(Marshal.SizeOf(typeof(Luid))!=8 || Marshal.SizeOf(typeof(Source))!=20 ||
           Marshal.SizeOf(typeof(Target))!=48 || Marshal.SizeOf(typeof(Path))!=72 || Marshal.SizeOf(typeof(Mode))!=64)
            throw new InvalidOperationException("CCD native ABI mismatch");
        const uint flags=2|0x10|0x40; // active only, virtual mode/refresh aware (Windows 11)
        for(int retry=0;retry<3;retry++) {
            uint paths,modes;int result=GetDisplayConfigBufferSizes(flags,out paths,out modes);
            if(result!=0)throw new Win32Exception(result);
            if(paths<1 || paths>64 || modes>256)throw new InvalidOperationException("CCD array bound");
            var p=new Path[paths];var m=new Mode[modes];
            result=QueryDisplayConfig(flags,ref paths,p,ref modes,m,IntPtr.Zero);
            if(result==122)continue; // read-only sizing race; bounded retry
            if(result!=0)throw new Win32Exception(result);
            Array.Resize(ref p,(int)paths);Array.Resize(ref m,(int)modes);
            var output=new PathResult[paths];
            for(int n=0;n<p.Length;n++) {
                bool virtualMode=(p[n].Flags&8)!=0;
                uint si=virtualMode?p[n].Source.ModeIndex>>16:p[n].Source.ModeIndex;
                uint ti=virtualMode?p[n].Target.ModeIndex>>16:p[n].Target.ModeIndex;
                output[n]=new PathResult {Native=p[n],SourceModeIndex=si,TargetModeIndex=ti,
                    SourceName=Name(1,p[n].Source.Adapter,p[n].Source.Id),
                    SourceAdapterName=Name(4,p[n].Source.Adapter,0),
                    TargetAdapterName=Name(4,p[n].Target.Adapter,0),
                    TargetName=Name(2,p[n].Target.Adapter,p[n].Target.Id)};
            }
            return new Snapshot {QueryFlags=flags,Paths=output,Modes=m};
        }
        throw new InvalidOperationException("CCD topology kept changing; no settings changed");
    }
}
