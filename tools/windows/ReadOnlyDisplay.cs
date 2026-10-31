// Read-only GDI enumeration; no mode setting, device reset or driver loading.
// https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-enumdisplaydevicesw
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class RtxReadOnlyDisplay {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct DisplayDevice {
        public uint cb;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string name;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string description;
        public uint flags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string id;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string key;
    }
    [DllImport("user32.dll", CharSet = CharSet.Unicode, EntryPoint = "EnumDisplayDevicesW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumDisplayDevices(string parent, uint index, ref DisplayDevice device, uint flags);

    public class Device {
        public string parent, name, description, id;
        public uint flags;
        public bool active, primary;
    }
    private static DisplayDevice Empty() {
        return new DisplayDevice { cb = (uint)Marshal.SizeOf(typeof(DisplayDevice)) };
    }
    private static Device Record(string parent, DisplayDevice d) {
        return new Device { parent=parent, name=d.name, description=d.description,
            id=d.id, flags=d.flags, active=(d.flags & 1)!=0,
            primary=parent==null && (d.flags & 4)!=0 };
    }
    public static Device[] Enumerate() {
        if (Marshal.SizeOf(typeof(DisplayDevice)) != 840) throw new InvalidOperationException("DISPLAY_DEVICEW ABI mismatch");
        var result = new List<Device>();
        for (uint i=0; i<64; i++) {
            DisplayDevice adapter = Empty();
            if (!EnumDisplayDevices(null, i, ref adapter, 0)) return result.ToArray();
            result.Add(Record(null, adapter));
            for (uint j=0; j<64; j++) {
                DisplayDevice monitor = Empty();
                if (!EnumDisplayDevices(adapter.name, j, ref monitor, 0)) break;
                if (j==63) throw new InvalidOperationException("Monitor enumeration limit reached");
                result.Add(Record(adapter.name, monitor));
            }
        }
        throw new InvalidOperationException("Adapter enumeration limit reached");
    }
}
