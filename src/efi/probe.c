/* SPDX-License-Identifier: GPL-2.0-only
 * USB-only capture. No PCI/MMIO writes, Attributes changes, DMA mapping,
 * driver disconnect/connect, firmware execution, reset, or chainload.
 * File writes below go only to the loaded image's USB volume.
 */
#include <Uefi.h>
#include <Protocol/PciIo.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/DevicePath.h>
#include <Protocol/DriverBinding.h>
#include <IndustryStandard/Acpi.h>
#include "sha256.h"

static EFI_GUID pci_guid = EFI_PCI_IO_PROTOCOL_GUID;
static EFI_GUID loaded_guid = EFI_LOADED_IMAGE_PROTOCOL_GUID;
static EFI_GUID fs_guid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
static EFI_GUID path_guid = EFI_DEVICE_PATH_PROTOCOL_GUID;
static EFI_GUID binding_guid = EFI_DRIVER_BINDING_PROTOCOL_GUID;
static EFI_BOOT_SERVICES *bs;
static EFI_FILE_PROTOCOL *root, *log_file;
static UINTN log_bytes, sequence;
static EFI_STATUS fault;
#if defined(RTX_UNLOCK)
static const CHAR8 arm_text[] = "RTX4080-UNLOCK schema=1 one-shot\n";
#elif defined(RTX_READINESS)
static const CHAR8 arm_text[] = "RTX4080-READY schema=1 one-shot\n";
#else
static const CHAR8 arm_text[] = "RTX4080-PROBE schema=2 one-shot\n";
#endif
EFI_STATUS EFIAPI EfiMain(EFI_HANDLE image, EFI_SYSTEM_TABLE *st);
/* Keep an explicit relocation directory and verify its application at entry. */
static EFI_STATUS (EFIAPI *const volatile relocated_entry)(EFI_HANDLE, EFI_SYSTEM_TABLE *) = EfiMain;

static VOID record(const CHAR8 *key, UINT64 value) {
    CHAR8 line[160]; UINTN n = 0;
#ifdef RTX_UNLOCK
    if (fault != EFI_SUCCESS) return;
#else
    if (EFI_ERROR(fault)) return;
#endif
    while (*key && n < 130) line[n++] = *key++;
    if (*key) { fault = EFI_BAD_BUFFER_SIZE; return; }
    line[n++] = '='; line[n++] = '0'; line[n++] = 'x';
    for (INTN i = 15; i >= 0; --i) line[n++] = "0123456789abcdef"[(value >> (4 * i)) & 15];
    line[n++] = '\r'; line[n++] = '\n';
    if (log_bytes > 16 * 1024 * 1024 - n) { fault = EFI_VOLUME_FULL; return; }
    UINTN wrote = n;
    fault = log_file->Write(log_file, &wrote, line);
    if (!EFI_ERROR(fault) && wrote != n) fault = EFI_DEVICE_ERROR;
    log_bytes += wrote;
}

static VOID record_bytes(const CHAR8 *key, const VOID *data, UINTN size) {
    const UINT8 *p = data;
    record(key, size);
    for (UINTN off = 0; off < size && !EFI_ERROR(fault); off += 8) {
        UINT64 value = 0;
        for (UINTN i = 0; i < 8 && off + i < size; ++i) value |= (UINT64)p[off + i] << (i * 8);
        record("data_le", value);
    }
}

static UINTN path_size(EFI_DEVICE_PATH_PROTOCOL *path, BOOLEAN *usb) {
    UINTN off = 0;
    *usb = FALSE;
    for (UINTN nodes = 0; path && nodes < 128; ++nodes) {
        EFI_DEVICE_PATH_PROTOCOL *node = (VOID *)((UINT8 *)path + off);
        UINTN size = node->Length[0] | ((UINTN)node->Length[1] << 8);
        if (size < 4 || size > 4096 - off) return 0;
        if (node->Type == MESSAGING_DEVICE_PATH &&
            (node->SubType == MSG_USB_DP || node->SubType == MSG_USB_CLASS_DP || node->SubType == MSG_USB_WWID_DP)) *usb = TRUE;
        off += size;
        if (node->Type == END_DEVICE_PATH_TYPE && node->SubType == END_ENTIRE_DEVICE_PATH_SUBTYPE)
            return size == 4 ? off : 0;
    }
    return 0;
}

static VOID name_for(CHAR16 name[16], UINTN number, const CHAR16 *extension) {
    name[0] = L'R'; name[1] = L'T'; name[2] = L'X';
    for (INTN i = 7; i >= 3; --i) { name[i] = (CHAR16)(L'0' + number % 10); number /= 10; }
    name[8] = L'.';
    for (UINTN i = 0; i < 4; ++i) name[9 + i] = extension[i];
}

static EFI_STATUS open_new(const CHAR16 *extension, EFI_FILE_PROTOCOL **file) {
    CHAR16 name[16]; EFI_FILE_PROTOCOL *existing = NULL;
    name_for(name, sequence, extension);
    EFI_STATUS s = root->Open(root, &existing, name, EFI_FILE_MODE_READ, 0);
    if (s == EFI_SUCCESS) {
        if (!existing) return EFI_DEVICE_ERROR;
        existing->Close(existing); return EFI_ALREADY_STARTED;
    }
    if (s != EFI_NOT_FOUND) return EFI_ERROR(s) ? s : EFI_DEVICE_ERROR;
    s = root->Open(root, file, name, EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE, 0);
    if (s != EFI_SUCCESS || !*file) return EFI_ERROR(s) ? s : EFI_DEVICE_ERROR;
    return EFI_SUCCESS;
}

static EFI_STATUS dump(const CHAR16 *ext, const VOID *data, UINTN size) {
    EFI_FILE_PROTOCOL *file = NULL;
    EFI_STATUS s = open_new(ext, &file);
    if (EFI_ERROR(s) || !file) return EFI_ERROR(s) ? s : EFI_DEVICE_ERROR;
    UINTN wrote = size;
    s = file->Write(file, &wrote, (VOID *)data);
    if (!EFI_ERROR(s) && wrote != size) s = EFI_DEVICE_ERROR;
    EFI_STATUS flush = file->Flush(file), close = file->Close(file);
    if (EFI_ERROR(s)) return s;
    return EFI_ERROR(flush) ? flush : close;
}

static EFI_STATUS open_log(EFI_HANDLE image) {
    EFI_LOADED_IMAGE_PROTOCOL *loaded = NULL;
    EFI_DEVICE_PATH_PROTOCOL *path = NULL;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *fs = NULL;
    BOOLEAN usb = FALSE;
    EFI_STATUS s = bs->HandleProtocol(image, &loaded_guid, (VOID **)&loaded);
    if (EFI_ERROR(s) || !loaded) return EFI_UNSUPPORTED;
    s = bs->HandleProtocol(loaded->DeviceHandle, &path_guid, (VOID **)&path);
    if (EFI_ERROR(s) || !path_size(path, &usb) || !usb) return EFI_ACCESS_DENIED;
    s = bs->HandleProtocol(loaded->DeviceHandle, &fs_guid, (VOID **)&fs);
    if (EFI_ERROR(s) || !fs) return EFI_UNSUPPORTED;
    s = fs->OpenVolume(fs, &root);
    if (EFI_ERROR(s) || !root) return EFI_ERROR(s) ? s : EFI_DEVICE_ERROR;
    for (sequence = 1; sequence <= 99999; ++sequence) {
        s = open_new(L"LOG", &log_file);
        if (s == EFI_ALREADY_STARTED) continue;
        return s;
    }
    return EFI_VOLUME_FULL;
}

/* A deliberately staged token and an exclusive used marker prevent an
 * unattended USB boot loop from taking another capture. Both are USB files. */
static EFI_STATUS claim_one_shot(VOID) {
    EFI_FILE_PROTOCOL *arm = NULL, *used = NULL;
    EFI_STATUS s = root->Open(root, &arm, L"RTX4080.ARM", EFI_FILE_MODE_READ, 0);
    if (s != EFI_SUCCESS || !arm) return EFI_ACCESS_DENIED;
    CHAR8 contents[sizeof(arm_text)]; UINTN size = sizeof(contents);
    s = arm->Read(arm, &size, contents);
    EFI_STATUS closed = arm->Close(arm);
    if (s != EFI_SUCCESS || EFI_ERROR(closed) || size != sizeof(arm_text)-1) return EFI_ACCESS_DENIED;
    for (UINTN i=0; i<size; ++i) if (contents[i] != arm_text[i]) return EFI_ACCESS_DENIED;
    s = root->Open(root, &used, L"RTX4080.USED", EFI_FILE_MODE_READ, 0);
    if (s == EFI_SUCCESS) { if (used) used->Close(used); return EFI_ALREADY_STARTED; }
    if (s != EFI_NOT_FOUND) return EFI_ACCESS_DENIED;
    s = root->Open(root, &used, L"RTX4080.USED", EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE, 0);
    if (s != EFI_SUCCESS || !used) return EFI_DEVICE_ERROR;
    CHAR8 message[] = "Capture claimed before PCI/MMIO reads; preserve files before another attempt.\r\n";
    size = sizeof(message)-1;
    s = used->Write(used, &size, message);
    EFI_STATUS flushed = used->Flush(used); closed = used->Close(used);
    if (s != EFI_SUCCESS || size != sizeof(message)-1 || EFI_ERROR(flushed) || EFI_ERROR(closed)) return EFI_DEVICE_ERROR;
    return EFI_SUCCESS;
}

static EFI_STATUS graph(EFI_SYSTEM_TABLE *st) {
    EFI_HANDLE *handles = NULL; UINTN count = 0;
    EFI_STATUS s = bs->LocateHandleBuffer(AllHandles, NULL, NULL, &count, &handles);
    if (EFI_ERROR(s)) return s;
    if (!handles || count > 4096) { if (handles) bs->FreePool(handles); return EFI_BAD_BUFFER_SIZE; }
    record("console_out_handle", (UINTN)st->ConsoleOutHandle);
    record("console_in_handle", (UINTN)st->ConsoleInHandle);
    record("con_out_pointer", (UINTN)st->ConOut);
    record("con_in_pointer", (UINTN)st->ConIn);
    record("handle_count", count);
    for (UINTN i = 0; i < count && !EFI_ERROR(fault); ++i) {
        EFI_GUID **protocols = NULL; UINTN total = 0;
        record("handle", (UINTN)handles[i]);
        EFI_DEVICE_PATH_PROTOCOL *path = NULL; BOOLEAN usb = FALSE;
        if (!EFI_ERROR(bs->HandleProtocol(handles[i], &path_guid, (VOID **)&path)) && path) {
            UINTN n = path_size(path, &usb);
            if (!n) { s = EFI_COMPROMISED_DATA; break; }
            record_bytes("device_path", path, n);
        }
        EFI_DRIVER_BINDING_PROTOCOL *binding = NULL;
        if (!EFI_ERROR(bs->HandleProtocol(handles[i], &binding_guid, (VOID **)&binding)) && binding) {
            record("driver_image", (UINTN)binding->ImageHandle);
            record("driver_binding_handle", (UINTN)binding->DriverBindingHandle);
            record("driver_version", binding->Version);
        }
        EFI_LOADED_IMAGE_PROTOCOL *loaded = NULL;
        if (!EFI_ERROR(bs->HandleProtocol(handles[i], &loaded_guid, (VOID **)&loaded)) && loaded) {
            record("image_base", (UINTN)loaded->ImageBase); record("image_size", loaded->ImageSize);
            record("image_device", (UINTN)loaded->DeviceHandle);
            if (loaded->ImageBase && loaded->ImageSize && loaded->ImageSize <= 32 * 1024 * 1024) {
                UINT8 hash[32]; GuSha256(loaded->ImageBase, (UINTN)loaded->ImageSize, hash);
                record_bytes("mapped_image_sha256", hash, sizeof(hash));
            }
        }
        s = bs->ProtocolsPerHandle(handles[i], &protocols, &total);
        if (EFI_ERROR(s)) break;
        if (!protocols || total > 128) { if (protocols) bs->FreePool(protocols); s = EFI_BAD_BUFFER_SIZE; break; }
        for (UINTN j = 0; j < total && !EFI_ERROR(fault); ++j) {
            EFI_OPEN_PROTOCOL_INFORMATION_ENTRY *entries = NULL; UINTN n = 0;
            if (!protocols[j]) { s = EFI_COMPROMISED_DATA; break; }
            record_bytes("protocol_guid", protocols[j], sizeof(EFI_GUID));
            s = bs->OpenProtocolInformation(handles[i], protocols[j], &entries, &n);
            if (EFI_ERROR(s)) { if (entries) bs->FreePool(entries); break; }
            if (n > 256 || (n && !entries)) { if (entries) bs->FreePool(entries); s = EFI_BAD_BUFFER_SIZE; break; }
            for (UINTN k = 0; k < n; ++k) {
                record("agent", (UINTN)entries[k].AgentHandle);
                record("controller", (UINTN)entries[k].ControllerHandle);
                record("attributes", entries[k].Attributes); record("open_count", entries[k].OpenCount);
            }
            if (entries) bs->FreePool(entries);
        }
        bs->FreePool(protocols);
        if (EFI_ERROR(s)) break;
    }
    bs->FreePool(handles);
    return EFI_ERROR(fault) ? fault : s;
}

static EFI_STATUS capture_target(VOID) {
    EFI_HANDLE *handles = NULL, target = NULL;
    EFI_PCI_IO_PROTOCOL *pci = NULL; UINTN count = 0, found = 0;
    EFI_STATUS s = bs->LocateHandleBuffer(ByProtocol, &pci_guid, NULL, &count, &handles);
    if (EFI_ERROR(s)) return s;
    if (!handles || count > 1024) { if (handles) bs->FreePool(handles); return EFI_BAD_BUFFER_SIZE; }
    for (UINTN i = 0; i < count; ++i) {
        EFI_PCI_IO_PROTOCOL *io = NULL; UINT32 id = 0;
        s = bs->HandleProtocol(handles[i], &pci_guid, (VOID **)&io);
        if (EFI_ERROR(s) || !io) { if (!EFI_ERROR(s)) s = EFI_COMPROMISED_DATA; break; }
        s = io->Pci.Read(io, EfiPciIoWidthUint32, 0, 1, &id);
        if (EFI_ERROR(s)) break;
        if (id == 0x270410deU) { ++found; target = handles[i]; pci = io; }
        if ((id & 0xffff) == 0x8086) { record("intel_pci_handle", (UINTN)handles[i]); record("intel_pci_id", id); }
    }
    bs->FreePool(handles);
    if (EFI_ERROR(s)) return s;
    if (found != 1 || !pci) return EFI_NOT_FOUND;
    UINT32 config[64]; UINTN segment, bus, device, function;
    s = pci->Pci.Read(pci, EfiPciIoWidthUint32, 0, 64, config);
    if (EFI_ERROR(s)) return s;
    if (config[0] != 0x270410deU || config[11] != 0x15007377U) return EFI_SECURITY_VIOLATION;
    s = pci->GetLocation(pci, &segment, &bus, &device, &function);
    if (EFI_ERROR(s)) return s;
    record("target_handle", (UINTN)target); record("pci_segment", segment);
    record("pci_bus", bus); record("pci_device", device); record("pci_function", function);
    record("pci_command", config[1] & 0xffff);
    s = dump(L"PCI", config, sizeof(config)); if (EFI_ERROR(s)) return s;
    if (pci->RomImage && pci->RomSize && pci->RomSize <= 1024 * 1024) {
        s = dump(L"ROM", pci->RomImage, (UINTN)pci->RomSize); if (EFI_ERROR(s)) return s;
    }
    record("rom_size", pci->RomSize);
    // No attempt to enable decode, disable BME, or expose a ROM BAR.
    if (!(config[1] & 2) || (config[1] & 4)) { record("mmio_skipped_decode_or_bme", 1); return EFI_SUCCESS; }
    EFI_ACPI_ADDRESS_SPACE_DESCRIPTOR *bar = NULL;
    s = pci->GetBarAttributes(pci, 0, NULL, (VOID **)&bar);
    if (EFI_ERROR(s)) return s;
    BOOLEAN valid = bar && bar->Desc == ACPI_ADDRESS_SPACE_DESCRIPTOR &&
        bar->Len == sizeof(*bar) - 3 && bar->ResType == 0 &&
        bar->AddrLen >= 0x9a014c && bar->AddrTranslationOffset == 0;
    if (bar) { record("bar0_base", bar->AddrRangeMin); record("bar0_bytes", bar->AddrLen); bs->FreePool(bar); }
    if (!valid) return EFI_UNSUPPORTED;
    static const UINT32 offsets[] = {0, 0x118128, 0x118234, 0x110100, 0x1fa824, 0x1fa828,
        0x1183a4, 0x625f04, 0x1fa7c8, 0x1fa82c, 0x1fa830, 0x1fa7cc, 0x9a0148,
        0x1fa7c4, 0x823804, 0x823814, 0x823818, 0x82381c, 0x823820,
        // Booter ucode_id=3 uses SEC2 UCODE3 (0x824148), not GSP UCODE3.
        // Keep the previous GSP UCODE3 observation for comparison only.
        0x824148, 0x8241c8, 0x8241e0};
    for (UINTN i = 0; i < sizeof(offsets) / sizeof(offsets[0]); ++i) {
        UINT32 value = 0;
        s = pci->Mem.Read(pci, EfiPciIoWidthUint32, 0, offsets[i], 1, &value);
        if (EFI_ERROR(s)) return s;
        record("mmio_offset", offsets[i]); record("mmio_value", value);
        if (i == 0 && value != 0x193000a1) return EFI_SECURITY_VIOLATION;
    }
    VOID *prom = NULL;
    s = bs->AllocatePool(EfiLoaderData, 1024 * 1024, &prom);
    if (EFI_ERROR(s) || !prom) return EFI_OUT_OF_RESOURCES;
    s = pci->Mem.Read(pci, EfiPciIoWidthUint32, 0, 0x300000, 1024 * 1024 / 4, prom);
    if (!EFI_ERROR(s)) s = dump(L"PRM", prom, 1024 * 1024);
    bs->FreePool(prom);
    return s;
}

#if defined(RTX_UNLOCK)
#include "unlock.inc"
#elif defined(RTX_READINESS)
#include "readiness.inc"
#else
EFI_STATUS EFIAPI EfiMain(EFI_HANDLE image, EFI_SYSTEM_TABLE *st) {
    if (!image || !st || !st->BootServices) return EFI_INVALID_PARAMETER;
    if (relocated_entry != EfiMain) return EFI_LOAD_ERROR;
    root = NULL; log_file = NULL; log_bytes = 0; fault = EFI_SUCCESS;
    bs = st->BootServices;
    EFI_STATUS s = open_log(image);
    if (EFI_ERROR(s)) { if (root) root->Close(root); return s; }
    record("probe_schema", 2); record("gpu_write_capability", 0);
    record("firmware_revision", st->FirmwareRevision);
    s = claim_one_shot(); record("one_shot_status", s);
    if (!EFI_ERROR(s)) s = graph(st);
    if (!EFI_ERROR(s)) s = capture_target();
    record("capture_status", s); record("capture_complete", !EFI_ERROR(s) && !EFI_ERROR(fault));
    EFI_STATUS flush = log_file->Flush(log_file), close = log_file->Close(log_file);
    root->Close(root);
    if (EFI_ERROR(s)) return s;
    if (EFI_ERROR(fault)) return fault;
    return EFI_ERROR(flush) ? flush : close;
}
#endif
