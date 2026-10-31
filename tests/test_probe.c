/* SPDX-License-Identifier: GPL-2.0-only
 * Execute the real capture routines against CPU-only UEFI service mocks.
 * Unsupported operations, including all device writes/DMA, are NULL traps.
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#undef NULL /* EDK2 supplies the same macro with its own VOID spelling. */
#include "../src/efi/probe.c"

static EFI_BOOT_SERVICES services;
static EFI_PCI_IO_PROTOCOL io;
static EFI_FILE_PROTOCOL fake_root, fake_file;
static EFI_SIMPLE_FILE_SYSTEM_PROTOCOL fs;
static EFI_LOADED_IMAGE_PROTOCOL loaded;
static UINT8 usb_path[] = {3, 5, 6, 0, 0, 0, 0x7f, 0xff, 4, 0};
static UINT8 internal_path[] = {0x7f, 0xff, 4, 0};
static VOID *chosen_path;
static unsigned creations, closes, mem_reads, pci_reads;
static unsigned handle_count, collision, short_write, deny_open, bad_id, bad_chip, bad_bar, fail_mem;
static UINT32 command;
static unsigned sec2_fuse_reads, fwsec_fuse_reads;
static int allocations;
static unsigned malformed_open, protocol_count, open_count;
static unsigned no_arm, used_marker, wrong_arm, arm_extra, arm_short, flush_fail;

static EFI_STATUS EFIAPI close_file(EFI_FILE_PROTOCOL *self) { (void)self; closes++; return EFI_SUCCESS; }
static EFI_STATUS EFIAPI flush_file(EFI_FILE_PROTOCOL *self) { (void)self; return flush_fail ? EFI_DEVICE_ERROR : EFI_SUCCESS; }
static EFI_STATUS EFIAPI write_file(EFI_FILE_PROTOCOL *self, UINTN *size, VOID *data) {
    (void)self; assert(data || !*size); if (short_write && *size) --*size; return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI read_arm(EFI_FILE_PROTOCOL *self, UINTN *size, VOID *data) {
    (void)self; assert(*size>=sizeof(arm_text)-1); *size=sizeof(arm_text)-1;
    memcpy(data,arm_text,*size); if(wrong_arm)((CHAR8 *)data)[0]='!';
    if(arm_extra)((CHAR8 *)data)[(*size)++]='!';
    if(arm_short)--*size;
    return EFI_SUCCESS;
}
static int name_is(const CHAR16 *a,const CHAR16 *b) {
    while(*a && *a==*b){a++;b++;}return *a==*b;
}
static EFI_STATUS EFIAPI open_file(EFI_FILE_PROTOCOL *self, EFI_FILE_PROTOCOL **out, CHAR16 *name, UINT64 mode, UINT64 attrs) {
    (void)self; (void)name; (void)attrs;
    if (malformed_open) { *out = NULL; return EFI_WARN_UNKNOWN_GLYPH; }
    if (deny_open) return EFI_ACCESS_DENIED;
    if(name_is(name,L"RTX4080.ARM")){if(no_arm)return EFI_NOT_FOUND;*out=&fake_file;return EFI_SUCCESS;}
    if(name_is(name,L"RTX4080.USED") && !(mode&EFI_FILE_MODE_CREATE)){
        if(!used_marker) return EFI_NOT_FOUND;
        *out=&fake_file;return EFI_SUCCESS;
    }
    if(name_is(name,L"RTX4080.USED") && (mode&EFI_FILE_MODE_CREATE))used_marker=1;
    if (!(mode & EFI_FILE_MODE_CREATE)) {
        if (!collision) return EFI_NOT_FOUND;
        *out = &fake_file; return EFI_SUCCESS;
    }
    creations++; *out = &fake_file; return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI open_volume(EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *self, EFI_FILE_PROTOCOL **out) {
    (void)self; *out = &fake_root; return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI free_pool(VOID *p) { assert(p && allocations>0); --allocations; free(p); return EFI_SUCCESS; }
static EFI_STATUS EFIAPI alloc_pool(EFI_MEMORY_TYPE type, UINTN size, VOID **out) {
    assert(type == EfiLoaderData); *out = malloc(size); if (*out) ++allocations; return *out ? EFI_SUCCESS : EFI_OUT_OF_RESOURCES;
}
static EFI_STATUS EFIAPI locate(EFI_LOCATE_SEARCH_TYPE type, EFI_GUID *guid, VOID *key, UINTN *count, EFI_HANDLE **out) {
    (void)type; (void)guid; (void)key;
    *count = handle_count; *out = calloc(handle_count ? handle_count : 1, sizeof(EFI_HANDLE));
    assert(*out); ++allocations; for (UINTN i = 0; i < *count; ++i) (*out)[i] = (EFI_HANDLE)(i + 1);
    return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI handle(EFI_HANDLE h, EFI_GUID *guid, VOID **out) {
    (void)h;
    if (!memcmp(guid, &pci_guid, sizeof(*guid))) *out = &io;
    else if (!memcmp(guid, &loaded_guid, sizeof(*guid))) *out = &loaded;
    else if (!memcmp(guid, &path_guid, sizeof(*guid))) *out = chosen_path;
    else if (!memcmp(guid, &fs_guid, sizeof(*guid))) *out = &fs;
    else return EFI_NOT_FOUND;
    return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI protocols(EFI_HANDLE h, EFI_GUID ***out, UINTN *count) {
    (void)h; *count=protocol_count; *out=calloc(protocol_count ? protocol_count : 1,sizeof(EFI_GUID *));
    assert(*out); ++allocations;
    for(UINTN i=0;i<*count;++i)(*out)[i]=&pci_guid;
    return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI opens(EFI_HANDLE h, EFI_GUID *guid, EFI_OPEN_PROTOCOL_INFORMATION_ENTRY **out, UINTN *count) {
    (void)h; (void)guid; *count=open_count;
    *out=calloc(open_count ? open_count : 1,sizeof(**out)); assert(*out); ++allocations;
    return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI pci_read(EFI_PCI_IO_PROTOCOL *self, EFI_PCI_IO_PROTOCOL_WIDTH width, UINT32 off, UINTN count, VOID *data) {
    (void)self; assert(width == EfiPciIoWidthUint32 && off == 0); pci_reads++;
    memset(data, 0, count * 4); ((UINT32 *)data)[0] = 0x270410de;
    if (count == 64) { ((UINT32 *)data)[1] = command; ((UINT32 *)data)[11] = bad_id ? 0 : 0x15007377; }
    return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI mem_read(EFI_PCI_IO_PROTOCOL *self, EFI_PCI_IO_PROTOCOL_WIDTH width, UINT8 bar, UINT64 off, UINTN count, VOID *data) {
    (void)self; assert(width == EfiPciIoWidthUint32 && bar == 0); mem_reads++;
    if (fail_mem) return EFI_DEVICE_ERROR;
    if(off==0x824148){assert(count==1);sec2_fuse_reads++;}
    if(off==0x8241e0){assert(count==1);fwsec_fuse_reads++;}
    memset(data, 0, count * 4);
    if (!off) *(UINT32 *)data = bad_chip ? 0xffffffff : 0x193000a1;
    return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI location(EFI_PCI_IO_PROTOCOL *self, UINTN *seg, UINTN *bus, UINTN *dev, UINTN *fun) {
    (void)self; *seg = 0; *bus = 2; *dev = *fun = 0; return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI bar_attributes(EFI_PCI_IO_PROTOCOL *self, UINT8 bar, UINT64 *supported, VOID **out) {
    (void)self; (void)supported; assert(bar == 0);
    EFI_ACPI_ADDRESS_SPACE_DESCRIPTOR *d = calloc(1, sizeof(*d)); assert(d); ++allocations;
    d->Desc = ACPI_ADDRESS_SPACE_DESCRIPTOR; d->Len = sizeof(*d) - 3;
    d->AddrLen = bad_bar ? 4096 : 0x1000000; *out = d; return EFI_SUCCESS;
}
static VOID setup(VOID) {
    assert(allocations==0);
    memset(&services, 0, sizeof(services)); memset(&io, 0, sizeof(io));
    services.HandleProtocol = handle; services.LocateHandleBuffer = locate;
    services.ProtocolsPerHandle = protocols; services.OpenProtocolInformation = opens;
    services.FreePool = free_pool; services.AllocatePool = alloc_pool; bs = &services;
    fake_file.Close = close_file; fake_file.Flush = flush_file; fake_file.Write = write_file; fake_file.Read = read_arm;
    fake_root = fake_file; fake_root.Open = open_file; fs.OpenVolume = open_volume;
    loaded.DeviceHandle = (EFI_HANDLE)3; chosen_path = usb_path;
    root = &fake_root; log_file = &fake_file; fault = EFI_SUCCESS; log_bytes = 0; sequence = 1;
    io.Pci.Read = pci_read; io.Mem.Read = mem_read; io.GetLocation = location; io.GetBarAttributes = bar_attributes;
    creations = closes = mem_reads = pci_reads = 0;
    sec2_fuse_reads=fwsec_fuse_reads=0;
    collision = short_write = deny_open = bad_id = bad_chip = bad_bar = fail_mem = 0;
    malformed_open=0;protocol_count=1;open_count=0;
    no_arm=used_marker=wrong_arm=arm_extra=arm_short=flush_fail=0;
    command = 2; handle_count = 1;
}

int main(void) {
    BOOLEAN usb;
    setup(); assert(path_size((VOID *)usb_path, &usb) == sizeof(usb_path) && usb);
    UINT8 invalid[] = {3, 5, 3, 0}; assert(!path_size((VOID *)invalid, &usb));
    setup(); chosen_path = internal_path; assert(open_log((EFI_HANDLE)1) == EFI_ACCESS_DENIED); assert(!creations && !pci_reads);
    setup(); assert(open_log((EFI_HANDLE)1) == EFI_SUCCESS && creations == 1);
    setup(); deny_open = 1; assert(open_log((EFI_HANDLE)1) == EFI_ACCESS_DENIED && !creations);
    setup(); collision = 1; assert(open_new(L"ROM", &log_file) == EFI_ALREADY_STARTED && !creations);
    setup(); short_write = 1; assert(dump(L"ROM", "abcd", 4) == EFI_DEVICE_ERROR && closes == 1);
    setup(); short_write = 1; record("test", 1); assert(fault == EFI_DEVICE_ERROR);
    setup(); assert(capture_target() == EFI_SUCCESS && mem_reads == 23 && creations == 2);
    assert(sec2_fuse_reads==1 && fwsec_fuse_reads==1);
    setup(); command = 6; assert(capture_target() == EFI_SUCCESS && !mem_reads);
    setup(); command = 0; assert(capture_target() == EFI_SUCCESS && !mem_reads);
    setup(); bad_id = 1; assert(capture_target() == EFI_SECURITY_VIOLATION && !mem_reads && !creations);
    setup(); handle_count = 2; assert(capture_target() == EFI_NOT_FOUND && !mem_reads && !creations);
    setup(); bad_chip = 1; assert(capture_target() == EFI_SECURITY_VIOLATION && mem_reads == 1);
    setup(); bad_bar = 1; assert(capture_target() == EFI_UNSUPPORTED && !mem_reads);
    setup(); fail_mem = 1; assert(capture_target() == EFI_DEVICE_ERROR && mem_reads == 1);
    setup(); handle_count = 1025; assert(capture_target() == EFI_BAD_BUFFER_SIZE && !pci_reads);
    setup(); handle_count = 4097; EFI_SYSTEM_TABLE st = {0}; assert(graph(&st) == EFI_BAD_BUFFER_SIZE);
    setup(); assert(EfiMain(NULL, NULL) == EFI_INVALID_PARAMETER);
    setup(); malformed_open=1; assert(dump(L"ROM","x",1)==EFI_DEVICE_ERROR);
    setup(); protocol_count=129; assert(graph(&st)==EFI_BAD_BUFFER_SIZE);
    setup(); open_count=257; assert(graph(&st)==EFI_BAD_BUFFER_SIZE);
    setup(); st.BootServices=&services; assert(EfiMain((EFI_HANDLE)1,&st)==EFI_SUCCESS && mem_reads==23);
    setup(); short_write=1; assert(EfiMain((EFI_HANDLE)1,&st)==EFI_DEVICE_ERROR && pci_reads==0);
    setup(); no_arm=1; assert(EfiMain((EFI_HANDLE)1,&st)==EFI_ACCESS_DENIED && !pci_reads && !mem_reads);
    setup(); wrong_arm=1; assert(EfiMain((EFI_HANDLE)1,&st)==EFI_ACCESS_DENIED && !pci_reads && !mem_reads);
    setup(); used_marker=1; assert(EfiMain((EFI_HANDLE)1,&st)==EFI_ALREADY_STARTED && !pci_reads && !mem_reads);
    setup(); arm_extra=1; assert(EfiMain((EFI_HANDLE)1,&st)==EFI_ACCESS_DENIED && !pci_reads && !mem_reads);
    setup(); arm_short=1; assert(EfiMain((EFI_HANDLE)1,&st)==EFI_ACCESS_DENIED && !pci_reads && !mem_reads);
    setup(); flush_fail=1; assert(EfiMain((EFI_HANDLE)1,&st)==EFI_DEVICE_ERROR && !pci_reads && !mem_reads);
    setup(); assert(EfiMain((EFI_HANDLE)1,&st)==EFI_SUCCESS && used_marker);
    unsigned previous_pci_reads=pci_reads,previous_mem_reads=mem_reads;
    assert(EfiMain((EFI_HANDLE)1,&st)==EFI_ALREADY_STARTED && pci_reads==previous_pci_reads && mem_reads==previous_mem_reads);
    setup(); /* checks final allocation balance, including error paths */
    puts("probe CPU mocks: USB origin, one-shot token, collisions, I/O faults, identity, bounds and no-write paths passed (30 cases)");
    return 0;
}
