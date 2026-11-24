#include <windows.h>
#include <intrin.h>
#include <stdio.h>
#include <string.h>

static FILE *out;

static void line(const char *key, const char *fmt, ...) {
    va_list ap;
    fprintf(out, "%s=", key);
    va_start(ap, fmt);
    vfprintf(out, fmt, ap);
    va_end(ap);
    fputc('\n', out);
    fflush(out);
}

static void cpuid_checks(void) {
    int r[4];
    char vendor[13] = {0};
    char hv[13] = {0};
    char brand[49] = {0};
    __cpuid(r, 0);
    memcpy(vendor, &r[1], 4);
    memcpy(vendor + 4, &r[3], 4);
    memcpy(vendor + 8, &r[2], 4);
    line("cpu_vendor", "%s", vendor);
    __cpuid(r, 1);
    line("cpu_hypervisor_bit", "%d", (r[2] >> 31) & 1);
    line("cpu_leaf1_ecx", "0x%08x", (unsigned)r[2]);
    __cpuid(r, 0x40000000);
    memcpy(hv, &r[1], 4);
    memcpy(hv + 4, &r[2], 4);
    memcpy(hv + 8, &r[3], 4);
    line("cpu_hv_leaf_max", "0x%08x", (unsigned)r[0]);
    line("cpu_hv_vendor", "%s", hv);
    for (int i = 0; i < 3; i++) {
        __cpuid(r, 0x80000002 + i);
        memcpy(brand + 16 * i, r, 16);
    }
    line("cpu_brand", "%s", brand);
}

static void timing_checks(void) {
    int r[4];
    unsigned long long a = __rdtsc();
    unsigned long long b = __rdtsc();
    line("rdtsc_back_to_back", "%llu", b - a);
    a = __rdtsc();
    __cpuid(r, 0);
    b = __rdtsc();
    line("rdtsc_around_cpuid", "%llu", b - a);
    DWORD t0 = GetTickCount();
    LARGE_INTEGER q0, q1, f;
    QueryPerformanceCounter(&q0);
    Sleep(500);
    QueryPerformanceCounter(&q1);
    QueryPerformanceFrequency(&f);
    line("sleep500_tick_ms", "%lu", GetTickCount() - t0);
    line("sleep500_qpc_ms", "%lld", (q1.QuadPart - q0.QuadPart) * 1000 / f.QuadPart);
    line("uptime_ms", "%llu", GetTickCount64());
}

static void smbios_checks(void) {
    DWORD size = GetSystemFirmwareTable('RSMB', 0, NULL, 0);
    line("smbios_size", "%lu", size);
    if (!size) {
        return;
    }
    BYTE *buf = HeapAlloc(GetProcessHeap(), 0, size);
    if (!buf || GetSystemFirmwareTable('RSMB', 0, buf, size) != size) {
        return;
    }
    char text[512] = {0};
    size_t n = 0;
    for (DWORD i = 8; i < size && n < sizeof(text) - 2; i++) {
        BYTE c = buf[i];
        if (c >= 0x20 && c < 0x7f) {
            text[n++] = (char)c;
        } else if (n && text[n - 1] != '|') {
            text[n++] = '|';
        }
    }
    line("smbios_strings", "%s", text);
    HeapFree(GetProcessHeap(), 0, buf);
    DWORD acpi = EnumSystemFirmwareTables('ACPI', NULL, 0);
    line("acpi_tables_bytes", "%lu", acpi);
    if (acpi) {
        char ids[256] = {0};
        EnumSystemFirmwareTables('ACPI', ids, acpi < sizeof(ids) ? acpi : sizeof(ids));
        DWORD fsz = GetSystemFirmwareTable('ACPI', *(DWORD *)ids, NULL, 0);
        if (fsz > 16) {
            BYTE *t = HeapAlloc(GetProcessHeap(), 0, fsz);
            if (t && GetSystemFirmwareTable('ACPI', *(DWORD *)ids, t, fsz) == fsz) {
                line("acpi_first_oem", "%.6s|%.8s", (char *)t + 10, (char *)t + 16);
            }
        }
    }
}

static void reg_value(const char *label, HKEY root, const char *path, const char *value) {
    char data[512] = {0};
    DWORD len = sizeof(data) - 1;
    LONG rc = RegGetValueA(root, path, value, RRF_RT_REG_SZ | RRF_RT_REG_MULTI_SZ, NULL, data, &len);
    for (DWORD i = 0; rc == ERROR_SUCCESS && i + 1 < len; i++) {
        if (!data[i]) {
            data[i] = '|';
        }
    }
    line(label, "%s", rc == ERROR_SUCCESS ? data : "<absent>");
}

static void registry_checks(void) {
    reg_value("reg_bios_version", HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System", "SystemBiosVersion");
    reg_value("reg_bios_vendor", HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\BIOS", "BIOSVendor");
    reg_value("reg_system_manufacturer", HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\BIOS", "SystemManufacturer");
    reg_value("reg_system_product", HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\BIOS", "SystemProductName");
    reg_value("reg_cpu_name", HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", "ProcessorNameString");
    reg_value("reg_scsi_disk", HKEY_LOCAL_MACHINE, "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier");
    reg_value("reg_scsi_cd", HKEY_LOCAL_MACHINE, "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 1\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier");
    HKEY k;
    line("reg_vmware_tools", "%s", RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\VMware, Inc.\\VMware Tools", 0, KEY_READ, &k) == ERROR_SUCCESS ? "present" : "absent");
    line("reg_vbox_guest", "%s", RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Oracle\\VirtualBox Guest Additions", 0, KEY_READ, &k) == ERROR_SUCCESS ? "present" : "absent");
}

static int window_count;

static BOOL CALLBACK count_window(HWND hwnd, LPARAM lp) {
    (void)lp;
    if (IsWindowVisible(hwnd)) {
        window_count++;
    }
    return TRUE;
}

static void environment_checks(void) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    line("cpu_count", "%lu", si.dwNumberOfProcessors);
    MEMORYSTATUSEX ms;
    ZeroMemory(&ms, sizeof(ms));
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    line("ram_mb", "%llu", ms.ullTotalPhys / (1024 * 1024));
    ULARGE_INTEGER total;
    if (GetDiskFreeSpaceExA("C:\\", NULL, &total, NULL)) {
        line("disk_gb", "%llu", total.QuadPart / (1024ULL * 1024 * 1024));
    }
    char name[256] = {0};
    DWORD n = sizeof(name);
    GetUserNameA(name, &n);
    line("user", "%s", name);
    n = sizeof(name);
    GetComputerNameA(name, &n);
    line("computer", "%s", name);
    DWORD session = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &session);
    line("session", "%lu", session);
    GetModuleFileNameA(NULL, name, sizeof(name));
    line("image_path", "%s", name);
    POINT p1, p2;
    GetCursorPos(&p1);
    Sleep(2000);
    GetCursorPos(&p2);
    line("cursor_moved", "%d", p1.x != p2.x || p1.y != p2.y);
    line("foreground_window", "%s", GetForegroundWindow() ? "yes" : "no");
    EnumWindows(count_window, 0);
    line("visible_toplevel_windows", "%d", window_count);
    line("screen", "%dx%d", GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN));
}

static LONG CALLBACK io_handler(PEXCEPTION_POINTERS info) {
#ifdef _WIN64
    info->ContextRecord->Rip += 1;
#else
    info->ContextRecord->Eip += 1;
#endif
    line("vmware_port_exception", "0x%08lx", info->ExceptionRecord->ExceptionCode);
    return EXCEPTION_CONTINUE_EXECUTION;
}

static void backdoor_check(void) {
    PVOID h = AddVectoredExceptionHandler(1, io_handler);
#ifdef _WIN64
    __asm__ volatile("mov $0x564D5868, %%eax\n\tmov $10, %%ecx\n\tmov $0x5658, %%dx\n\tin %%dx, %%eax" ::: "eax", "ecx", "edx", "memory");
#else
    __asm__ volatile("mov $0x564D5868, %%eax\n\tmov $10, %%ecx\n\tmov $0x5658, %%dx\n\tin %%dx, %%eax" ::: "eax", "ecx", "edx", "memory");
#endif
    RemoveVectoredExceptionHandler(h);
}

int main(void) {
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, sizeof(path));
    char *slash = strrchr(path, '\\');
    if (slash) {
        strcpy(slash + 1, "vm_probe_result.txt");
    }
    out = fopen(path, "w");
    if (!out) {
        return 2;
    }
    cpuid_checks();
    timing_checks();
    smbios_checks();
    registry_checks();
    environment_checks();
    backdoor_check();
    line("done", "1");
    fclose(out);
    return 0;
}
