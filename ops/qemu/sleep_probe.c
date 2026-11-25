#include <windows.h>
#include <stdio.h>
#include <io.h>

static FILE *out;

static unsigned long long ft(FILETIME f) {
    return ((unsigned long long)f.dwHighDateTime << 32) | f.dwLowDateTime;
}

static void measure(const char *name, DWORD ms, int count) {
    LARGE_INTEGER f, q0, q1;
    QueryPerformanceFrequency(&f);
    for (int i = 0; i < count; i++) {
        FILETIME i0, k0, u0, i1, k1, u1;
        GetSystemTimes(&i0, &k0, &u0);
        DWORD t0 = GetTickCount();
        QueryPerformanceCounter(&q0);
        Sleep(ms);
        QueryPerformanceCounter(&q1);
        DWORD t1 = GetTickCount();
        GetSystemTimes(&i1, &k1, &u1);
        unsigned long long idle = ft(i1) - ft(i0), kern = ft(k1) - ft(k0), user = ft(u1) - ft(u0);
        unsigned long long busy = kern - idle + user;
        fprintf(out, "%s[%d] tick=%lu qpc_us=%lld busy_pct=%llu\n", name, i, t1 - t0,
                (q1.QuadPart - q0.QuadPart) * 1000000 / f.QuadPart,
                kern + user ? busy * 100 / (kern + user) : 0);
        fflush(out);
    }
}

int main(void) {
    char path[MAX_PATH];
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    GetModuleFileNameA(NULL, path, MAX_PATH);
    char *slash = strrchr(path, '\\');
    strcpy(slash ? slash + 1 : path, "sleep_probe_result.txt");
    out = fopen(path, "w");
    if (!out)
        return 1;
    fprintf(out, "uptime_ms=%llu\n", GetTickCount64());
    measure("sleep500", 500, 10);
    measure("sleep16", 16, 10);
    timeBeginPeriod(1);
    measure("p1_sleep500", 500, 10);
    measure("p1_sleep16", 16, 10);
    timeEndPeriod(1);
    fprintf(out, "done uptime_ms=%llu\n", GetTickCount64());
    fflush(out);
    FlushFileBuffers((HANDLE)_get_osfhandle(_fileno(out)));
    fclose(out);
    return 0;
}
