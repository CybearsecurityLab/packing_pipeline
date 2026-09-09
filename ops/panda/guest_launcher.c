/*
 * PANDA recording launcher for the Windows analysis guest.
 *
 * The launcher creates the packed program suspended, starts a deterministic
 * PANDA recording, emits the child PID in a CPUID marker, and only then lets
 * the first packed instruction execute.  It waits for the complete job (root
 * process plus descendants), so process-switching packers remain in scope.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RECCTRL_MAGIC 0x666u
#define RECCTRL_TOGGLE ((uint32_t)-100)
#define RECCTRL_RET_START 1u
#define RECCTRL_RET_STOP 2u

#define PACKER_MARKER_MAGIC 0x5041434bu /* "PACK" */
#define PACKER_MARKER_ROOT_PID 1u
#define PACKER_MARKER_TRACE_START 2u
#define PACKER_MARKER_TRACE_STOP 3u
#define PACKER_MARKER_STATUS_QUERY 4u
#define PACKER_STOP_TIMEOUT_FLAG 0x80000000u
#define PACKER_STOP_IDLE_FLAG 0x40000000u
#define PACKER_STOP_QUERY_FAILURE_FLAG 0x20000000u
#define PACKER_STOP_EXCEPTION_FLAG 0x10000000u
#define PACKER_STATUS_MAGIC UINT64_C(0x5153544154555350)
#define PACKER_IDLE_MILLISECONDS UINT64_C(120000)

typedef struct {
    uint64_t magic;
    uint64_t status_ready;
    uint64_t sample_started;
    uint64_t active_processes;
    uint64_t execution_events;
    uint64_t pending_exceptions;
    uint64_t oldest_exception_age_ms;
} PACKER_STATUS;

static int service_argc;
static char **service_argv;
static SERVICE_STATUS_HANDLE service_status_handle;

static uint32_t cpuid_call(uint32_t eax_in, uintptr_t ebx_in,
                           uintptr_t ecx_in, uintptr_t edx_in) {
    uintptr_t eax = eax_in;
    uintptr_t ebx = ebx_in;
    uintptr_t ecx = ecx_in;
    uintptr_t edx = edx_in;
    /* QEMU TCG does not invoke instruction-execution plugin callbacks for
     * CPUID on this target.  This architectural long NOP embeds "PACK" in
     * its ignored displacement and is the QEMU marker point.  PANDA
     * continues to consume the following CPUID instruction. */
    __asm__ __volatile__(".byte 0x0f, 0x1f, 0x84, 0x00, "
                         "0x4b, 0x43, 0x41, 0x50\n\t"
                         "cpuid"
                         : "+a"(eax), "+b"(ebx), "+c"(ecx), "+d"(edx)
                         :
                         : "memory");
    return (uint32_t)eax;
}

static uint32_t recording_toggle(const char *recording_name) {
    return cpuid_call(RECCTRL_MAGIC, RECCTRL_TOGGLE,
                      (uintptr_t)recording_name, 0);
}

static int query_packer_status(DWORD root_pid, PACKER_STATUS *status) {
    ZeroMemory(status, sizeof(*status));
    cpuid_call(PACKER_MARKER_MAGIC, root_pid, PACKER_MARKER_STATUS_QUERY,
               (uintptr_t)status);
    return status->magic == PACKER_STATUS_MAGIC;
}

static void write_status(const char *path, const char *state, DWORD detail,
                         DWORD child_pid) {
    FILE *handle = fopen(path, "wb");
    if (handle == NULL) {
        return;
    }
    fprintf(handle, "state=%s\r\ndetail=%lu\r\nchild_pid=%lu\r\n",
            state, (unsigned long)detail, (unsigned long)child_pid);
    fclose(handle);
}

/* The 2-minute idle boundary is the paper's rule for real packer samples, which
 * run to a quiescent tail.  The cross-process VALIDATION FIXTURE instead spawns
 * cooperating children and blocks in WaitForSingleObject, and under exact
 * instrumentation a child's CreateProcess+bring-up can exceed 2 guest-minutes.
 * Only the fixture setup provides C:\Panda\idle_ms.txt, so real-sample runs keep
 * the 2-minute boundary while the fixture gets a longer, validation-only window.
 * The value is clamped to [2 min, 30 min] and never exceeds the 30-minute max. */
static uint64_t read_idle_milliseconds(void) {
    uint64_t idle = PACKER_IDLE_MILLISECONDS;
    FILE *override_file = fopen("C:\\Panda\\idle_ms.txt", "r");
    if (override_file != NULL) {
        unsigned long long value = 0;
        if (fscanf(override_file, "%llu", &value) == 1 &&
            value >= PACKER_IDLE_MILLISECONDS && value <= UINT64_C(1800000)) {
            idle = (uint64_t)value;
        }
        fclose(override_file);
    }
    return idle;
}


/* Snapshot-resume support.
 *
 * A savevm snapshot captures a RUNNING guest, so its NTFS volume is dirty and the
 * host cannot mount it read-write to drop in a sample (ntfs-3g refuses; forcing it
 * risks corrupting both the filesystem and the captured VM state). The sample is
 * therefore delivered on a SECOND DISK attached at resume time, and the launcher
 * waits for it here instead of running whatever was staged before the snapshot.
 *
 * Enabled only when argv[1] names a path that does not yet exist, so cold-boot runs
 * -- where the sample is already staged -- are completely unaffected.
 *
 * "Non-empty and stable" is required, not merely "exists": a file that is still
 * being written would otherwise be executed half-delivered.
 */
/* The sample is delivered on the guest's CD-ROM drive, as \SAMPLE.EXE on an ISO.
 *
 * It must be REMOVABLE media, not a second hard disk. A resumed guest only has the
 * devices that existed when its RAM state was captured, so a fixed IDE disk attached
 * at resume time is invisible to Windows -- measured: that device showed Read = 0
 * ops after a full resume while the boot disk showed 7416. A media CHANGE on an
 * already-enumerated CD drive IS honoured across resume (measured: 23 read ops).
 *
 * The drive letter is not fixed, so probe the plausible ones. Copying to the
 * expected path keeps everything downstream (job object, marker scoping, status
 * file) identical to a cold-boot run. The caller re-probes every second, so media
 * arriving after resume is picked up. */
static int fetch_from_delivery_disk(const char *dest) {
    static const char *const letters = "DEFGHIJK";
    char source[64];
    size_t i;

    /* Probing a drive letter blindly is a trap: GetFileAttributesA on a letter with
     * no device, or a removable drive with no medium, BLOCKS while the device times
     * out -- and Windows may pop a "no disk" dialog that never gets dismissed on a
     * headless guest. Eight blind probes per second then wedges the poll loop
     * entirely (observed: status.txt froze at the first 30 s tick, detail=30, in a
     * run that lasted 500 s). SetErrorMode suppresses the dialogs, and GetDriveTypeA
     * is a cheap non-blocking check that skips everything that is not a CD. */
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX);

    for (i = 0; i < strlen(letters); i++) {
        char root[4];
        _snprintf(root, sizeof(root), "%c:\\", letters[i]);
        root[sizeof(root) - 1] = '\0';
        if (GetDriveTypeA(root) != DRIVE_CDROM) {
            continue;
        }
        _snprintf(source, sizeof(source), "%c:\\SAMPLE.EXE", letters[i]);
        source[sizeof(source) - 1] = '\0';
        if (GetFileAttributesA(source) == INVALID_FILE_ATTRIBUTES) {
            continue;
        }
        if (CopyFileA(source, dest, FALSE)) {
            return 1;
        }
    }
    return 0;
}

static int wait_for_sample(const char *path, DWORD timeout_seconds,
                           const char *status_path) {
    DWORD waited = 0;
    LARGE_INTEGER last_size;
    LARGE_INTEGER size;
    int stable = 0;

    last_size.QuadPart = -1;
    while (waited < timeout_seconds) {
        HANDLE probe;

        /* Pull it across from the delivery volume as soon as that volume appears. */
        if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES) {
            fetch_from_delivery_disk(path);
        }

        probe = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                                   OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (probe != INVALID_HANDLE_VALUE) {
            if (GetFileSizeEx(probe, &size) && size.QuadPart > 0) {
                if (size.QuadPart == last_size.QuadPart) {
                    if (++stable >= 2) {
                        CloseHandle(probe);
                        return 1;
                    }
                } else {
                    stable = 0;
                    last_size = size;
                }
            }
            CloseHandle(probe);
        }
        Sleep(1000);
        waited++;
        if (waited % 30 == 0) {
            write_status(status_path, "awaiting_sample", waited, 0);
        }
    }
    return 0;
}

static int run_sample(int argc, char **argv) {
    STARTUPINFOA startup;
    PROCESS_INFORMATION process;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;
    HANDLE job = NULL;
    HANDLE stdio_sink = INVALID_HANDLE_VALUE;
    SECURITY_ATTRIBUTES sink_security;
    BOOL inherit_handles = FALSE;
    char *command_line = NULL;
    DWORD timeout_seconds;
    uint64_t idle_milliseconds;
    DWORD wait_result;
    DWORD child_exit_code = STILL_ACTIVE;
    DWORD stop_detail = 0;
    uint32_t record_result;
    int live_mode;
    int result = 1;

    if (argc != 5) {
        fprintf(stderr,
                "usage: %s <sample.exe> <timeout-seconds> "
                "<host-recording-name> <status-file>\n",
                argv[0]);
        return 2;
    }

    timeout_seconds = strtoul(argv[2], NULL, 10);
    live_mode = strcmp(argv[3], "-") == 0;
    if (timeout_seconds == 0 || timeout_seconds > 3600) {
        write_status(argv[4], "invalid_timeout", timeout_seconds, 0);
        return 2;
    }
    idle_milliseconds = read_idle_milliseconds();

    /* Snapshot-resume: if the sample is not present yet it is arriving on the
     * secondary disk, so wait for it. Absent in cold-boot runs (file already
     * staged), which therefore behave exactly as before. */
    if (GetFileAttributesA(argv[1]) == INVALID_FILE_ATTRIBUTES) {
        if (!wait_for_sample(argv[1], timeout_seconds, argv[4])) {
            write_status(argv[4], "sample_never_arrived", timeout_seconds, 0);
            return 2;
        }
    }

    write_status(argv[4], "starting", timeout_seconds, 0);

    ZeroMemory(&sink_security, sizeof(sink_security));
    sink_security.nLength = sizeof(sink_security);
    sink_security.bInheritHandle = TRUE;

    ZeroMemory(&startup, sizeof(startup));
    ZeroMemory(&process, sizeof(process));
    ZeroMemory(&limits, sizeof(limits));
    startup.cb = sizeof(startup);

    /* Give the sample real standard handles.  Previously STARTUPINFO was zeroed
     * with no STARTF_USESTDHANDLES and CreateProcess was called with
     * bInheritHandles=FALSE, so the sample ran with NO stdin/stdout/stderr at all.
     * A process launched from a desktop or a shell always has them; a guest that
     * does not is the outlier, and a packer stub that writes progress output can
     * stall there through no fault of its own.  alushpacker maps its payload --
     * header copy, section copy and destination stores are all recorded -- and
     * then its last observed user code is a CRT print call from which it never
     * returns, with the trace ending inside ntdll.
     *
     * The handles go to a file rather than NUL so the output is recoverable as
     * evidence.  Failure is non-fatal: the sample simply runs as it did before. */
    stdio_sink = CreateFileA("C:\\Panda\\sample_stdout.txt",
                             FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                             &sink_security, OPEN_ALWAYS,
                             FILE_ATTRIBUTE_NORMAL, NULL);
    if (stdio_sink != INVALID_HANDLE_VALUE) {
        startup.dwFlags |= STARTF_USESTDHANDLES;
        startup.hStdInput = INVALID_HANDLE_VALUE;
        startup.hStdOutput = stdio_sink;
        startup.hStdError = stdio_sink;
        inherit_handles = TRUE;
    }

    command_line = _strdup(argv[1]);
    if (command_line == NULL) {
        write_status(argv[4], "allocation_failed", ERROR_NOT_ENOUGH_MEMORY, 0);
        return 1;
    }

    job = CreateJobObjectA(NULL, NULL);
    if (job == NULL) {
        write_status(argv[4], "job_create_failed", GetLastError(), 0);
        goto cleanup;
    }
    limits.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                                 &limits, sizeof(limits))) {
        write_status(argv[4], "job_config_failed", GetLastError(), 0);
        goto cleanup;
    }

    if (!CreateProcessA(argv[1], command_line, NULL, NULL, inherit_handles,
                        CREATE_SUSPENDED, NULL, NULL, &startup, &process)) {
        write_status(argv[4], "create_process_failed", GetLastError(), 0);
        goto cleanup;
    }
    if (!AssignProcessToJobObject(job, process.hProcess)) {
        write_status(argv[4], "job_assign_failed", GetLastError(),
                     process.dwProcessId);
        TerminateProcess(process.hProcess, 1);
        goto process_cleanup;
    }

    if (!live_mode) {
        record_result = recording_toggle(argv[3]);
        if (record_result != RECCTRL_RET_START) {
            write_status(argv[4], "record_start_failed", record_result,
                         process.dwProcessId);
            TerminateProcess(process.hProcess, 1);
            goto process_cleanup;
        }
    }

    /* Replay learns the child's ASID from its TEB before the PE entry point. */
    cpuid_call(PACKER_MARKER_MAGIC, process.dwProcessId,
               PACKER_MARKER_ROOT_PID, process.dwThreadId);
    cpuid_call(PACKER_MARKER_MAGIC, process.dwProcessId,
               PACKER_MARKER_TRACE_START, process.dwThreadId);

    if (ResumeThread(process.hThread) == (DWORD)-1) {
        DWORD error = GetLastError();
        if (!live_mode) {
            recording_toggle(argv[3]);
        }
        write_status(argv[4], "resume_failed", error, process.dwProcessId);
        TerminateProcess(process.hProcess, 1);
        goto process_cleanup;
    }

    if (live_mode) {
        ULONGLONG started = GetTickCount64();
        ULONGLONG last_execution = started;
        uint64_t last_execution_events = 0;
        int sample_started = 0;
        int root_exited = 0;
        ULONGLONG root_exit_at = 0;

        for (;;) {
            PACKER_STATUS packer_status;
            ULONGLONG now;
            /* Wait on the SAMPLE PROCESS handle, not the job object.  A job is
             * never signaled by becoming empty, and the plugin's active-process
             * count cannot be trusted to reach 0 here: this launcher holds the
             * sample's handle, so its EPROCESS lingers on PsActiveProcessHead
             * after exit (referenced) and keeps getting counted.  The process
             * handle signals exactly when the sample exits — the reliable clean
             * completion boundary.  For the cross-process fixture the root exits
             * only after WaitForSingleObject on its children returns, so this is
             * the all-work-done boundary in both modes. */
            /* Once the root has exited its handle is closed, so stop waiting on
             * it; from then on completion is driven by execution idleness below. */
            DWORD current_wait = WAIT_TIMEOUT;
            if (root_exited) {
                Sleep(1000u);
            } else {
                current_wait = WaitForSingleObject(process.hProcess, 1000u);
            }

            if (current_wait == WAIT_OBJECT_0) {
                /* The ROOT exited.  That is NOT necessarily all-work-done: a
                 * process-hollowing packer resumes its payload in a child and
                 * returns immediately, so the root is gone while the payload has
                 * not run a single instruction yet.  hxor_packer does exactly
                 * this -- LoadEXE calls ResumeThread and returns, and main
                 * returns 0 without waiting.  Breaking here emitted the stop
                 * marker, which sets active=false in the plugin and stops
                 * tracing, and then closing the job terminated the surviving
                 * child under KILL_ON_JOB_CLOSE.  We were killing the payload
                 * before it executed and recording "no unpacking observed".
                 *
                 * So root exit only ARMS the completion: keep watching until the
                 * plugin reports no monitored execution for the idle window, or
                 * the timeout fires.  When the root really was the last worker
                 * -- the ordinary case, and the cross-process fixture, which
                 * waits on its children before exiting -- execution is already
                 * quiet and this adds one idle window, not a stall. */
                if (!root_exited) {
                    root_exited = 1;
                    root_exit_at = GetTickCount64();
                    /* Release the root handle so its EPROCESS stops lingering on
                     * PsActiveProcessHead and the plugin's active-process count
                     * becomes meaningful for the descendants. */
                    CloseHandle(process.hProcess);
                    process.hProcess = NULL;
                }
            } else if (current_wait != WAIT_TIMEOUT) {
                wait_result = current_wait;
                break;
            }
            if (!query_packer_status(process.dwProcessId, &packer_status)) {
                wait_result = WAIT_FAILED;
                stop_detail = PACKER_STOP_QUERY_FAILURE_FLAG;
                break;
            }
            now = GetTickCount64();
            if (now - started >= (ULONGLONG)timeout_seconds * 1000u) {
                wait_result = WAIT_TIMEOUT;
                stop_detail = PACKER_STOP_TIMEOUT_FLAG | WAIT_TIMEOUT;
                break;
            }
            if (!packer_status.status_ready) {
                continue;
            }
            if (packer_status.sample_started && !sample_started) {
                sample_started = 1;
                last_execution_events = packer_status.execution_events;
                last_execution = now;
            }
            if (packer_status.execution_events != last_execution_events) {
                last_execution_events = packer_status.execution_events;
                last_execution = now;
            }
            /* Clean completion is detected by the process-handle wait above; the
             * plugin's active_processes count is unreliable for it (held-handle
             * EPROCESS lingering), so it is used only for exception scoping. */
            if (packer_status.pending_exceptions > 0 &&
                packer_status.oldest_exception_age_ms >=
                    PACKER_IDLE_MILLISECONDS) {
                wait_result = WAIT_TIMEOUT;
                stop_detail = PACKER_STOP_EXCEPTION_FLAG | WAIT_TIMEOUT;
                break;
            }
            if (sample_started &&
                now - last_execution >= idle_milliseconds) {
                wait_result = WAIT_TIMEOUT;
                stop_detail = PACKER_STOP_IDLE_FLAG | WAIT_TIMEOUT;
                break;
            }
            /* Root gone AND nothing executing: now it is genuinely finished.
             * Reported as a clean exit, matching the previous meaning of the
             * root-handle signal. */
            if (root_exited &&
                now - last_execution >= idle_milliseconds) {
                wait_result = WAIT_OBJECT_0;
                break;
            }
            /* Root gone and the payload never started within a full idle window:
             * nothing is coming.  Do not hold the guest for the whole timeout. */
            if (root_exited && !sample_started &&
                now - root_exit_at >= idle_milliseconds) {
                wait_result = WAIT_OBJECT_0;
                break;
            }
        }
    } else {
        wait_result = WaitForSingleObject(job, timeout_seconds * 1000u);
        if (wait_result == WAIT_TIMEOUT) {
            stop_detail = PACKER_STOP_TIMEOUT_FLAG | WAIT_TIMEOUT;
        }
    }
    if (wait_result == WAIT_TIMEOUT) {
        TerminateJobObject(job, WAIT_TIMEOUT);
    }

    /* Persist termination before recctrl's nrec=1 setting quits PANDA. */
    if (wait_result == WAIT_TIMEOUT &&
        (stop_detail & PACKER_STOP_EXCEPTION_FLAG)) {
        write_status(argv[4], "unrecovered_exception", 120,
                     process.dwProcessId);
        result = 0;
    } else if (wait_result == WAIT_TIMEOUT &&
        (stop_detail & PACKER_STOP_IDLE_FLAG)) {
        write_status(argv[4], "idle", 120,
                     process.dwProcessId);
        result = 0;
    } else if (wait_result == WAIT_TIMEOUT) {
        write_status(argv[4], "timeout", timeout_seconds,
                     process.dwProcessId);
        result = 3;
    } else if (wait_result == WAIT_OBJECT_0) {
        if (process.hProcess != NULL) {
            GetExitCodeProcess(process.hProcess, &child_exit_code);
        }
        write_status(argv[4], "complete", child_exit_code, process.dwProcessId);
        result = 0;
    } else {
        write_status(argv[4], "wait_failed", GetLastError(),
                     process.dwProcessId);
    }
    cpuid_call(PACKER_MARKER_MAGIC, process.dwProcessId,
               PACKER_MARKER_TRACE_STOP,
               wait_result == WAIT_TIMEOUT || stop_detail
                   ? stop_detail : child_exit_code);
    if (live_mode) {
        /* Let Windows close NTFS cleanly.  The host tracer exits when QEMU
         * observes the guest power-off instead of aborting the VM at CPUID. */
        if (system("C:\\Windows\\System32\\shutdown.exe /s /t 0 /f") == -1) {
            write_status(argv[4], "shutdown_failed", GetLastError(),
                         process.dwProcessId);
            result = 1;
        }
    } else {
        record_result = recording_toggle(argv[3]);
        if (record_result != RECCTRL_RET_STOP) {
            write_status(argv[4], "record_stop_failed", record_result,
                         process.dwProcessId);
            result = 1;
        }
    }

process_cleanup:
    CloseHandle(process.hThread);
    if (process.hProcess != NULL) {
        CloseHandle(process.hProcess);
    }
cleanup:
    if (job != NULL) {
        CloseHandle(job);
    }
    if (stdio_sink != INVALID_HANDLE_VALUE) {
        CloseHandle(stdio_sink);
    }
    free(command_line);
    return result;
}

static void WINAPI service_control(DWORD control) {
    (void)control;
}

static void WINAPI service_main(DWORD argc, char **argv) {
    SERVICE_STATUS status;
    int result;

    (void)argc;
    (void)argv;
    ZeroMemory(&status, sizeof(status));
    service_status_handle =
        RegisterServiceCtrlHandlerA("PandaPilot", service_control);
    if (service_status_handle == NULL) {
        return;
    }
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = SERVICE_RUNNING;
    status.dwControlsAccepted = 0;
    status.dwWin32ExitCode = NO_ERROR;
    SetServiceStatus(service_status_handle, &status);

    result = run_sample(service_argc, service_argv);
    status.dwCurrentState = SERVICE_STOPPED;
    status.dwWin32ExitCode = result == 0 ? NO_ERROR : ERROR_SERVICE_SPECIFIC_ERROR;
    status.dwServiceSpecificExitCode = (DWORD)result;
    SetServiceStatus(service_status_handle, &status);
}

int main(int argc, char **argv) {
    SERVICE_TABLE_ENTRYA service_table[] = {
        {"PandaPilot", service_main},
        {NULL, NULL},
    };

    if (argc > 1 && strcmp(argv[1], "--service") == 0) {
        /* Keep the configured command-line arguments for ServiceMain. */
        service_argc = argc - 1;
        service_argv = argv + 1;
        if (!StartServiceCtrlDispatcherA(service_table)) {
            write_status(argc > 5 ? argv[5] : "C:\\Panda\\status.txt",
                         "service_dispatch_failed", GetLastError(), 0);
            return 1;
        }
        return 0;
    }
    return run_sample(argc, argv);
}
