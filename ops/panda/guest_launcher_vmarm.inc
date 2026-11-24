#include <aclapi.h>
#include <tlhelp32.h>
#include <userenv.h>
#include <wtsapi32.h>

#ifndef ERROR_ELEVATION_REQUIRED
#define ERROR_ELEVATION_REQUIRED 740L
#endif

#define VMARM_SESSION_WAIT_SECONDS 600u
#define VMARM_SHELL_WAIT_SECONDS 120u
#define VMARM_CAPTURE_MILLISECONDS 2000u
#define VMARM_MIN_VISIBLE_WINDOWS 14
#define VMARM_MAX_TOOL_WINDOWS 24
#define VMARM_MAX_JOB_PIDS 256
#define VMARM_MAX_SEEN 2048
#define VMARM_MAX_BASELINE 4096
#define VMARM_DEFAULT_NAME L"setup.exe"
#define VMARM_PATH 1024

static struct {
    int user;
    int elevated;
    DWORD session_id;
    DWORD explorer_pid;
    DWORD helper_pid;
    DWORD create_error;
    HANDLE token;
    HANDLE explorer;
    HANDLE helper_process;
    HANDLE remote_job;
    const char *reason;
    BYTE sid[SECURITY_MAX_SID_SIZE];
    int have_sid;
    wchar_t profile[VMARM_PATH];
    wchar_t downloads[VMARM_PATH];
    wchar_t image[VMARM_PATH];
    char panda_dir[VMARM_PATH];
    char windows_file[VMARM_PATH];
    char job_file[VMARM_PATH];
    char activity_file[VMARM_PATH];
} vmarm = {0, 0, 0xFFFFFFFFu, 0, 0, 0, NULL, NULL, NULL, NULL, "not_attempted",
           {0}, 0, {0}, {0}, {0}, {0}, {0}, {0}, {0}};

static wchar_t vmarm_desktop[] = L"winsta0\\default";

static void vmarm_status_extra(FILE *handle) {
    char image[VMARM_PATH * 3];
    image[0] = '\0';
    if (vmarm.image[0] != L'\0') {
        WideCharToMultiByte(CP_UTF8, 0, vmarm.image, -1, image, sizeof(image),
                            NULL, NULL);
    }
    fprintf(handle,
            "launch=%s\r\nreason=%s\r\nsession_id=%lu\r\nexplorer_pid=%lu\r\n"
            "elevated=%d\r\nactivity_pid=%lu\r\ncreate_error=%lu\r\n"
            "image=%s\r\n",
            vmarm.user ? "user_session" : "session0", vmarm.reason,
            (unsigned long)vmarm.session_id, (unsigned long)vmarm.explorer_pid,
            vmarm.elevated, (unsigned long)vmarm.helper_pid,
            (unsigned long)vmarm.create_error, image);
}

static void vmarm_grant(const wchar_t *path, DWORD mask) {
    PACL old_dacl = NULL;
    PACL new_dacl = NULL;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    EXPLICIT_ACCESSW access;

    if (!vmarm.have_sid) {
        return;
    }
    if (GetNamedSecurityInfoW(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                              NULL, NULL, &old_dacl, NULL,
                              &descriptor) != ERROR_SUCCESS) {
        return;
    }
    ZeroMemory(&access, sizeof(access));
    access.grfAccessPermissions = mask;
    access.grfAccessMode = GRANT_ACCESS;
    access.grfInheritance = NO_INHERITANCE;
    access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    access.Trustee.TrusteeType = TRUSTEE_IS_USER;
    access.Trustee.ptstrName = (LPWSTR)vmarm.sid;
    if (SetEntriesInAclW(1, &access, old_dacl, &new_dacl) == ERROR_SUCCESS) {
        SetNamedSecurityInfoW((LPWSTR)path, SE_FILE_OBJECT,
                              DACL_SECURITY_INFORMATION, NULL, NULL, new_dacl,
                              NULL);
        LocalFree(new_dacl);
    }
    LocalFree(descriptor);
}

static void vmarm_grant_ansi(const char *path, DWORD mask) {
    wchar_t wide[VMARM_PATH];
    if (MultiByteToWideChar(CP_ACP, 0, path, -1, wide, VMARM_PATH) > 0) {
        vmarm_grant(wide, mask);
    }
}

static void vmarm_precreate(const char *path) {
    FILE *handle = fopen(path, "wb");
    if (handle != NULL) {
        fclose(handle);
    }
    vmarm_grant_ansi(path, FILE_GENERIC_READ | FILE_GENERIC_WRITE);
}

static DWORD vmarm_find_explorer(DWORD session_id) {
    PROCESSENTRY32W entry;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    DWORD found = 0;

    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }
    ZeroMemory(&entry, sizeof(entry));
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry)) {
        do {
            DWORD entry_session = 0xFFFFFFFFu;
            if (_wcsicmp(entry.szExeFile, L"explorer.exe") == 0 &&
                ProcessIdToSessionId(entry.th32ProcessID, &entry_session) &&
                entry_session == session_id &&
                (found == 0 || entry.th32ProcessID < found)) {
                found = entry.th32ProcessID;
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return found;
}

static HANDLE vmarm_explorer_handle(void) {
    DWORD pid;
    if (vmarm.explorer != NULL &&
        WaitForSingleObject(vmarm.explorer, 0) == WAIT_TIMEOUT) {
        return vmarm.explorer;
    }
    if (vmarm.explorer != NULL) {
        CloseHandle(vmarm.explorer);
        vmarm.explorer = NULL;
    }
    pid = vmarm_find_explorer(vmarm.session_id);
    if (pid == 0) {
        return NULL;
    }
    vmarm.explorer = OpenProcess(PROCESS_CREATE_PROCESS | SYNCHRONIZE |
                                     PROCESS_QUERY_LIMITED_INFORMATION,
                                 FALSE, pid);
    if (vmarm.explorer != NULL) {
        vmarm.explorer_pid = pid;
    }
    return vmarm.explorer;
}

static BOOL vmarm_spawn(HANDLE token, const wchar_t *image, wchar_t *command,
                        const wchar_t *directory, DWORD flags,
                        PROCESS_INFORMATION *process) {
    STARTUPINFOEXW startup;
    SIZE_T attribute_size = 0;
    LPPROC_THREAD_ATTRIBUTE_LIST attributes = NULL;
    HANDLE parent = vmarm_explorer_handle();
    void *environment = NULL;
    DWORD error = ERROR_SUCCESS;
    BOOL ok;

    ZeroMemory(&startup, sizeof(startup));
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.lpDesktop = vmarm_desktop;
    if (parent != NULL) {
        InitializeProcThreadAttributeList(NULL, 1, 0, &attribute_size);
        attributes = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(attribute_size);
        if (attributes != NULL &&
            InitializeProcThreadAttributeList(attributes, 1, 0,
                                              &attribute_size)) {
            if (UpdateProcThreadAttribute(attributes, 0,
                                          PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                                          &parent, sizeof(parent), NULL,
                                          NULL)) {
                startup.lpAttributeList = attributes;
                flags |= EXTENDED_STARTUPINFO_PRESENT;
            }
        }
    }
    if (CreateEnvironmentBlock(&environment, token, FALSE)) {
        flags |= CREATE_UNICODE_ENVIRONMENT;
    } else {
        environment = NULL;
    }
    ok = CreateProcessAsUserW(token, image, command, NULL, NULL, FALSE, flags,
                              environment, directory, &startup.StartupInfo,
                              process);
    if (!ok) {
        error = GetLastError();
    }
    if (environment != NULL) {
        DestroyEnvironmentBlock(environment);
    }
    if (startup.lpAttributeList != NULL) {
        DeleteProcThreadAttributeList(attributes);
    }
    free(attributes);
    SetLastError(error);
    return ok;
}

static void vmarm_ensure_directory(const wchar_t *path) {
    wchar_t partial[VMARM_PATH];
    size_t i;
    size_t length = wcslen(path);
    if (length >= VMARM_PATH) {
        return;
    }
    for (i = 0; i <= length; i++) {
        partial[i] = path[i];
        if ((path[i] == L'\\' || path[i] == L'\0') && i > 2) {
            partial[i] = L'\0';
            CreateDirectoryW(partial, NULL);
            partial[i] = path[i];
        }
    }
}

static void vmarm_start_helper(void) {
    wchar_t self[VMARM_PATH];
    wchar_t directory[VMARM_PATH];
    wchar_t helper[VMARM_PATH];
    wchar_t command[VMARM_PATH * 4];
    PROCESS_INFORMATION process;

    if (GetModuleFileNameW(NULL, self, VMARM_PATH) == 0) {
        return;
    }
    _snwprintf(directory, VMARM_PATH, L"%ls\\AppData\\Local\\Programs\\InputHelper",
               vmarm.profile);
    directory[VMARM_PATH - 1] = L'\0';
    _snwprintf(helper, VMARM_PATH, L"%ls\\inputhelper.exe", directory);
    helper[VMARM_PATH - 1] = L'\0';
    vmarm_ensure_directory(directory);
    if (CopyFileW(self, helper, FALSE)) {
        vmarm_grant(helper, FILE_GENERIC_READ | FILE_GENERIC_EXECUTE);
    } else {
        wcscpy(helper, self);
    }
    _snwprintf(command, VMARM_PATH * 4, L"\"%ls\" --activity \"%hs\" \"%hs\" \"%hs\"",
               helper, vmarm.windows_file, vmarm.job_file, vmarm.activity_file);
    command[VMARM_PATH * 4 - 1] = L'\0';
    ZeroMemory(&process, sizeof(process));
    if (vmarm_spawn(vmarm.token, helper, command, vmarm.profile, 0, &process)) {
        vmarm.helper_process = process.hProcess;
        vmarm.helper_pid = process.dwProcessId;
        CloseHandle(process.hThread);
    }
}

static void vmarm_prepare(const char *status_path) {
    DWORD waited = 0;
    DWORD profile_size = VMARM_PATH;
    const char *slash = strrchr(status_path, '\\');
    size_t dir_length = slash != NULL ? (size_t)(slash - status_path) : 0;
    BYTE user_buffer[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE];
    DWORD returned = 0;

    if (dir_length == 0 || dir_length >= VMARM_PATH - 32) {
        strcpy(vmarm.panda_dir, "C:\\Panda");
    } else {
        memcpy(vmarm.panda_dir, status_path, dir_length);
        vmarm.panda_dir[dir_length] = '\0';
    }
    _snprintf(vmarm.windows_file, VMARM_PATH, "%s\\windows.txt", vmarm.panda_dir);
    _snprintf(vmarm.job_file, VMARM_PATH, "%s\\job.txt", vmarm.panda_dir);
    _snprintf(vmarm.activity_file, VMARM_PATH, "%s\\activity.txt", vmarm.panda_dir);

    vmarm.reason = "no_user_session";
    while (waited < VMARM_SESSION_WAIT_SECONDS) {
        DWORD session_id = WTSGetActiveConsoleSessionId();
        HANDLE token = NULL;
        if (session_id != 0xFFFFFFFFu && session_id != 0 &&
            WTSQueryUserToken(session_id, &token)) {
            if (vmarm_find_explorer(session_id) != 0) {
                vmarm.session_id = session_id;
                vmarm.token = token;
                break;
            }
            vmarm.reason = "no_explorer";
            CloseHandle(token);
        }
        Sleep(1000);
        waited++;
        if (waited % 30 == 0) {
            write_status(status_path, "awaiting_session", waited, 0);
        }
    }
    if (vmarm.token == NULL) {
        return;
    }
    if (vmarm_explorer_handle() == NULL) {
        vmarm.reason = "explorer_open_failed";
        return;
    }
    if (GetTokenInformation(vmarm.token, TokenUser, user_buffer,
                            sizeof(user_buffer), &returned) &&
        CopySid(sizeof(vmarm.sid), vmarm.sid,
                ((TOKEN_USER *)user_buffer)->User.Sid)) {
        vmarm.have_sid = 1;
    }
    if (!GetUserProfileDirectoryW(vmarm.token, vmarm.profile, &profile_size)) {
        vmarm.reason = "profile_failed";
        return;
    }
    _snwprintf(vmarm.downloads, VMARM_PATH, L"%ls\\Downloads", vmarm.profile);
    vmarm.downloads[VMARM_PATH - 1] = L'\0';
    CreateDirectoryW(vmarm.downloads, NULL);

    vmarm_precreate(vmarm.windows_file);
    vmarm_precreate(vmarm.job_file);
    vmarm_precreate(vmarm.activity_file);
    vmarm.user = 1;
    vmarm.reason = "ok";
    vmarm_start_helper();
}

static void vmarm_read_name(char letter, wchar_t *name, size_t capacity) {
    char path[16];
    char raw[256];
    wchar_t wide[256];
    FILE *handle;
    size_t length;
    size_t i;
    int valid = 1;

    wcscpy(name, VMARM_DEFAULT_NAME);
    _snprintf(path, sizeof(path), "%c:\\NAME.TXT", letter);
    path[sizeof(path) - 1] = '\0';
    handle = fopen(path, "rb");
    if (handle == NULL) {
        return;
    }
    length = fread(raw, 1, sizeof(raw) - 1, handle);
    fclose(handle);
    raw[length] = '\0';
    if ((unsigned char)raw[0] == 0xEF && (unsigned char)raw[1] == 0xBB &&
        (unsigned char)raw[2] == 0xBF) {
        memmove(raw, raw + 3, strlen(raw + 3) + 1);
    }
    raw[strcspn(raw, "\r\n")] = '\0';
    length = strlen(raw);
    while (length > 0 && (raw[length - 1] == ' ' || raw[length - 1] == '\t')) {
        raw[--length] = '\0';
    }
    if (length == 0 ||
        MultiByteToWideChar(CP_UTF8, 0, raw, -1, wide, 256) == 0) {
        return;
    }
    length = wcslen(wide);
    for (i = 0; i < length; i++) {
        if (wide[i] < 0x20 || wcschr(L"\\/:*?\"<>|", wide[i]) != NULL) {
            valid = 0;
        }
    }
    if (!valid || wide[0] == L'.' || length + 5 >= capacity || length > 120) {
        return;
    }
    if (length < 4 || _wcsicmp(wide + length - 4, L".exe") != 0) {
        wcscat(wide, L".exe");
    }
    wcscpy(name, wide);
}

static int vmarm_place(const wchar_t *source, const wchar_t *name) {
    _snwprintf(vmarm.image, VMARM_PATH, L"%ls\\%ls", vmarm.downloads, name);
    vmarm.image[VMARM_PATH - 1] = L'\0';
    if (!CopyFileW(source, vmarm.image, FALSE)) {
        vmarm.image[0] = L'\0';
        return 0;
    }
    vmarm_grant(vmarm.image, FILE_GENERIC_READ | FILE_GENERIC_EXECUTE);
    return 1;
}

static int vmarm_fetch(const char *staged) {
    static const char *const letters = "DEFGHIJK";
    wchar_t source[64];
    wchar_t name[160];
    size_t i;

    if (!vmarm.user) {
        if (GetFileAttributesA(staged) == INVALID_FILE_ATTRIBUTES &&
            !fetch_from_delivery_disk(staged)) {
            return 0;
        }
        MultiByteToWideChar(CP_ACP, 0, staged, -1, vmarm.image, VMARM_PATH);
        return 1;
    }
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX);
    for (i = 0; i < strlen(letters); i++) {
        char root[4];
        _snprintf(root, sizeof(root), "%c:\\", letters[i]);
        root[sizeof(root) - 1] = '\0';
        if (GetDriveTypeA(root) != DRIVE_CDROM) {
            continue;
        }
        _snwprintf(source, 64, L"%hc:\\SAMPLE.EXE", letters[i]);
        source[63] = L'\0';
        if (GetFileAttributesW(source) == INVALID_FILE_ATTRIBUTES) {
            continue;
        }
        vmarm_read_name(letters[i], name, 160);
        if (vmarm_place(source, name)) {
            return 1;
        }
    }
    return 0;
}

static int vmarm_wait_for_sample(const char *staged, const char *status_path) {
    DWORD waited = 0;
    LARGE_INTEGER last_size;
    LARGE_INTEGER size;
    int stable = 0;
    int placed = 0;

    if (GetFileAttributesA(staged) != INVALID_FILE_ATTRIBUTES) {
        if (!vmarm.user) {
            MultiByteToWideChar(CP_ACP, 0, staged, -1, vmarm.image, VMARM_PATH);
            return 1;
        }
        {
            wchar_t source[VMARM_PATH];
            MultiByteToWideChar(CP_ACP, 0, staged, -1, source, VMARM_PATH);
            if (vmarm_place(source, VMARM_DEFAULT_NAME)) {
                return 1;
            }
        }
    }

    last_size.QuadPart = -1;
    while (waited < PACKER_DELIVERY_WAIT_SECONDS) {
        HANDLE probe;
        if (!placed) {
            placed = vmarm_fetch(staged);
        }
        if (placed) {
            probe = CreateFileW(vmarm.image, GENERIC_READ, FILE_SHARE_READ, NULL,
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
        }
        Sleep(1000);
        waited++;
        if (waited % 30 == 0) {
            write_status(status_path, "awaiting_sample", waited, 0);
        }
    }
    return 0;
}

static HANDLE vmarm_linked_token(void) {
    TOKEN_LINKED_TOKEN linked;
    DWORD returned = 0;
    HANDLE primary = NULL;

    ZeroMemory(&linked, sizeof(linked));
    if (!GetTokenInformation(vmarm.token, TokenLinkedToken, &linked,
                             sizeof(linked), &returned) ||
        linked.LinkedToken == NULL) {
        return NULL;
    }
    if (!DuplicateTokenEx(linked.LinkedToken, MAXIMUM_ALLOWED, NULL,
                          SecurityImpersonation, TokenPrimary, &primary)) {
        primary = NULL;
    }
    CloseHandle(linked.LinkedToken);
    return primary;
}

static BOOL vmarm_create_process(const char *staged, char *command_line,
                                 BOOL inherit_handles, STARTUPINFOA *startup,
                                 PROCESS_INFORMATION *process) {
    wchar_t command[VMARM_PATH + 4];
    STARTUPINFOW fallback;
    DWORD error;

    if (!vmarm.user) {
        return CreateProcessA(staged, command_line, NULL, NULL, inherit_handles,
                              CREATE_SUSPENDED, NULL, NULL, startup, process);
    }
    _snwprintf(command, VMARM_PATH + 4, L"\"%ls\"", vmarm.image);
    command[VMARM_PATH + 3] = L'\0';
    if (vmarm_spawn(vmarm.token, vmarm.image, command, vmarm.downloads,
                    CREATE_SUSPENDED, process)) {
        return TRUE;
    }
    error = GetLastError();
    if (error == ERROR_ELEVATION_REQUIRED) {
        HANDLE elevated = vmarm_linked_token();
        if (elevated != NULL) {
            BOOL ok = vmarm_spawn(elevated, vmarm.image, command,
                                  vmarm.downloads, CREATE_SUSPENDED, process);
            error = GetLastError();
            CloseHandle(elevated);
            if (ok) {
                vmarm.elevated = 1;
                return TRUE;
            }
        }
    }
    vmarm.create_error = error;
    vmarm.user = 0;
    vmarm.reason = "create_as_user_failed";
    ZeroMemory(&fallback, sizeof(fallback));
    fallback.cb = sizeof(fallback);
    return CreateProcessW(vmarm.image, command, NULL, NULL, FALSE,
                          CREATE_SUSPENDED, NULL, vmarm.downloads, &fallback,
                          process);
}

static void vmarm_handoff_job(HANDLE job, DWORD root_pid) {
    HANDLE remote = NULL;
    FILE *handle;

    if (!vmarm.user || vmarm.helper_process == NULL) {
        return;
    }
    if (!DuplicateHandle(GetCurrentProcess(), job, vmarm.helper_process,
                         &remote, JOB_OBJECT_QUERY, FALSE, 0)) {
        return;
    }
    vmarm.remote_job = remote;
    handle = fopen(vmarm.job_file, "wb");
    if (handle == NULL) {
        return;
    }
    fprintf(handle, "job=%llx\r\nroot_pid=%lu\r\n",
            (unsigned long long)(uintptr_t)remote, (unsigned long)root_pid);
    fclose(handle);
}

static void vmarm_release_job(void) {
    if (vmarm.remote_job != NULL && vmarm.helper_process != NULL) {
        DuplicateHandle(vmarm.helper_process, vmarm.remote_job, NULL, NULL, 0,
                        FALSE, DUPLICATE_CLOSE_SOURCE);
        vmarm.remote_job = NULL;
    }
}

typedef struct {
    const char *windows_file;
    const char *job_file;
    const char *activity_file;
    HANDLE job;
    DWORD root_pid;
    ULONGLONG attached_at;
    DWORD pids[VMARM_MAX_JOB_PIDS];
    DWORD pid_count;
    uint64_t seen[VMARM_MAX_SEEN];
    DWORD seen_count;
    HWND baseline[VMARM_MAX_BASELINE];
    DWORD baseline_count;
    int baseline_taking;
    int visible_count;
    int total_count;
    int tool_windows;
    int shell_ready;
    volatile LONG moves;
} VMARM_ACTIVITY;

static VMARM_ACTIVITY activity;

static uint64_t vmarm_hash(uint64_t hash, const void *data, size_t length) {
    const unsigned char *bytes = (const unsigned char *)data;
    size_t i;
    for (i = 0; i < length; i++) {
        hash ^= bytes[i];
        hash *= UINT64_C(0x100000001b3);
    }
    return hash;
}

static void vmarm_utf8(const wchar_t *text, char *out, int capacity) {
    wchar_t clean[512];
    size_t i;
    size_t length = wcslen(text);
    if (length >= 512) {
        length = 511;
    }
    for (i = 0; i < length; i++) {
        clean[i] = (text[i] == L'\t' || text[i] == L'\r' || text[i] == L'\n')
                       ? L' ' : text[i];
    }
    clean[length] = L'\0';
    if (WideCharToMultiByte(CP_UTF8, 0, clean, -1, out, capacity, NULL,
                            NULL) == 0) {
        out[0] = '\0';
    }
}

typedef struct {
    wchar_t text[1024];
    size_t length;
} VMARM_CHILD_TEXT;

static BOOL CALLBACK vmarm_child_text(HWND window, LPARAM context) {
    VMARM_CHILD_TEXT *collected = (VMARM_CHILD_TEXT *)context;
    wchar_t class_name[64];
    wchar_t text[512];
    int length;

    if (GetClassNameW(window, class_name, 64) == 0 ||
        (_wcsicmp(class_name, L"Static") != 0 &&
         _wcsicmp(class_name, L"Button") != 0 &&
         _wcsicmp(class_name, L"DirectUIHWND") != 0)) {
        return TRUE;
    }
    length = InternalGetWindowText(window, text, 512);
    if (length <= 0) {
        return TRUE;
    }
    if (collected->length + (size_t)length + 4 >= 1024) {
        return FALSE;
    }
    if (collected->length > 0) {
        wcscpy(collected->text + collected->length, L" | ");
        collected->length += 3;
    }
    wcscpy(collected->text + collected->length, text);
    collected->length += (size_t)length;
    return TRUE;
}

static void vmarm_record(HWND window, DWORD pid, const char *source) {
    wchar_t class_name[256];
    wchar_t title[512];
    VMARM_CHILD_TEXT children;
    char class_utf8[1024];
    char title_utf8[2048];
    char text_utf8[4096];
    uint64_t key = UINT64_C(0xcbf29ce484222325);
    DWORD i;
    FILE *handle;

    if (GetClassNameW(window, class_name, 256) == 0) {
        class_name[0] = L'\0';
    }
    if (InternalGetWindowText(window, title, 512) <= 0) {
        title[0] = L'\0';
    }
    ZeroMemory(&children, sizeof(children));
    EnumChildWindows(window, vmarm_child_text, (LPARAM)&children);
    vmarm_utf8(class_name, class_utf8, sizeof(class_utf8));
    vmarm_utf8(title, title_utf8, sizeof(title_utf8));
    vmarm_utf8(children.text, text_utf8, sizeof(text_utf8));
    key = vmarm_hash(key, &pid, sizeof(pid));
    key = vmarm_hash(key, source, strlen(source));
    key = vmarm_hash(key, class_utf8, strlen(class_utf8));
    key = vmarm_hash(key, title_utf8, strlen(title_utf8));
    key = vmarm_hash(key, text_utf8, strlen(text_utf8));
    for (i = 0; i < activity.seen_count; i++) {
        if (activity.seen[i] == key) {
            return;
        }
    }
    if (activity.seen_count >= VMARM_MAX_SEEN) {
        return;
    }
    activity.seen[activity.seen_count++] = key;
    handle = fopen(activity.windows_file, "ab");
    if (handle == NULL) {
        return;
    }
    fprintf(handle,
            "t_ms=%llu\tsrc=%s\tpid=%lu\tvisible=%d\thwnd=%llx\tclass=%s"
            "\ttitle=%s\ttext=%s\r\n",
            (unsigned long long)(GetTickCount64() - activity.attached_at),
            source, (unsigned long)pid, IsWindowVisible(window) ? 1 : 0,
            (unsigned long long)(uintptr_t)window, class_utf8, title_utf8,
            text_utf8);
    fclose(handle);
}

static BOOL CALLBACK vmarm_capture_window(HWND window, LPARAM context) {
    DWORD pid = 0;
    DWORD i;
    wchar_t class_name[16];

    (void)context;
    if (activity.baseline_taking) {
        if (activity.baseline_count < VMARM_MAX_BASELINE) {
            activity.baseline[activity.baseline_count++] = window;
        }
        return TRUE;
    }
    GetWindowThreadProcessId(window, &pid);
    for (i = 0; i < activity.pid_count; i++) {
        if (activity.pids[i] == pid) {
            vmarm_record(window, pid, "job");
            return TRUE;
        }
    }
    if (pid == GetCurrentProcessId() ||
        GetClassNameW(window, class_name, 16) == 0 ||
        wcscmp(class_name, L"#32770") != 0) {
        return TRUE;
    }
    for (i = 0; i < activity.baseline_count; i++) {
        if (activity.baseline[i] == window) {
            return TRUE;
        }
    }
    vmarm_record(window, pid, "dialog");
    return TRUE;
}

static void vmarm_write_activity(const char *state) {
    FILE *handle = fopen(activity.activity_file, "wb");
    if (handle == NULL) {
        return;
    }
    fprintf(handle,
            "state=%s\r\nshell_ready=%d\r\ntoplevel=%d\r\nvisible_toplevel=%d"
            "\r\ntool_windows=%d\r\nroot_pid=%lu\r\nmoves=%ld\r\n",
            state, activity.shell_ready, activity.total_count,
            activity.visible_count, activity.tool_windows,
            (unsigned long)activity.root_pid, (long)activity.moves);
    fclose(handle);
}

static void vmarm_attach_job(void) {
    FILE *handle = fopen(activity.job_file, "rb");
    unsigned long long value = 0;
    unsigned long root_pid = 0;

    if (handle == NULL) {
        return;
    }
    if (fscanf(handle, "job=%llx root_pid=%lu", &value, &root_pid) == 2 &&
        value != 0) {
        activity.job = (HANDLE)(uintptr_t)value;
        activity.root_pid = (DWORD)root_pid;
        activity.attached_at = GetTickCount64();
        activity.baseline_taking = 1;
        EnumWindows(vmarm_capture_window, 0);
        activity.baseline_taking = 0;
        vmarm_write_activity("attached");
    }
    fclose(handle);
}

static void vmarm_capture(void) {
    struct {
        JOBOBJECT_BASIC_PROCESS_ID_LIST list;
        ULONG_PTR more[VMARM_MAX_JOB_PIDS];
    } ids;
    DWORD i;

    if (activity.job == NULL) {
        vmarm_attach_job();
        if (activity.job == NULL) {
            return;
        }
    }
    ZeroMemory(&ids, sizeof(ids));
    activity.pid_count = 0;
    if (QueryInformationJobObject(activity.job, JobObjectBasicProcessIdList,
                                  &ids, sizeof(ids), NULL) ||
        GetLastError() == ERROR_MORE_DATA) {
        for (i = 0; i < ids.list.NumberOfProcessIdsInList &&
                    i < VMARM_MAX_JOB_PIDS; i++) {
            activity.pids[activity.pid_count++] =
                (DWORD)ids.list.ProcessIdList[i];
        }
    }
    if (activity.pid_count == 0 && activity.root_pid != 0) {
        activity.pids[activity.pid_count++] = activity.root_pid;
    }
    EnumWindows(vmarm_capture_window, 0);
}

static uint32_t vmarm_lcg_state = 0x5EED1234u;

static uint32_t vmarm_lcg(void) {
    vmarm_lcg_state = vmarm_lcg_state * 1664525u + 1013904223u;
    return vmarm_lcg_state >> 8;
}

static void vmarm_move_to(int x, int y, int width, int height) {
    INPUT input;
    ZeroMemory(&input, sizeof(input));
    input.type = INPUT_MOUSE;
    input.mi.dx = (LONG)(((int64_t)x * 65535) / (width > 1 ? width - 1 : 1));
    input.mi.dy = (LONG)(((int64_t)y * 65535) / (height > 1 ? height - 1 : 1));
    input.mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE;
    if (SendInput(1, &input, sizeof(input)) != 1) {
        SetCursorPos(x, y);
    }
    InterlockedIncrement(&activity.moves);
}

static int vmarm_clamp(int value, int low, int high) {
    return value < low ? low : value > high ? high : value;
}

static DWORD WINAPI vmarm_mouse_thread(void *unused) {
    int width = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);
    int x;
    int y;
    int margin;

    (void)unused;
    if (width < 64 || height < 64) {
        width = 1024;
        height = 768;
    }
    margin = width / 20;
    x = width / 2;
    y = height / 2;
    for (;;) {
        int target_x = margin + (int)(vmarm_lcg() % (uint32_t)(width - 2 * margin));
        int target_y = margin + (int)(vmarm_lcg() % (uint32_t)(height - 2 * margin));
        int dx = target_x - x;
        int dy = target_y - y;
        int bend = (int)(vmarm_lcg() % 81u) - 40;
        int control_x = vmarm_clamp((x + target_x) / 2 - dy * bend / 100, 0, width - 1);
        int control_y = vmarm_clamp((y + target_y) / 2 + dx * bend / 100, 0, height - 1);
        int distance = (dx < 0 ? -dx : dx) + (dy < 0 ? -dy : dy);
        int steps = distance / (int)(6 + vmarm_lcg() % 7u) + 8;
        int step;

        for (step = 1; step <= steps; step++) {
            int64_t t = ((int64_t)step * 1024) / steps;
            int64_t u = 1024 - t;
            int px = (int)((u * u * x + 2 * u * t * control_x + t * t * target_x) >> 20);
            int py = (int)((u * u * y + 2 * u * t * control_y + t * t * target_y) >> 20);
            if (step < steps) {
                px += (int)(vmarm_lcg() % 3u) - 1;
                py += (int)(vmarm_lcg() % 3u) - 1;
            }
            vmarm_move_to(vmarm_clamp(px, 0, width - 1),
                          vmarm_clamp(py, 0, height - 1), width, height);
            Sleep(8 + vmarm_lcg() % 17u);
            if (vmarm_lcg() % 97u == 0) {
                Sleep(150 + vmarm_lcg() % 350u);
            }
        }
        x = target_x;
        y = target_y;
        if (vmarm_lcg() % 3u == 0) {
            Sleep(500 + vmarm_lcg() % 2500u);
        }
    }
    return 0;
}

static BOOL CALLBACK vmarm_count_window(HWND window, LPARAM context) {
    (void)context;
    activity.total_count++;
    if (IsWindowVisible(window)) {
        activity.visible_count++;
    }
    return TRUE;
}

static void vmarm_count_windows(void) {
    activity.total_count = 0;
    activity.visible_count = 0;
    EnumWindows(vmarm_count_window, 0);
}

static void vmarm_launch_benign(const wchar_t *image, const wchar_t *argument) {
    wchar_t command[VMARM_PATH * 2];
    STARTUPINFOW startup;
    PROCESS_INFORMATION process;

    if (argument != NULL) {
        wchar_t expanded[VMARM_PATH];
        if (ExpandEnvironmentStringsW(argument, expanded, VMARM_PATH) == 0) {
            return;
        }
        _snwprintf(command, VMARM_PATH * 2, L"\"%ls\" \"%ls\"", image, expanded);
    } else {
        _snwprintf(command, VMARM_PATH * 2, L"\"%ls\"", image);
    }
    command[VMARM_PATH * 2 - 1] = L'\0';
    ZeroMemory(&startup, sizeof(startup));
    ZeroMemory(&process, sizeof(process));
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESHOWWINDOW;
    startup.wShowWindow = SW_SHOWNORMAL;
    if (!CreateProcessW(image, command, NULL, NULL, FALSE, 0, NULL, NULL,
                        &startup, &process)) {
        return;
    }
    WaitForInputIdle(process.hProcess, 30000);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    Sleep(3000);
}

static int vmarm_activity_main(int argc, char **argv) {
    WNDCLASSW window_class;
    HINSTANCE instance = GetModuleHandleW(NULL);
    int screen_width = GetSystemMetrics(SM_CXSCREEN);
    int screen_height = GetSystemMetrics(SM_CYSCREEN);
    DWORD waited = 0;
    HANDLE mouse;
    MSG message;

    if (argc != 5) {
        return 2;
    }
    ZeroMemory(&activity, sizeof(activity));
    activity.windows_file = argv[2];
    activity.job_file = argv[3];
    activity.activity_file = argv[4];
    SetThreadExecutionState(ES_CONTINUOUS | ES_DISPLAY_REQUIRED |
                            ES_SYSTEM_REQUIRED);
    vmarm_write_activity("starting");

    while (waited < VMARM_SHELL_WAIT_SECONDS &&
           FindWindowW(L"Shell_TrayWnd", NULL) == NULL) {
        Sleep(1000);
        waited++;
    }
    activity.shell_ready = FindWindowW(L"Shell_TrayWnd", NULL) != NULL;

    mouse = CreateThread(NULL, 0, vmarm_mouse_thread, NULL, 0, NULL);
    if (mouse != NULL) {
        CloseHandle(mouse);
    }

    vmarm_launch_benign(L"C:\\Windows\\System32\\notepad.exe", NULL);
    vmarm_launch_benign(L"C:\\Windows\\explorer.exe", L"%USERPROFILE%\\Documents");
    vmarm_launch_benign(L"C:\\Windows\\explorer.exe", L"%USERPROFILE%\\Pictures");

    ZeroMemory(&window_class, sizeof(window_class));
    window_class.lpfnWndProc = DefWindowProcW;
    window_class.hInstance = instance;
    window_class.lpszClassName = L"InputHelperTip";
    RegisterClassW(&window_class);
    if (screen_width < 64 || screen_height < 64) {
        screen_width = 1024;
        screen_height = 768;
    }
    vmarm_count_windows();
    while (activity.visible_count < VMARM_MIN_VISIBLE_WINDOWS &&
           activity.tool_windows < VMARM_MAX_TOOL_WINDOWS) {
        CreateWindowExW(WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE, L"InputHelperTip",
                        L"", WS_POPUP | WS_VISIBLE,
                        screen_width - 2 - activity.tool_windows,
                        screen_height - 2, 1, 1, NULL, NULL, instance, NULL);
        activity.tool_windows++;
        vmarm_count_windows();
    }
    vmarm_write_activity("ready");

    SetTimer(NULL, 0, VMARM_CAPTURE_MILLISECONDS, NULL);
    while (GetMessageW(&message, NULL, 0, 0) > 0) {
        if (message.message == WM_TIMER && message.hwnd == NULL) {
            vmarm_capture();
            continue;
        }
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    return 0;
}
