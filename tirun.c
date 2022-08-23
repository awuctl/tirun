#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <Windows.h>
#include <winsvc.h>

/* clang headers don't have that for some reason */
#ifndef SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME
#define SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME TEXT("SeDelegateSessionUserImpersonatePrivilege")
#endif

/* Any other way is painful */
/* This is why Windows sucks */
#ifdef UNICODE
#define write(a) _putws(TEXT(a)) 
#define _tmain wmain
#define strncmp wcsncmp
#define strcat wcscat
#define strlen wcslen
#else
#define write(s) puts(TEXT(s))
#define _tmain main
#endif

const TCHAR *ALL_TOKEN_PRIVILEGES[35] = {
	SE_ASSIGNPRIMARYTOKEN_NAME,
	SE_AUDIT_NAME,
	SE_BACKUP_NAME,
	SE_CHANGE_NOTIFY_NAME,
	SE_CREATE_GLOBAL_NAME,
	SE_CREATE_PAGEFILE_NAME,
	SE_CREATE_PERMANENT_NAME,
	SE_CREATE_SYMBOLIC_LINK_NAME,
	SE_CREATE_TOKEN_NAME,
	SE_DEBUG_NAME,
	SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME,
	SE_ENABLE_DELEGATION_NAME,
	SE_IMPERSONATE_NAME,
	SE_INC_BASE_PRIORITY_NAME,
	SE_INCREASE_QUOTA_NAME,
	SE_LOAD_DRIVER_NAME,
	SE_LOCK_MEMORY_NAME,
	SE_MACHINE_ACCOUNT_NAME,
	SE_MANAGE_VOLUME_NAME,
	SE_PROF_SINGLE_PROCESS_NAME,
	SE_RELABEL_NAME,
	SE_REMOTE_SHUTDOWN_NAME,
	SE_RESTORE_NAME,
	SE_SECURITY_NAME,
	SE_SHUTDOWN_NAME,
	SE_SYNC_AGENT_NAME,
	SE_SYSTEM_ENVIRONMENT_NAME,
	SE_SYSTEM_PROFILE_NAME,
	SE_SYSTEMTIME_NAME,
	SE_TAKE_OWNERSHIP_NAME,
	SE_TCB_NAME,
	SE_TIME_ZONE_NAME,
	SE_TRUSTED_CREDMAN_ACCESS_NAME,
	SE_UNDOCK_NAME,
	SE_UNSOLICITED_INPUT_NAME
};

/* returns a createprocessable handle to TrustedInstaller */
HANDLE get_ti_process() {
    int result;
    SERVICE_STATUS_PROCESS stat = { 0 };

    SC_HANDLE hTI = OpenService(
        OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE),
        TEXT("TrustedInstaller"),
        SERVICE_START | SERVICE_QUERY_STATUS
    );

    result = StartService(hTI, 0, NULL);
    if(!result) {
        result = GetLastError();
        if(result != ERROR_SERVICE_ALREADY_RUNNING) {
            write("Failed to start the TrustedInstaller service");
            exit(4);
        }
    }

    DWORD idc;
    QueryServiceStatusEx(hTI, SC_STATUS_PROCESS_INFO, &stat, sizeof(SERVICE_STATUS_PROCESS), &idc);

    if(stat.dwCurrentState != SERVICE_RUNNING && stat.dwCurrentState != SERVICE_START_PENDING) {
        if(stat.dwCurrentState == SERVICE_DISABLED)
            write("You disabled TrustedInstaller. Undisable it.");
        write("TrustedInstaller does not react.");
        exit(5);
    }

    return OpenProcess(PROCESS_CREATE_PROCESS, FALSE, stat.dwProcessId);
}

/* attempts to enable every known privilege on a token */
void try_max_privileges(HANDLE token) {
    /* this ignores any errors because not all tokens are present for Administrators */
    TOKEN_PRIVILEGES *tp = calloc(1, 4 + 35 * sizeof(LUID_AND_ATTRIBUTES));
    tp->PrivilegeCount = 35;

    for(size_t i = 0; i < 35; ++i) {
        LUID luid;
        LookupPrivilegeValue(NULL, ALL_TOKEN_PRIVILEGES[i], &luid);

        tp->Privileges[i].Luid = luid;
        tp->Privileges[i].Attributes = SE_PRIVILEGE_ENABLED;
    }
    AdjustTokenPrivileges(token, FALSE, tp, 0, NULL, NULL);
}

/* 0 - ok, 1 - failed to adjust */
int add_privilege(HANDLE token, TCHAR *name) {
    /* this only cares about results */
    int result;
    TOKEN_PRIVILEGES tp = { 0 };
    LUID luid = { 0 };

    result = LookupPrivilegeValue(NULL, name, &luid);

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    result = AdjustTokenPrivileges(token, FALSE, &tp, 0, NULL, NULL);
    if(result)
        return 0;
    return 1;

}

void get_sedebug() {
    int result;
    HANDLE thread_token;

    ImpersonateSelf(SecurityImpersonation);
    if(OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &thread_token)){
        result = add_privilege(thread_token, TEXT("SeDebugPrivilege"));
        if(result != 0) {
            write("Make sure your user account has SeDebugPrivilege");
            exit(3);
        }
    } else {
        write("Could not open token for adjustment");
        exit(2);
    }
}

void run_as_ti(TCHAR *command, int wait) {
    size_t attr_list_size;
    HANDLE hpTI = get_ti_process();

    STARTUPINFOEX startup_info = {
        .StartupInfo.cb = sizeof(STARTUPINFOEX),
        .StartupInfo.dwFlags = STARTF_USESHOWWINDOW,
        .StartupInfo.wShowWindow = SW_SHOWNORMAL
    };

    { /* init attribute list to allow setting process' parent */
        InitializeProcThreadAttributeList(NULL, 1, 0, &attr_list_size);
        startup_info.lpAttributeList = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, attr_list_size);
        InitializeProcThreadAttributeList(startup_info.lpAttributeList, 1, 0, &attr_list_size);

        UpdateProcThreadAttribute(startup_info.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hpTI, sizeof(HANDLE), NULL, NULL);
    }

    PROCESS_INFORMATION proc_info = { 0 };

	int result = CreateProcess(
        NULL,
        command,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE,
        NULL,
        NULL,
        &startup_info,
        &proc_info
    );
    if(!result) {
        write("Creating process failed!?");
        exit(GetLastError()); // TODO better way?
    }
    HANDLE token;

    OpenProcessToken(proc_info.hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token);
    try_max_privileges(token);

    ResumeThread(proc_info.hThread);
    if(wait)
        WaitForSingleObject(proc_info.hProcess, INFINITE);

}

/* end of disgusting win32 code */
/* time for disgusting libc code */

void print_help() {
    write("Usage: tirun [-w] [-h] [-c (COMMAND...)]");
    write("");
    write(" -w: Wait for process to finish after running it");
    write(" -h: Show this help message");
    write(" -c: Specify command to run");
}

TCHAR *glue_cmdline(int argc, TCHAR *argv[], int arg_offset) {
    size_t total_length = 0;
    for(size_t i = arg_offset; i < argc; ++i)
        total_length += strlen(argv[i]);

    TCHAR *cmdline = calloc(total_length + (argc - arg_offset), sizeof(TCHAR));
	
    for(size_t i = arg_offset; i < argc; ++i) {
        strcat(cmdline, argv[i]);
        if(i != argc - 1)
            strcat(cmdline, " ");
    }

    return cmdline;
}

int _tmain(int argc, TCHAR *argv[]) {

    /* parse commandline */
    int wait = 0;
    int command_index = 0;
    for(size_t i = 1; i < argc; ++i) {
        if(strncmp(argv[i], TEXT("-w"), 2) == 0) {
            wait = 1;
        } else if(strncmp(argv[i], TEXT("-h"), 2) == 0) {
            print_help();
            return 0;
        } else if(strncmp(argv[i], TEXT("-c"), 2) == 0) {
            command_index = i + 1;
            break;
        } else {
            write("Unknown argument.");
            print_help();
            return 1;
        }
    }

    TCHAR *command = calloc(8, sizeof(TCHAR));

    if(command_index == 0)
		strcat(command, TEXT("cmd.exe"));
    else
        command = glue_cmdline(argc, argv, command_index);

    get_sedebug();
    run_as_ti(command, wait);

    write("bye!");
    return 0;
}