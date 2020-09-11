#include <iostream>
#include <Windows.h>
#include <winternl.h>

FARPROC messageBoxAddress = NULL;
SIZE_T bytesWritten = 0;
char messageBoxOriginalBytes[6] = {};

int __stdcall HookedMessageBox(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {

	// print intercepted values from the MessageBoxA function
	std::cout << "Ohai from the hooked function\n";
	std::cout << "Text: " << (LPCSTR)lpText << "\nCaption: " << (LPCSTR)lpCaption << std::endl;

	// unpatch MessageBoxA
	//WriteProcessMemory(GetCurrentProcess(), (LPVOID)messageBoxAddress, messageBoxOriginalBytes, sizeof(messageBoxOriginalBytes), &bytesWritten);

	// call the original MessageBoxA
	return 0;//MessageBoxA(NULL, lpText, lpCaption, uType);
}

int Hook(HANDLE hProcess)
{
    hProcess = GetCurrentProcess();

	HINSTANCE library = LoadLibraryA("user32.dll");
	SIZE_T bytesRead = 0;

	void* hookedMessageBoxAddress = &HookedMessageBox;
	char patch[6] = { 0 };

	// get address of the MessageBox function in memory
	messageBoxAddress = GetProcAddress(library, "MessageBoxA");

	// Get write permissions to the code
	DWORD oldProtect;
	if (!VirtualProtectEx(hProcess, messageBoxAddress, 6, PAGE_EXECUTE_READWRITE, &oldProtect)) {
		fprintf(stderr, "Could not modify code permissions");
		goto exit;
	}

	// save the first 6 bytes of the original MessageBoxA function - will need for unhooking
	ReadProcessMemory(hProcess, messageBoxAddress, messageBoxOriginalBytes, 6, &bytesRead);

	// create a patch "push <address of new MessageBoxA>; ret"
	memcpy_s(patch, 1, "\x68", 1);
	memcpy_s(patch + 1, 4, &hookedMessageBoxAddress, 4);
	memcpy_s(patch + 5, 1, "\xC3", 1);
    fprintf(stderr, "2");
	// patch the MessageBoxA
	WriteProcessMemory(hProcess, (LPVOID)messageBoxAddress, patch, sizeof(patch), &bytesWritten);

	FlushInstructionCache(hProcess, messageBoxAddress, 6);

    MessageBoxA(NULL, "Text", "Cap", 0);

exit:

	// Restore original code permissions
	if (!VirtualProtectEx(hProcess, messageBoxAddress, 6, oldProtect, &oldProtect)) {
		fprintf(stderr, "Could not restore original code permissions");
	}

	return 0;
}

bool CreateSuspendedProcess(const char* exePath, const char* args, PROCESS_INFORMATION* processInfo)
{
    // Create the process in suspended mode
    // No need to create a copy of args since we're calling
    // the ANSI version which will internally copy the buffer
    STARTUPINFOA startupInfo = { 0 };
    startupInfo.cb = sizeof(startupInfo);
    bool success = CreateProcessA(
        exePath,
        (char*)args,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &startupInfo,
        processInfo);

    if (!success) {
        fprintf(stderr, "Could not create suspended process");
    }
    return success;
}

bool WaitForMainThreadInit(HANDLE hMainThread, DWORD entryPoint)
{
    while (true) {
        // Resume the thread
        if (ResumeThread(hMainThread) == (DWORD)-1) {
            fprintf(stderr, "Could not resume main thread");
            return false;
        }

        // Give the thread some time to progress
        Sleep(100);

        // Suspend the thread to check its status
        if (SuspendThread(hMainThread) == (DWORD)-1) {
            fprintf(stderr, "Could not suspend main thread");
            return false;
        }

        // Get control registers of the thread
        CONTEXT context;
        context.ContextFlags = CONTEXT_CONTROL;
        if (!GetThreadContext(hMainThread, &context)) {
            fprintf(stderr, "Could not get main thread context");
            return false;
        }

        // Are we at the entry point yet?
        if (context.Eip == entryPoint) {
            return true;
        }
    }
}

bool ReadNtHeader(HANDLE hProcess, void* baseAddress, IMAGE_NT_HEADERS32* headers)
{
    IMAGE_DOS_HEADER dosHeader;
    if (!ReadProcessMemory(hProcess, baseAddress, &dosHeader, sizeof(dosHeader), NULL)) {
        fprintf(stderr, "Could not read DOS header");
        return false;
    }
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        fprintf(stderr, "DOS header signature mismatch (got 0x%04x)\n", dosHeader.e_magic);
        return false;
    }

    LONG ntHeaderOffset = dosHeader.e_lfanew;
    IMAGE_NT_HEADERS32 ntHeader;
    if (!ReadProcessMemory(hProcess, (char*)baseAddress + ntHeaderOffset, &ntHeader, sizeof(ntHeader), NULL)) {
        fprintf(stderr, "Could not read NT header");
        return false;
    }
    if (ntHeader.Signature != IMAGE_NT_SIGNATURE) {
        fprintf(stderr, "NT header signature mismatch (got 0x%08x)\n", ntHeader.Signature);
        return false;
    }
    if (ntHeader.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        fprintf(stderr, "NT optional header signature mismatch (got 0x%04x)\n", ntHeader.OptionalHeader.Magic);
        return false;
    }

    *headers = ntHeader;
    return true;
}

bool PatchCode(HANDLE hProcess, void* address, size_t length, const void* newBytes, void* oldBytes)
{
    bool success = false;

    // Get write permissions to the code
    DWORD oldProtect;
    if (!VirtualProtectEx(hProcess, address, length, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        fprintf(stderr, "Could not modify code permissions");
        goto exit;
    }

    // Save the original bytes
    if (!ReadProcessMemory(hProcess, address, oldBytes, length, NULL)) {
        fprintf(stderr, "Could not read original bytes");
        goto restore;
    }

    // Write the new bytes
    if (!WriteProcessMemory(hProcess, address, newBytes, length, NULL)) {
        fprintf(stderr, "Could not write new bytes");
        goto restore;
    }

    // Flush instruction cache
    FlushInstructionCache(hProcess, address, length);

    success = true;

restore:
    // Restore original code permissions
    if (!VirtualProtectEx(hProcess, address, length, oldProtect, &oldProtect)) {
        fprintf(stderr, "Could not restore original code permissions");
    }

exit:
    return success;
}

bool GetBaseAddress(HANDLE hProcess, HANDLE hMainThread, DWORD* base)
{
    PPEB peb;

    // Method 1: Rely on PEB pointer being stored in EBX upon startup
    // http://stackoverflow.com/questions/12808516/pointer-to-baseaddress-through-context-ebx8
    CONTEXT context;
    context.ContextFlags = CONTEXT_INTEGER;
    if (!GetThreadContext(hMainThread, &context)) {
        fprintf(stderr, "Could not get main thread context");
        return false;
    }
    peb = (PPEB)context.Ebx;

    // Method 2: Use NtQueryInformationProcess to get PEB pointer
    // http://stackoverflow.com/questions/8336214/how-can-i-get-a-process-entry-point-address
    /*
#pragma comment(lib, "ntdll.lib")
    PROCESS_BASIC_INFORMATION info;
    if (!NT_SUCCESS(NtQueryInformationProcess(hProcess, ProcessBasicInformation, &info, sizeof(info), NULL))) {
        fprintf(stderr, "Failed to get process info\n");
        return false;
    }
    peb = info.PebBaseAddress;
    */

    // Read base address from PEB
    if (!ReadProcessMemory(hProcess, &peb->Reserved3[1], base, sizeof(*base), NULL)) {
        fprintf(stderr, "Could not read PEB -> base address");
        return false;
    }

    return true;
}

int main()
{
    HANDLE hProcess = NULL;
    HANDLE hMainThread = NULL;
    bool success = false;

    WORD origEntry;
    WORD newEntry = 0xFEEB;

    DWORD entryPoint;

    // Create the process in suspended mode
    PROCESS_INFORMATION processInfo;
    if (!CreateSuspendedProcess("t.exe", "", &processInfo)) {
        fprintf(stderr, "Could not create process\n");
        goto cleanup;
    }

    hProcess = processInfo.hProcess;
    hMainThread = processInfo.hThread;

    // Get base address
    DWORD baseAddress;
    if (!GetBaseAddress(hProcess, hMainThread, &baseAddress)) {
        fprintf(stderr, "Could not get process base address\n");
        goto cleanup;
    }

    // Read NT headers to find entry point
    IMAGE_NT_HEADERS32 ntHeaders;
    if (!ReadNtHeader(hProcess, (void*)baseAddress, &ntHeaders)) {
        fprintf(stderr, "Could not read NT headers\n");
        goto cleanup;
    }

    // Entry point can be calculated from base + relative
    entryPoint = baseAddress + ntHeaders.OptionalHeader.AddressOfEntryPoint;

    // Patch entry point
    // 0xEB = JMP rel8
    // 0xFE = -2
    if (!PatchCode(hProcess, (void*)entryPoint, sizeof(WORD), &newEntry, &origEntry)) {
        fprintf(stderr, "Could not patch entry point\n");
        goto cleanup;
    }

    // Wait for main thread to reach entry point
    // The main thread will be suspended upon return
    if (!WaitForMainThreadInit(hMainThread, entryPoint)) {
        fprintf(stderr, "Waiting for main thread init failed\n");
        goto cleanup;
    }

    Hook(hProcess);

    // Restore entry point
    if (!PatchCode(hProcess, (void*)entryPoint, sizeof(WORD), &origEntry, &newEntry)) {
        fprintf(stderr, "Could not restore entry point\n");
        goto cleanup;
    }

    // Resume execution of main thread
    if (ResumeThread(hMainThread) == (DWORD)-1) {
        fprintf(stderr, "Could not resume main thread");
        goto cleanup;
    }

    success = true;

cleanup:
    if (hMainThread != NULL) {
        CloseHandle(hMainThread);
    }
    if (hProcess != NULL) {
        if (!success) {
            TerminateProcess(hProcess, 1);
        }
        CloseHandle(hProcess);
    }

	return !success;
}