#include <windows.h>
#include <conio.h>
#include <stdio.h>

bool CreateProcessWithDlls(const char* exePath, const char* args, int numDlls, const char* dllPaths[]);

VOID startup(TCHAR* argv[], LPCTSTR lpApplicationName)
{
    // additional information
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    // set the size of the structures
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // start the program up
    if (!CreateProcess(lpApplicationName,   // the path
        argv[1],        // Command line
        NULL,           // Process handle not inheritable
        NULL,           // Thread handle not inheritable
        FALSE,          // Set handle inheritance to FALSE
        0,              // No creation flags
        NULL,           // Use parent's environment block
        NULL,           // Use parent's starting directory 
        &si,            // Pointer to STARTUPINFO structure
        &pi             // Pointer to PROCESS_INFORMATION structure (removed extra parentheses)
    )) {
        printf("CreateProcess failed (%d).\n", GetLastError());
        return;
    }
    // Close process and thread handles. 
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

int main(int argc, TCHAR* argv[])
{
	//const char* dllPaths[1] = { "hook_splice_lib.dll" };
	//CreateProcessWithDlls("t.exe", "", 1, dllPaths);
    
    HMODULE hLib = LoadLibrary(L"hook_splice_lib.dll");
	HOOKPROC HookProcAddr = (HOOKPROC) GetProcAddress(hLib, "?HookProc@@YAJHIJ@Z");
	//printf("MessageBoxA intercepted (%p %p), press ENTER to resume...", hLib, HookProcAddr);
	HHOOK HookHandle = SetWindowsHookEx(WH_GETMESSAGE, HookProcAddr, hLib, 0);
	startup(argv, L"t.exe");
    MessageBoxA(0, "Text", "Cap", 0);
	_getch();
	//UnhookWindowsHookEx(HookHandle);
	//FreeLibrary(hLib);

    return 0;
}
