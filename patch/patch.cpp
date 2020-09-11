#include <cstdio>
#include <windows.h>

//
// Меняем 
//  0x0040108f  eb0c  jmp loc.0040109d
// на
//  0x0040108f  90    nop
//  0x00401090  90    nop
//
VOID patch(LPCTSTR szFile)
{
    CONST BYTE bData[2] = { 0x90, 0x90 };
    HANDLE hFile;
    DWORD dwBytesWritten;

    hFile = CreateFile(
        szFile, 
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Couldn't open the file!");
        return;
    }

    // инструкция виртуального адреса 0x0040108f
    // находится в файле по смещению 0x28F
    SetFilePointer(hFile, 0x28F, NULL, FILE_BEGIN);
    WriteFile(hFile, bData, 2, &dwBytesWritten, NULL);
    CloseHandle(hFile);
}

VOID startup(TCHAR *argv[], LPCTSTR lpApplicationName)
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
    patch(L"t.exe");
    startup(argv, L"t.exe");
    //system("t.exe");
    return 0;
}
