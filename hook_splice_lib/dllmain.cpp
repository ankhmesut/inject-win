// dllmain.cpp : Определяет точку входа для приложения DLL.
#include "pch.h"
#include "CommonHotSplice.h"

__declspec(dllexport) LRESULT HookProc(int Code, WPARAM WParam, LPARAM LParam)
{
    return CallNextHookEx(0, Code, WParam, LParam);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // инициализируем структуру для перехватчика
        InitHotPatchSpliceRec();
        // пишем прыжок в область NOP-ов
        SpliceNearJmp((char *)(HotPathSpliceRec.FuncAddr) - 5, HotPathSpliceRec.SpliceRec);
        // перехватываем MessageBoxA
        SpliceLockJmp(HotPathSpliceRec.FuncAddr, LOCK_JMP_OPCODE);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        // при выгрузке библиотеки снимаем перехват
        SpliceLockJmp(HotPathSpliceRec.FuncAddr, HotPathSpliceRec.LockJmp);
        break;
    }
    return TRUE;
}
