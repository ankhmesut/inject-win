#include "CommonHotSplice.h"
#include <string>

THotPachSpliceData HotPathSpliceRec;

// процедура пишет новый блок данных по адресу функции
void SpliceNearJmp(void* FuncAddr, TNearJmpSpliceRec NewData)
{
    DWORD OldProtect;

    VirtualProtect(FuncAddr, sizeof(TNearJmpSpliceRec), PAGE_EXECUTE_READWRITE, &OldProtect);

    memcpy(FuncAddr, &NewData, sizeof(TNearJmpSpliceRec));

    VirtualProtect(FuncAddr, sizeof(TNearJmpSpliceRec), OldProtect, &OldProtect);
    FlushInstructionCache(GetCurrentProcess, FuncAddr, sizeof(TNearJmpSpliceRec));
}

// процедура атомарно изменяет два байта по переданному адресу
void SpliceLockJmp(void* FuncAddr, WORD NewData)
{

    DWORD OldProtect;

    VirtualProtect(FuncAddr, 2, PAGE_EXECUTE_READWRITE, &OldProtect);

    __asm {
        mov  ax, NewData
        mov  ecx, FuncAddr
        lock xchg word ptr[ecx], ax
    };

    VirtualProtect(FuncAddr, 2, OldProtect, &OldProtect);
    FlushInstructionCache(GetCurrentProcess(), FuncAddr, 2);
}

INT InterceptedMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
    std::string s = (const char *)(lpText);
    s = s + "\n_(HOOK)";

    // снимаем перехват
    SpliceLockJmp(HotPathSpliceRec.FuncAddr, HotPathSpliceRec.LockJmp);
    
    // вызываем оригинальную функцию
    int res = MessageBoxA(hWnd, (LPCSTR)s.c_str(), lpCaption, uType);
    
    // восстанавливаем перехват
    SpliceLockJmp(HotPathSpliceRec.FuncAddr, LOCK_JMP_OPCODE);

    return res;
}

void InitHotPatchSpliceRec()
{
    // запоминаем оригинальный адрес перехватываемой функции
    HotPathSpliceRec.FuncAddr = GetProcAddress(GetModuleHandle(L"user32"), "MessageBoxA");
    // читаем два байта с ее начала, их мы будем перезатирать
    memcpy(&HotPathSpliceRec.LockJmp, *HotPathSpliceRec.FuncAddr, 2);
    // инициализируем опкод JMP NEAR
    HotPathSpliceRec.SpliceRec.JmpOpcode = 0xE9;
    // рассчитываем адрес прыжка
    HotPathSpliceRec.SpliceRec.Offset = (char *)(&InterceptedMessageBoxA) + 5 -
        (char *)(HotPathSpliceRec.FuncAddr) - sizeof(TNearJmpSpliceRec);
}