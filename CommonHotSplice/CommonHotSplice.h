#pragma once

#include <windows.h>

const WORD LOCK_JMP_OPCODE = 0xF9EB;

#pragma pack(push, 1)
struct TNearJmpSpliceRec
{
    // структура для обычного сплайса через JMP NEAR OFFSET
    BYTE JmpOpcode;
    DWORD Offset;
};

struct THotPachSpliceData
{
    FARPROC FuncAddr;
    TNearJmpSpliceRec SpliceRec;
    WORD LockJmp;
};
#pragma pack(pop)

void SpliceNearJmp(void* FuncAddr, TNearJmpSpliceRec NewData);
void SpliceLockJmp(void* FuncAddr, WORD NewData);
INT InterceptedMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
void InitHotPatchSpliceRec();


extern THotPachSpliceData HotPathSpliceRec;