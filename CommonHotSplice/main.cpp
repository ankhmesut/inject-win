#include <windows.h>
#include "CommonHotSplice.h"

int main(int argc, char* argv[])
{
	
	// инициализируем структуру для перехватчика
	InitHotPatchSpliceRec();
	// пишем прыжок в область NOP-ов
	SpliceNearJmp((char *)(HotPathSpliceRec.FuncAddr) - 5, HotPathSpliceRec.SpliceRec);
	// перехватываем MessageBoxW
	SpliceLockJmp(HotPathSpliceRec.FuncAddr, LOCK_JMP_OPCODE);
	
	MessageBoxA(0, "TEST", nullptr, 0);

	return 0;
}