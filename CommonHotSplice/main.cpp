#include <windows.h>
#include "CommonHotSplice.h"

int main(int argc, char* argv[])
{
	
	// �������������� ��������� ��� ������������
	InitHotPatchSpliceRec();
	// ����� ������ � ������� NOP-��
	SpliceNearJmp((char *)(HotPathSpliceRec.FuncAddr) - 5, HotPathSpliceRec.SpliceRec);
	// ������������� MessageBoxW
	SpliceLockJmp(HotPathSpliceRec.FuncAddr, LOCK_JMP_OPCODE);
	
	MessageBoxA(0, "TEST", nullptr, 0);

	return 0;
}