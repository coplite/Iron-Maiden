// g++ -shared -o payload.dll DLLfile.cpp
#include <Windows.h>

LONG WINAPI Exceptioner(_EXCEPTION_POINTERS *ExceptionInfo)
{
	//std::cout << "[-] exception caught";
	MessageBox(0,"Insert", "Shellcode here kitty cat", MB_OK);
	exit(-1);
}

bool __stdcall DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
	switch(dwReason)
	{
		case DLL_PROCESS_ATTACH:
		{
			AddVectoredExceptionHandler(1, Exceptioner);
			MessageBox(NULL, "[+]", "Injected DLL", MB_OK | MB_ICONINFORMATION);
		}
		case DLL_PROCESS_DETACH:
		{
			MessageBox(NULL, "[!] Dead bird detected!", "I<3Futanari", MB_OK | MB_ICONINFORMATION);
			break;
		}
	}
	return true;
}