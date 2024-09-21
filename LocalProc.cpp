#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>


int GetThreadID(int PID)
{
	THREADENTRY32 threadEntry;
	CONTEXT context;
	context.ContextFlags = CONTEXT_FULL;
	threadEntry.dwSize = sizeof(THREADENTRY32);
	
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	Thread32First(snapshot, &threadEntry);

	while(Thread32Next(snapshot, &threadEntry))
	{
		if (threadEntry.th32OwnerProcessID == PID)
		{
			std::cout << "thread ID: " << threadEntry.th32ThreadID << "\n";
			CloseHandle(snapshot);
			return threadEntry.th32ThreadID;
		}
	}
	CloseHandle(snapshot);
	return -1;
}


LONG WINAPI Exceptioner(_EXCEPTION_POINTERS *ExceptionInfo)
{
	//std::cout << "[-] exception caught";
	MessageBox(0,"Insert", "Shellcode here", MB_OK);
	exit(-1);
}

int main()
{
	AddVectoredExceptionHandler(1, Exceptioner);
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_FULL;
	
	HANDLE hProcess = GetModuleHandleA(NULL);
	if(!hProcess)
	{
		std::cout << "[-] Failed to get handle!!";
		exit(-1);
	}

	int tid = GetThreadID(GetCurrentProcessId());
	if(tid == -1)
	{
		std::cout << "[-] Failed to get Thread ID";
		CloseHandle(hProcess);
		exit(-1);
	}
	
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, false, tid);
	if(!hThread)
	{
		std::cout << "[-] Failed to open thread";
		CloseHandle(hProcess);
		exit(-1);
	}
	
	GetThreadContext(hThread, &ctx);
	ctx.Rip = (DWORD64)nullptr;
	SetThreadContext(hThread, &ctx);
	
	CloseHandle(hProcess);
	CloseHandle(hThread);
}