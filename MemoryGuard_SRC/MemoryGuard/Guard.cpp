/*
	Memory Guard Library
	Platform: x64-x86
	Version: 1.0.0f
	Creation Date: 12.05.19
	Copyrights: NtKernelMC
	Task: Prevention external memory allocations & detecting hidden memory

	[ENG] Features:
	> Detection of external kernel-space and user-space memory allocations
	> Support for x64-x86 architectures for Windows family systems from Vista and higher
	> Protection from illegal memory allocation from target process
	> Additional functional for releasing detected memory with hacks
	> Addition functional for destroying hacking threads
	> Additional functional for dumping memory with hacks
	[RUS] Функционал: 
	> Обнаружение внешнего выделения памяти как с режима ядра так и с юзермода
	> Поддержка х64-х86 архитектур для операционных систем семейства Windows начиная с Vista и выше
	> Защита против несанционнированого выделения памяти уже из нутри целевого процесса
	> Дополнительный функционал для освобождения обнаруженой памяти 
	> Дополнительный функционал для безопасного удаления читерских потоков
	> Дополнительный функционал для дампа памяти с обнаружеными читами
*/
#include <Windows.h>
#include <thread>
#include <map>
#include <Psapi.h>
#include <winternl.h>
#include <TlHelp32.h>
#include "VEH.h"
using namespace std;
namespace MemoryGuard
{
#ifdef _WIN64
typedef DWORD64 COMPATIBLE_DWORD;
#define START_ADDRESS (PVOID)0x00000000010000
#define END_ADDRESS (0x00007FF8F2580000 - 0x00000000010000)
#else
typedef DWORD COMPATIBLE_DWORD;
#define START_ADDRESS (PVOID)0x10000
#define END_ADDRESS (0x7FFF0000 - 0x10000)
#endif
	HANDLE hThread = NULL;
	typedef NTSTATUS(__stdcall *NtAllocateVirtualMemoryT)(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG ZeroBits,
	PULONG RegionSize, ULONG AllocationType, ULONG Protect);
	NtAllocateVirtualMemoryT NtAllocateVirtualMemory = NULL;
	enum DetectionType
	{
		ByExternalAllocation = 1
	};
	typedef struct
	{
		MEMORY_BASIC_INFORMATION mbi;
		DetectionType detectBy;
	} MEM_GUARD, *PMEM_GUARD;
	typedef bool(__stdcall *MemoryGuardCallback)(PMEM_GUARD guard_info);
	typedef struct
	{
		WORD iteration_delay;
		map<PVOID, DWORD> RegionInfo;
		MemoryGuardCallback callback;
		bool WasFilled;
	} MEM_WATCHER, *PMEM_WATCHER;
	MEM_WATCHER watcher;
	template<typename First, typename Second>
	bool __stdcall SearchForMapMatch(const map<First, Second> &map, const First first, const Second second)
	{
		for (auto it : map)
		{
			if (it.first == first && it.second == second) return true;
		}
		return false;
	}
	BYTE __stdcall WatchMemoryAllocations(PMEM_WATCHER pwatcher, const void* ptr, size_t length, MEMORY_BASIC_INFORMATION* info, int size)
	{
		if (pwatcher == nullptr || ptr == nullptr || info == nullptr) return 0;
		const void* end = (const void*)((const char*)ptr + length);
		DWORD mask = (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_READ);
		while (ptr < end && VirtualQuery(ptr, &info[0], sizeof(*info)) == sizeof(*info))
		{
			MEMORY_BASIC_INFORMATION* i = &info[0];
			if ((i->State != MEM_FREE || i->State != MEM_RELEASE) && i->Type & (MEM_IMAGE | MEM_PRIVATE) && i->Protect & mask)
			{
				if (!pwatcher->WasFilled)
				{
					if (!SearchForMapMatch<PVOID, DWORD>(pwatcher->RegionInfo, i->BaseAddress, i->RegionSize))
					pwatcher->RegionInfo.insert(pwatcher->RegionInfo.begin(), pair<PVOID, DWORD>(i->BaseAddress, i->RegionSize));
				}
				else
				{
					if (!SearchForMapMatch<PVOID, DWORD>(pwatcher->RegionInfo, i->BaseAddress, i->RegionSize)) return 1;
				}
			}
			ptr = (const void*)((const char*)(i->BaseAddress) + i->RegionSize);
		}
		return 0;
	}
	bool __cdecl MakeMemoryDump(MEMORY_BASIC_INFORMATION* mbi, PVOID buffer)
	{
		if (mbi == nullptr || buffer == nullptr) return false;
		__try
		{
			memcpy(buffer, mbi->BaseAddress, mbi->RegionSize);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) { return false; }
		return true;
	}
	bool __stdcall DestroyThreadsAndFreeMemory(MEMORY_BASIC_INFORMATION* mbi)
	{
		if (mbi == nullptr) return false;
		typedef NTSTATUS(__stdcall *tNtQueryInformationThread)
		(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass,
		PVOID ThreadInformation, ULONG ThreadInformationLength,
		PULONG ReturnLength); tNtQueryInformationThread NtQueryInformationThread =
		(tNtQueryInformationThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread");
		THREADENTRY32 th32; HANDLE hSnapshot = NULL; th32.dwSize = sizeof(THREADENTRY32);
		hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (Thread32First(hSnapshot, &th32))
		{
			do
			{
				if (th32.th32OwnerProcessID == GetCurrentProcessId() && th32.th32ThreadID != GetCurrentThreadId())
				{
					HANDLE targetThread = OpenThread(THREAD_ALL_ACCESS, FALSE, th32.th32ThreadID);
					if (targetThread)
					{
						SuspendThread(targetThread); COMPATIBLE_DWORD tempBase = 0x0;
						NtQueryInformationThread(targetThread, (THREADINFOCLASS)9, &tempBase, sizeof(COMPATIBLE_DWORD), NULL);
						ResumeThread(targetThread); 
						if (tempBase >= (COMPATIBLE_DWORD)mbi->BaseAddress && tempBase <= ((COMPATIBLE_DWORD)mbi->BaseAddress + mbi->RegionSize))
						TerminateThread(targetThread, 0);
						CloseHandle(targetThread);
					}
				}
			}
			while (Thread32Next(hSnapshot, &th32));
			if (hSnapshot != NULL) CloseHandle(hSnapshot);
		}
		return (bool)VirtualFree(mbi->BaseAddress, 0, MEM_RELEASE);
	}
	bool __stdcall ReportToCallback(MEMORY_BASIC_INFORMATION *mbi, PMEM_WATCHER pwatcher, DetectionType detectBy)
	{
		if (mbi == nullptr || pwatcher == nullptr) return false;
		MEM_GUARD guard; guard.detectBy = detectBy; guard.mbi = *mbi; 
		char MappedName[256]; memset(MappedName, 0, sizeof(MappedName));
		typedef DWORD (__stdcall *LPFN_GetMappedFileNameA)(HANDLE hProcess, LPVOID lpv, LPCSTR lpFilename, DWORD nSize);
	    HMODULE hPsapi = LoadLibraryA("psapi.dll");
		LPFN_GetMappedFileNameA lpGetMappedFileNameA = (LPFN_GetMappedFileNameA)GetProcAddress(hPsapi, "GetMappedFileNameA");
		lpGetMappedFileNameA(GetCurrentProcess(), mbi->BaseAddress, MappedName, sizeof(MappedName));
		if (strlen(MappedName) > 4) return false; // Fix of false-positives on win7 x32 (apphelp.dll)
		bool action = pwatcher->callback(&guard);
		if (!action) DestroyThreadsAndFreeMemory(mbi);
		return true;
	}
	void __stdcall MemoryWatcher(PMEM_WATCHER pwatcher)
	{
		if (pwatcher == nullptr) return;
		while (true)
		{
			MEMORY_BASIC_INFORMATION mbi = { 0 };
			BYTE IllegalAlloc = WatchMemoryAllocations(pwatcher, START_ADDRESS, END_ADDRESS, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
			pwatcher->WasFilled = true;
			if (IllegalAlloc == 1) ReportToCallback(&mbi, pwatcher, ByExternalAllocation);
			Sleep(pwatcher->iteration_delay);
		}
	}
	NTSTATUS __stdcall NtAllocateVirtualMemoryHook(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG ZeroBits,
	PULONG RegionSize, ULONG AllocationType, ULONG Protect)
	{
		DeleteVEH();
		NTSTATUS sts = NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
		if (!SearchForMapMatch<PVOID, DWORD>(watcher.RegionInfo, *BaseAddress, *RegionSize))
		{
			watcher.RegionInfo.insert(watcher.RegionInfo.begin(), pair<PVOID, DWORD>(*BaseAddress, (DWORD)*RegionSize));
		}
		SetupVEH((DWORD_PTR)NtAllocateVirtualMemory, (DWORD_PTR)NtAllocateVirtualMemoryHook);
		return sts;
	}
	bool __cdecl InstallMemoryGuard(MemoryGuardCallback callback, WORD iteration_delay)
	{
		if (callback == nullptr || iteration_delay == 0 || hThread) return false;
		NtAllocateVirtualMemory = (NtAllocateVirtualMemoryT)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
		if (NtAllocateVirtualMemory == nullptr) return false; 
		watcher.iteration_delay = iteration_delay;
		watcher.WasFilled = false; watcher.callback = callback;
		hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)MemoryWatcher, &watcher, 0, 0);
		SetupVEH((DWORD_PTR)NtAllocateVirtualMemory, (DWORD_PTR)NtAllocateVirtualMemoryHook);
		return true;
	}
	bool __cdecl DestroyMemoryGuard(void)
	{
		if (!hThread) return false;
		else
		{
			TerminateThread(hThread, 0); hThread = NULL; 
			DeleteVEH();
		}
		return true;
	}
};