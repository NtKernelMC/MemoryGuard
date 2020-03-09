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
#pragma once
#include <Windows.h>
namespace MemoryGuard
{
	enum DetectionType
	{
		ByExternalAllocation = 1
	};
	typedef struct
	{
		MEMORY_BASIC_INFORMATION mbi;
		DetectionType detectBy;
	} MEM_GUARD, *PMEM_GUARD;
	/*
		bool __stdcall MemoryGuardCallback(PMEM_GUARD guard_info);
		> return false - if you wanna destroy all hack threads and free this memory
		> before you will return false - recommended to call MakeMemoryDump for storing hack on your server
	*/
	typedef bool(__stdcall *MemoryGuardCallback)(PMEM_GUARD guard_info);
	bool __cdecl MakeMemoryDump(MEMORY_BASIC_INFORMATION* mbi, PVOID buffer);
	bool __cdecl InstallMemoryGuard(MemoryGuardCallback callback, WORD iteration_delay);
	bool __cdecl DestroyMemoryGuard(void);
};