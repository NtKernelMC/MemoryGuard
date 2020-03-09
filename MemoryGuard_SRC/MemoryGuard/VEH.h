#pragma once
#include <windows.h>
DWORD_PTR hookAddr, origAddr; 
DWORD __stdcall ExceptionFilter(EXCEPTION_POINTERS *pExceptionInfo)
{
	if (pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
	{
#ifdef _WIN64
		if (pExceptionInfo->ContextRecord->Rip == origAddr) pExceptionInfo->ContextRecord->Rip = hookAddr;
#else
		if (pExceptionInfo->ContextRecord->Eip == origAddr) pExceptionInfo->ContextRecord->Eip = hookAddr;
#endif
		pExceptionInfo->ContextRecord->EFlags |= 0x100;
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	if (pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
	{
		DWORD dwOld; VirtualProtect((void*)origAddr, 1, PAGE_EXECUTE | PAGE_GUARD, &dwOld);
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}
void SetupVEH(DWORD_PTR funcAddr, DWORD_PTR hookedFunc)
{
	hookAddr = hookedFunc; origAddr = funcAddr;
	AddVectoredExceptionHandler(true, (PVECTORED_EXCEPTION_HANDLER)ExceptionFilter);
	DWORD dwOld; VirtualProtect((void*)origAddr, 1, PAGE_EXECUTE | PAGE_GUARD, &dwOld);
}
void DeleteVEH()
{
	DWORD dwOld; VirtualProtect((void*)origAddr, 1, PAGE_EXECUTE_READWRITE, &dwOld);
	RemoveVectoredExceptionHandler(ExceptionFilter);
}