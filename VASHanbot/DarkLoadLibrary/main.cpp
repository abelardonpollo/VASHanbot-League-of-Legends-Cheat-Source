#include <stdio.h>
#include <windows.h>

#include "pebutils.h"
#include "darkloadlibrary.h"

typedef DWORD (WINAPI * _ThisIsAFunction) (LPCWSTR);


void* read_file(const char* fileName, size_t* fileSize)
{
	HANDLE fileHandle = NULL;
	DWORD readd = 0;
	PVOID fileBufPtr = NULL;

	fileHandle = CreateFileA(
		fileName,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (fileHandle == INVALID_HANDLE_VALUE)
	{
		*fileSize = 0;
		return NULL;
	}

	*fileSize = GetFileSize(fileHandle, NULL);

	fileBufPtr = calloc(1, *fileSize);

	if (!ReadFile(fileHandle, fileBufPtr, *fileSize, &readd, NULL))
	{
		free(fileBufPtr);
		fileBufPtr = NULL;
		*fileSize = 0;
	}

	CloseHandle(fileHandle);
	return fileBufPtr;

}

VOID main()
{
	GETPROCESSHEAP pGetProcessHeap = (GETPROCESSHEAP)GetFunctionAddress(IsModulePresent(L"Kernel32.dll"), "GetProcessHeap");
	HEAPFREE pHeapFree = (HEAPFREE)GetFunctionAddress(IsModulePresent(L"Kernel32.dll"), "HeapFree");



	size_t n_size = 0;
	void* buffer_ = read_file("dll.dll", &n_size);
	if (!buffer_ || n_size == 0)
	{
		return;
	}

	PDARKMODULE DarkModule = DarkLoadLibrary(
		LOAD_LOCAL_FILE,
		L"D:\\Download\\DarkLoadLibrary-master\\DarkLoadLibrary\\dll.dll",
		0,
		0,
		0
	);

	char buff_[MAX_PATH];
	GetModuleFileNameA((HMODULE)DarkModule->ModuleBase, buff_, MAX_PATH);

	auto b = GetModuleHandleA("dll.dll");

	if (!DarkModule->bSuccess)
	{
		printf("load failed: %S\n", DarkModule->ErrorMsg);
		pHeapFree(pGetProcessHeap(), 0, DarkModule->ErrorMsg);
		pHeapFree(pGetProcessHeap(), 0, DarkModule);
		return;
	}

	_ThisIsAFunction ThisIsAFunction = (_ThisIsAFunction)GetFunctionAddress(
		(HMODULE)DarkModule->ModuleBase,
		"CallThisFunction"
	);
	pHeapFree(pGetProcessHeap(), 0, DarkModule);

	if (!ThisIsAFunction)
	{
		printf("failed to find it\n");
		return;
	}

    ThisIsAFunction(L"this is working!!!");

	return;
}