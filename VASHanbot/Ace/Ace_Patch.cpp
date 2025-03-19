#include <intrin.h>
#include <random>
#include "Ace_Patch.h"

#include "../utils/ntdll.h"


#include <TlHelp32.h>

#include "AceHook.h"
#include "../Common.h"
#include "../utils/inline.h"
#include "../utils/fp_call.h"
#include "../utils/syscall.h"
#include "../DarkLoadLibrary/syscalls.h"

#pragma optimize( "", off )



namespace umc
{


	typedef struct _context_info {
		ULONG64 flag;
		ULONG64 tick;
		ULONG64 code;
		ULONG64 in_buffer;
		ULONG64 in_size;
		ULONG64 out_buffer;
		ULONG64 out_size;
		bool* b;

	}context_info, * p_context_info;

	inline __int64  sub_14001A590(BYTE* OutputBuffer, BYTE* key, unsigned int key_len)
	{
		__int64 result; // rax
		int i; // [rsp+0h] [rbp-28h]
		int j; // [rsp+0h] [rbp-28h]
		unsigned int v6; // [rsp+4h] [rbp-24h]
		BYTE v7; // [rsp+8h] [rbp-20h]
		BYTE v8; // [rsp+Ch] [rbp-1Ch]
		BYTE* v9; // [rsp+10h] [rbp-18h]

		*(DWORD*)OutputBuffer = 0;
		*((DWORD*)OutputBuffer + 1) = 0;
		v9 = OutputBuffer + 8;
		for (i = 0; i < 0x100; ++i)
			v9[i] = (BYTE)i;
		v6 = 0;
		result = 0i64;
		v7 = 0;
		for (j = 0; j < 0x100; ++j)
		{
			v8 = v9[j];
			v7 = (unsigned __int8)(key[v6] + v8 + v7);
			v9[j] = v9[v7];
			v9[v7] = v8;
			if (++v6 >= key_len)
				v6 = 0;
			result = (unsigned int)(j + 1);
		}
		return result;
	}

	inline BYTE* sub_14001A3F0(BYTE* key, BYTE* buffer, unsigned int buffer_size)
	{

		BYTE* result; // rax
		unsigned int i; // [rsp+0h] [rbp-28h]
		int v5; // [rsp+4h] [rbp-24h]
		int v6; // [rsp+8h] [rbp-20h]
		BYTE v7; // [rsp+Ch] [rbp-1Ch]
		BYTE v8; // [rsp+10h] [rbp-18h]
		BYTE* v9; // [rsp+18h] [rbp-10h]

		v5 = *(DWORD*)key;
		v6 = *((DWORD*)key + 1);
		v9 = key + 8;
		for (i = 0; i < buffer_size; ++i)
		{
			v5 = (unsigned __int8)(v5 + 1);
			v7 = v9[v5];
			v6 = (unsigned __int8)(v7 + v6);
			v8 = v9[v6];
			v9[v5] = v8;
			v9[v6] = v7;
			buffer[i] ^= v9[(unsigned __int8)(v8 + v7)];
		}
		*(DWORD*)key = v5;
		result = key;
		*((DWORD*)key + 1) = v6;
		return result;
	}

	inline void  tp_e(BYTE* key, unsigned int data_size, BYTE* buffer, unsigned int buffer_size)
	{
		BYTE OutputBuffer[264] = {};
		sub_14001A590(OutputBuffer, key, data_size);
		sub_14001A3F0(OutputBuffer, buffer, buffer_size);
	}

	bool send_request(int code, void* in_buffer, size_t in_size, void* out_buffer, size_t out_size)
	{
		bool b = false;

		context_info ci = { 0 };
		ci.flag = 0x14187345435;
		ci.tick = GetTickCount64();
		ci.code = code;
		ci.in_buffer = (ULONG64)in_buffer;
		ci.in_size = in_size;
		ci.out_buffer = (ULONG64)out_buffer;
		ci.out_size = out_size;
		ci.b = &b;

		const char* key = "#4rXzStiMa^s";
		tp_e((BYTE*)key, (unsigned int)strlen(key), (BYTE*)&ci, sizeof(context_info));

		DWORD c_pid = GetCurrentProcessId();
#ifdef _WIN64
		PULONG_PTR com_addr = (PULONG_PTR)(__readgsqword(0x30) + 0x1820);//特征在这里
		*com_addr = (ULONG64)&ci;
#else
		PULONG_PTR com_addr = (PULONG_PTR)(__readfsdword(0x18) + 0xfe8);//特征在这里
		*com_addr = (ULONG64)&ci;
#endif 

		HANDLE hprocess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, c_pid);
		CloseHandle(hprocess);

		return b;
	}

	bool write_process_memory(uint32_t pid, void* addr, void* buffer, size_t size)
	{
		typedef struct _context_write_memory {

			ULONG64 target_pid;
			ULONG64 addr;
			ULONG64 buffer;
			ULONG64 size;

		}context_write_memory, * p_context_write_memory;

		context_write_memory c;
		c.target_pid = pid;
		c.addr = (ULONG64)addr;
		c.size = size;
		c.buffer = (ULONG64)buffer;

		return umc::send_request(umc::code_util_write_memory, &c, sizeof(context_write_memory));
	}

	bool unlock_protect(uint32_t pid, uintptr_t address)
	{
		typedef struct _REMOVE_VAD {
			ULONG64 ProcessId;
			ULONG64 Address;
		} REMOVE_VAD, * PREMOVE_VAD;

		REMOVE_VAD rv;
		rv.ProcessId = pid;
		rv.Address = address;

		auto b = umc::send_request(umc::code_util_unlock_protect, &rv, sizeof(REMOVE_VAD));
		return  b;
	}

	bool create_thread(uint32_t pid, uintptr_t routine, uintptr_t param)
	{
		typedef struct _context_create_thread {

			ULONG64 target_pid;
			ULONG64 routine;
			ULONG64 param;

		}context_create_thread, * p_context_create_thread;

		context_create_thread c;
		c.target_pid = pid;
		c.routine = routine;
		c.param = param;

		return umc::send_request(umc::code_util_create_thread, &c, sizeof(context_create_thread));
	}

	bool remove_vad(uint32_t pid, uintptr_t address)
	{
		typedef struct _REMOVE_VAD {
			ULONG64 ProcessId;
			ULONG64 Address;
		} REMOVE_VAD, * PREMOVE_VAD;

		REMOVE_VAD rv;
		rv.ProcessId = pid;
		rv.Address = address;

		auto b = umc::send_request(umc::code_util_remove_vad, &rv, sizeof(REMOVE_VAD));
		return  b;
	}

	void protect_add_driver(std::string driver_name)
	{
		umc::send_request(umc::code_protect_add_driver, (void*)driver_name.c_str(), sizeof(void*));
	}

	void protect_remove_driver(std::string driver_name)
	{
		umc::send_request(umc::code_protect_remove_driver, (void*)driver_name.c_str(), sizeof(void*));
	}

	void protect_add_file(std::wstring file_name)
	{
		umc::send_request(umc::code_protect_add_file, (void*)file_name.c_str(), sizeof(void*));
	}

	void protect_remove_file(std::wstring file_name)
	{
		umc::send_request(umc::code_protect_remove_file, (void*)file_name.c_str(), sizeof(void*));
	}

	void protect_add_process(ULONG64 pid)
	{
		umc::send_request(umc::code_protect_add_process, &pid, sizeof(ULONG64));
	}

	void protect_remove_process(ULONG64 pid)
	{
		umc::send_request(umc::code_protect_remove_process, &pid, sizeof(ULONG64));
	}

	void protect_add_memory(int pid, ULONG64 addr, ULONG64 size, protect_type p_type)
	{
		typedef struct _context_protect_memory {

			ULONG64 pid;
			ULONG64 addr;
			ULONG64 size;
			protect_type protect;

		}context_protect_memory, * p_context_protect_memory;

		context_protect_memory pm = {};
		pm.pid = pid;
		pm.addr = addr;
		pm.size = size;
		pm.protect = p_type;

		umc::send_request(umc::code_protect_add_memory, &pm, sizeof(context_protect_memory));
	}

	void protect_remove_memory(int pid, ULONG64 addr, ULONG64 size, protect_type p_type)
	{
		typedef struct _context_protect_memory {

			ULONG64 pid;
			ULONG64 addr;
			ULONG64 size;
			protect_type protect;

		}context_protect_memory, * p_context_protect_memory;

		context_protect_memory pm = {};
		pm.pid = pid;
		pm.addr = addr;
		pm.size = size;
		pm.protect = p_type;

		umc::send_request(umc::code_protect_remove_memory, &pm, sizeof(context_protect_memory));
	}

	void protect_add_whitelist(ULONG64 pid)
	{
		umc::send_request(umc::code_protect_add_whitelist, &pid, sizeof(ULONG64));
	}

	void protect_remove_whitelist(ULONG64 pid)
	{
		umc::send_request(umc::code_protect_remove_whitelist, &pid, sizeof(ULONG64));
	}
}

namespace Ace_Patch
{

	extern "C"
	{
		uintptr_t real_NewCastSpell = 0;
		uintptr_t real_NewIssueOrder = 0;
		uintptr_t real_NewSmoothPath = 0;
		uintptr_t real_RpcsCallBack = 0;
		uintptr_t real_RpcsAceHookInfoPtr = 0;

	}

	using namespace Utils;
	class CFileMapping {
	public:
		CFileMapping() {
			m_bCreated = FALSE;
			m_hFileMap = 0;
			m_dwSize = 0;
			m_lpBaseAddr = NULL;
		}
		virtual ~CFileMapping() { Close(); }

		BOOL Create(LPCSTR pszName, DWORD dwSize, LPBOOL _Out_ lpIsCreated) {
			if (m_bCreated) {
				return m_bCreated;
			}

			m_hFileMap = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, pszName);
			*lpIsCreated = FALSE;
			if (m_hFileMap == NULL) {
				m_hFileMap =
					CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE | SEC_COMMIT, 0, dwSize, pszName);
				if (m_hFileMap == NULL)
					return FALSE;
				*lpIsCreated = TRUE;
			}
			m_lpBaseAddr = MapViewOfFile(m_hFileMap, FILE_MAP_ALL_ACCESS, 0, 0, 0);
			if (m_lpBaseAddr == NULL) {
				CloseHandle(m_hFileMap);
				m_hFileMap = 0;
				return FALSE;
			}
			if (*lpIsCreated == TRUE) {
				ZeroMemory(m_lpBaseAddr, dwSize);
			}
			m_dwSize = dwSize;
			m_bCreated = TRUE;
			return TRUE;
		}
		void Close() {
			if (m_lpBaseAddr) {
				UnmapViewOfFile(m_lpBaseAddr);
				m_lpBaseAddr = NULL;
				m_dwSize = 0;
			}
			if (m_hFileMap) {
				CloseHandle(m_hFileMap);
				m_hFileMap = 0;
			}
			m_bCreated = FALSE;
		}
		BOOL   IsCreated() { return m_bCreated; }
		LPVOID GetBase() { return m_lpBaseAddr; }
		DWORD  GetSize() { return m_dwSize; }

	private:
		BOOL   m_bCreated;
		HANDLE m_hFileMap;
		DWORD  m_dwSize;
		LPVOID m_lpBaseAddr;
	};

	CFileMapping* g_file_mapping = nullptr;

	PatchDllInfo* g_DllInfo = nullptr;
	float LastMoveTick;
	bool limit_mode;
	int debug_mode;
	Utils::module_info g_bot_info = {};
	Utils::module_info g_game_info = {};
	Utils::module_info g_base64_info = {};
	Utils::module_info g_pbc_game64_info = {};
	Utils::module_info g_ats64_info = {};
	Utils::module_info g_csi64_info = {};
	Utils::module_info g_drv64_info = {};
	Utils::module_info g_ace_lolbae_info = {};

	uintptr_t  dwVMTCrcBase;
	//uintptr_t  dwVMTCsi64Base;
	//uintptr_t  dwVMTAts64Base;


	ace_hook* inline_GetLastError = nullptr;

	ace_hook lolbase_load = {};
	ace_hook ace_base_load = {};

	Imsg_info::Imsg_info(BYTE state, int _slot)
	{
		slot = _slot;

		if (state == 0) { u_msg = 0x100; }
		else if (state == 1) { u_msg = 0x101; }


		switch (slot)
		{
		case Q:
		{
			w_param = 0x51;
			if (state == 0) l_param = 0x100001; else if (state == 1) l_param = 0xC0100001;
			break;
		}

		case W:
		{
			w_param = 0x57;
			if (state == 0) l_param = 0x110001; else if (state == 1) l_param = 0xC0110001;
			break;
		}

		case E:
		{
			w_param = 0x45;
			if (state == 0) l_param = 0x120001; else if (state == 1) l_param = 0xC0120001;
			break;
		}
		case R:
		{
			w_param = 0x52;
			if (state == 0) l_param = 0x130001; else if (state == 1) l_param = 0xC0130001;
			break;
		}
		case D:
		{
			w_param = 0x44;
			if (state == 0) l_param = 0x200001; else if (state == 1) l_param = 0xC0200001;
			break;
		}
		case F:
		{
			w_param = 0x46;
			if (state == 0) l_param = 0x210001; else if (state == 1) l_param = 0xC0210001;
			break;
		}
		case n1:
		{
			w_param = 0x31;
			if (state == 0) l_param = 0x20001; else if (state == 1) l_param = 0xC0020001;
			break;
		}
		case n2:
		{
			w_param = 0x32;
			if (state == 0) l_param = 0x30001; else if (state == 1) l_param = 0xC0030001;
			break;
		}
		case n3:
		{
			w_param = 0x33;
			if (state == 0) l_param = 0x40001; else if (state == 1) l_param = 0xC0040001;
			break;
		}
		case n4:
		{
			w_param = 0x34;
			if (state == 0) l_param = 0x50001; else if (state == 1) l_param = 0xC0050001;
			break;
		}
		case n5:
		{
			w_param = 0x35;
			if (state == 0) l_param = 0x60001; else if (state == 1) l_param = 0xC0060001;
			break;
		}
		case n6:
		{
			w_param = 0x36;
			if (state == 0) l_param = 0x70001; else if (state == 1) l_param = 0xC0070001;
			break;
		}
		case n7:
		{
			w_param = 0x37;
			if (state == 0) l_param = 0x80001; else if (state == 1) l_param = 0xC0080001;
			break;
		}

		default:
			break;
		}
	}

	void AddModuleInfo(const DllInfo& info)
	{
		if (info.DllBase == 0 || info.DllSize == 0) {
			return;
		}
		if (!g_DllInfo) return;
		if (g_DllInfo->module_size >= 1000) return;

		

		g_DllInfo->list[g_DllInfo->module_size] = info;
		g_DllInfo->module_size++;
		DedbgA("添加保护模块%d:%p %p", g_DllInfo->module_size, info.DllBase, info.DllSize);
	}

	void DelModuleInfo(uintptr_t mod_base)
	{
		if (mod_base == 0) {
			return;
		}
		if (!g_DllInfo) return;

		if (g_DllInfo->module_size < 1) return;

		int i = 0;
		for (; i < (int)g_DllInfo->module_size; i++)
		{
			if (mod_base == g_DllInfo->list[i].DllBase)
			{
				break;
			}
		}

		if (i != (int)g_DllInfo->module_size)
		{
			for (int j = i; j < 9; j++)
			{
				g_DllInfo->list[j] = g_DllInfo->list[j + 1];
			}

			g_DllInfo->module_size--;
		}

	}

	uintptr_t ntdll_memory = 0;

	namespace real
	{
		uintptr_t LoadLibraryExW = 0;
		uintptr_t LdrLoadDll = 0;
		uintptr_t VirtualQueryEx = 0;
		uintptr_t NtDeviceIoControlFile = 0;
		uintptr_t Csi64MemmoveProc = 0;
		uintptr_t ATS64NtDeviceIoControlFile = 0;
		uintptr_t ATS64ReadProcessMemory = 0;
		uintptr_t CSI64NtDeviceIoControlFile = 0;
		uintptr_t DRV64NtDeviceIoControlFile = 0;
		uintptr_t CSI64ReadProcessMemory = 0;
		uintptr_t CSI64NtQueryVirtualMemory = 0;
		uintptr_t CSI64VirtualQuery = 0;
		uintptr_t CSI64VirtualQueryEx = 0;
		uintptr_t GetModuleHandleA = 0;
		uintptr_t CreateThread = 0;
		uintptr_t VirtualAlloc = 0;
		uintptr_t NtAllocateVirtualMemory = 0;
		uintptr_t ZwCallbackReturn = 0;
		char ZwCallbackReturn_byte[14] = {};
	}

	namespace hook_t
	{
		base::hook::hook_t LoadLibraryExW = 0;
		base::hook::hook_t LdrLoadDll = 0;
	}


	namespace ace_enc
	{
		__int64  sub_14001A590(BYTE* OutputBuffer, BYTE* key, unsigned int key_len)
		{
			__int64 result; // rax
			int i; // [rsp+0h] [rbp-28h]
			int j; // [rsp+0h] [rbp-28h]
			int v6; // [rsp+4h] [rbp-24h]
			BYTE v7; // [rsp+8h] [rbp-20h]
			BYTE v8; // [rsp+Ch] [rbp-1Ch]
			BYTE* v9; // [rsp+10h] [rbp-18h]

			*(DWORD*)OutputBuffer = 0;
			*((DWORD*)OutputBuffer + 1) = 0;
			v9 = OutputBuffer + 8;
			for (i = 0; i < 0x100; ++i)
				v9[i] = (BYTE)i;
			v6 = 0;
			result = 0i64;
			v7 = 0;
			for (j = 0; j < 0x100; ++j)
			{
				v8 = v9[j];
				v7 = (unsigned __int8)(key[v6] + v8 + v7);
				v9[j] = v9[v7];
				v9[v7] = v8;
				if (++v6 >= (int)key_len)
					v6 = 0;
				result = (unsigned int)(j + 1);
			}
			return result;
		}

		BYTE* sub_14001A3F0(BYTE* key, BYTE* buffer, unsigned int buffer_size)
		{
			BYTE* result; // rax
			unsigned int i; // [rsp+0h] [rbp-28h]
			int v5; // [rsp+4h] [rbp-24h]
			int v6; // [rsp+8h] [rbp-20h]
			BYTE v7; // [rsp+Ch] [rbp-1Ch]
			BYTE v8; // [rsp+10h] [rbp-18h]
			BYTE* v9; // [rsp+18h] [rbp-10h]

			v5 = *(DWORD*)key;
			v6 = *((DWORD*)key + 1);
			v9 = key + 8;
			for (i = 0; i < buffer_size; ++i)
			{
				v5 = (unsigned __int8)(v5 + 1);
				v7 = v9[v5];
				v6 = (unsigned __int8)(v7 + v6);
				v8 = v9[v6];
				v9[v5] = v8;
				v9[v6] = v7;
				buffer[i] ^= v9[(unsigned __int8)(v8 + v7)];
			}
			*(DWORD*)key = v5;
			result = key;
			*((DWORD*)key + 1) = v6;
			return result;
		}

		void  sub_14001A510(BYTE* key, unsigned int data_size, BYTE* buffer, unsigned int buffer_size)
		{
			BYTE OutputBuffer[264] = {};

			sub_14001A590(OutputBuffer, key, data_size);
			sub_14001A3F0(OutputBuffer, buffer, buffer_size);
		}



		void  sub_140006B90(BYTE* buffer, unsigned int buffer_size)
		{
			BYTE key[52] = {
		0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x10, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x49,
		0x8B, 0xF8, 0x8B, 0xDA, 0x48, 0x8B, 0xF1, 0x85, 0xD2, 0x74, 0x0C, 0x83, 0xFA, 0x03, 0x75, 0x0C,
		0xE8, 0x90, 0x0B, 0xF9, 0xFF, 0xFF, 0xEB, 0x05, 0xE8, 0xD4, 0xF8, 0xCC, 0xFF, 0xFF, 0x48, 0x8B,
		0x05, 0x4D, 0x73, 0x10
			};



			sub_14001A510(key, sizeof(key), buffer, buffer_size);
		}
	}

	namespace vmt_hook
	{
		NTSTATUS
			NTAPI
			ATS64NtDeviceIoControlFile(
				IN  HANDLE FileHandle,
				IN  HANDLE Event,
				IN  PIO_APC_ROUTINE ApcRoutine,
				IN  PVOID ApcContext,
				OUT PIO_STATUS_BLOCK IoStatusBlock,
				IN  ULONG IoControlCode,
				IN  PVOID InputBuffer,
				IN  ULONG InputBufferLength,
				IN  PVOID OutputBuffer,
				IN  ULONG OutputBufferLength
			)
		{
			//return STATUS_INVALID_HANDLE;
			auto r = base::std_call<NTSTATUS>(real::ATS64NtDeviceIoControlFile, FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);

			if (NT_SUCCESS(r))
			{
				BYTE* buff = new BYTE[InputBufferLength];
				memcpy(buff, InputBuffer, InputBufferLength);
				int i = 0;
				int src_size = InputBufferLength;
				do
				{
					buff[i] = Utils::Math::__ROL1__(buff[i] ^ src_size, 3);
					++i;
				} while (i < src_size);

				if (*(DWORD*)buff == 0x8000201c && OutputBufferLength == sizeof(_MEMORY_BASIC_INFORMATION64))
				{
					auto newdata = new BYTE[OutputBufferLength];

					memcpy(newdata, OutputBuffer, sizeof(_MEMORY_BASIC_INFORMATION64));

					ace_enc::sub_140006B90(newdata, OutputBufferLength);

					auto m = reinterpret_cast<PMEMORY_BASIC_INFORMATION64>(newdata);

					struct csi_201c //接收结构 _MEMORY_BASIC_INFORMATION64
					{
						uint32_t IoControlCode;
						uint32_t tick;
						uint32_t ThreadId;
						uint32_t a;
						uint32_t b;
						uint32_t c;
						uint32_t pid;
						uint32_t d;
						uint32_t address;
					};

					csi_201c* ptr = (csi_201c*)buff;
					DedbgW(L"ATS64NtDeviceIoControlFile: 识别到查询 内存:%x|lol_pid:%d|AllocationBase:%llx", ptr->address, ptr->pid, m->AllocationBase);
					if (ptr->pid == GetCurrentProcessId())
					{

						if (Utils::is_address_in_module(m->AllocationBase, g_csi64_info) || Utils::is_address_in_module(m->BaseAddress, g_csi64_info))
						{
							m->AllocationBase = 0;
							m->AllocationProtect = 0;
							m->State = MEM_FREE;
							m->Protect = PAGE_NOACCESS;
							m->Type = 0;
							//LOG(u8"识别到驱动查询 csi内存:%x|size:%x", ptr->address, m->RegionSize);
							ace_enc::sub_140006B90(newdata, OutputBufferLength);
							memcpy(OutputBuffer, newdata, sizeof(_MEMORY_BASIC_INFORMATION64));
						}

						if (Utils::is_address_in_module(m->AllocationBase, g_game_info) || Utils::is_address_in_module(m->BaseAddress, g_game_info))
						{

							m->AllocationBase = 0;
							m->AllocationProtect = 0;
							m->State = MEM_FREE;
							m->Protect = PAGE_NOACCESS;
							m->Type = 0;
							//Utils::Out::Dedbg_ExA("识别到驱动查询 csi内存:%p|size:%p", m->BaseAddress, m->RegionSize);
							ace_enc::sub_140006B90(newdata, OutputBufferLength);
							memcpy(OutputBuffer, newdata, sizeof(_MEMORY_BASIC_INFORMATION64));
						}

						if (Utils::is_address_in_module(m->AllocationBase, g_ats64_info) || Utils::is_address_in_module(m->BaseAddress, g_ats64_info))
						{

							m->AllocationBase = 0;
							m->AllocationProtect = 0;
							m->State = MEM_FREE;
							m->Protect = PAGE_NOACCESS;
							m->Type = 0;
							//Utils::Out::Dedbg_ExA("识别到驱动查询 csi内存:%p|size:%p", m->BaseAddress, m->RegionSize);
							ace_enc::sub_140006B90(newdata, OutputBufferLength);
							memcpy(OutputBuffer, newdata, sizeof(_MEMORY_BASIC_INFORMATION64));
						}
					}

					delete[] newdata;
				}
				delete[]buff;
			}


			return r;
		}

		__int64 __fastcall ATS64InitNtdll(__int64 a1, __int64 a2, __int64 a3)
		{
			//DedbgA("ATS64InitNtdll======= %p", a1);
			auto arr_size_ptr = (DWORD*)(g_ats64_info.base_address + 0x1FCB40);

			if (arr_size_ptr != 0)
			{
				auto hash_arr_size = *arr_size_ptr;
				auto list_arr_ptr = (DWORD*)(g_ats64_info.base_address + 0x1FCB48);

				for (DWORD i = 0; i < hash_arr_size; i++)
				{
					if (0xC391E903 == list_arr_ptr[i * 4])
					{
						DedbgA("识别到哈希碰撞成功 index:%d", i);
						list_arr_ptr[i * 4] = 0xCE91F903;
						break;
					}
				}
			}

			if (a1 == 0x888888888888)
			{
				return a1 - 0x888888888888;
			}
			return 0;
		}



		NTSTATUS
			NTAPI
			DRV64NtDeviceIoControlFile(
				IN  HANDLE FileHandle,
				IN  HANDLE Event,
				IN  PIO_APC_ROUTINE ApcRoutine,
				IN  PVOID ApcContext,
				OUT PIO_STATUS_BLOCK IoStatusBlock,
				IN  ULONG IoControlCode,
				IN  PVOID InputBuffer,
				IN  ULONG InputBufferLength,
				IN  PVOID OutputBuffer,
				IN  ULONG OutputBufferLength
			)
		{



			

			
			if (IoControlCode == 0x221C2C)
			{
				return STATUS_INVALID_HANDLE;
				/*
				DedbgA("调用成功 IoControlCode:%x", IoControlCode);
			
				
				auto newdata = new BYTE[OutputBufferLength];

				memcpy(newdata, OutputBuffer, sizeof(_MEMORY_BASIC_INFORMATION64));

				ace_enc::sub_140006B90(newdata, OutputBufferLength);

				DedbgA("NtDeviceIoControlFile:%llx|%x|%llx", newdata, OutputBufferLength, OutputBuffer);
				MessageBoxA(0, "NtDeviceIoControlFile", 0, 0);
				delete[] newdata;*/
			}

			auto r = base::std_call<NTSTATUS>(real::DRV64NtDeviceIoControlFile, FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);

			return r;
		}



		NTSTATUS
			NTAPI
			CSI64NtDeviceIoControlFile(
				IN  HANDLE FileHandle,
				IN  HANDLE Event,
				IN  PIO_APC_ROUTINE ApcRoutine,
				IN  PVOID ApcContext,
				OUT PIO_STATUS_BLOCK IoStatusBlock,
				IN  ULONG IoControlCode,
				IN  PVOID InputBuffer,
				IN  ULONG InputBufferLength,
				IN  PVOID OutputBuffer,
				IN  ULONG OutputBufferLength
			)
		{



			//return STATUS_INVALID_HANDLE;

			auto r = base::std_call<NTSTATUS>(real::CSI64NtDeviceIoControlFile, FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
			if (NT_SUCCESS(r))
			{
				BYTE* buff = new BYTE[InputBufferLength];
				memcpy(buff, InputBuffer, InputBufferLength);
				int i = 0;
				int src_size = InputBufferLength;
				do
				{
					buff[i] = Utils::Math::__ROL1__(buff[i] ^ src_size, 3);
					++i;
				} while (i < src_size);

				if (*(DWORD*)buff == 0x8000201c && OutputBufferLength == sizeof(_MEMORY_BASIC_INFORMATION64))
				{

					auto newdata = new BYTE[OutputBufferLength];

					memcpy(newdata, OutputBuffer, sizeof(_MEMORY_BASIC_INFORMATION64));

					ace_enc::sub_140006B90(newdata, OutputBufferLength);

					auto m = reinterpret_cast<PMEMORY_BASIC_INFORMATION64>(newdata);

					struct csi_201c //接收结构 _MEMORY_BASIC_INFORMATION64
					{
						uint32_t IoControlCode;
						uint32_t tick;
						uint32_t ThreadId;
						uint32_t a;
						uint32_t b;
						uint32_t c;
						uint32_t pid;
						uint32_t d;
						uint32_t address;
					};

					csi_201c* ptr = (csi_201c*)buff;
					//DedbgW(L"Sguard64: 识别到查询 内存:%x|pid:%d|lol_pid:%d|AllocationBase:%llx", ptr->address, ptr->pid, g_patch_info->pid, m->AllocationBase);
					if (ptr->pid == GetCurrentProcessId())
					{

						for (int i = 0; i < g_DllInfo->module_size; i++)
						{
							bool one = m->AllocationBase >= g_DllInfo->list[i].DllBase && m->AllocationBase < g_DllInfo->list[i].DllBase + g_DllInfo->list[i].DllSize;
							bool two = m->BaseAddress >= g_DllInfo->list[i].DllBase && m->BaseAddress < g_DllInfo->list[i].DllBase + g_DllInfo->list[i].DllSize;
							if (one || two)
							{
								m->AllocationBase = 0;
								m->AllocationProtect = 0;
								m->State = MEM_FREE;
								m->Protect = PAGE_NOACCESS;
								m->Type = 0;

								DedbgA("CSI64 驱动查询内存:%p|size:%p", ptr->address, m->RegionSize);
								ace_enc::sub_140006B90(newdata, OutputBufferLength);
								memcpy(OutputBuffer, newdata, sizeof(_MEMORY_BASIC_INFORMATION64));
								break;
							}
						}


					}

					delete[] newdata;
				}
				delete[]buff;
			}



			return r;
		}

		static HMODULE WINAPI GetModuleHandleA(_In_opt_ LPCSTR lpModuleName)
		{

			auto r = base::std_call<HMODULE>(real::GetModuleHandleA, lpModuleName);
			if (r == reinterpret_cast<HMODULE>(0x140000000))
			{

				MessageBoxA(0, "识别到VMT检测", 0, 0);
			}
			if (dwVMTCrcBase)
			{
				if (r == reinterpret_cast<HMODULE>(0x140000000))
				{
					DedbgA("识别到VMT检测");
					return reinterpret_cast<HMODULE>(dwVMTCrcBase);
				}
			}
			return r;
		}


		BOOL  WINAPI ATS64_ReadProcessMemory(
			_In_ HANDLE hProcess,
			_In_ LPCVOID lpBaseAddress,
			_Out_writes_bytes_to_(nSize, *lpNumberOfBytesRead) LPVOID lpBuffer,
			_In_ SIZE_T nSize,
			_Out_opt_ SIZE_T* lpNumberOfBytesRead
		)
		{
			auto r = base::std_call<BOOL>(real::ATS64ReadProcessMemory, hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);

			auto pid = GetProcessId(hProcess);
			if (hProcess == GetCurrentProcess() || pid == GetCurrentProcessId())
			{
				if (r == TRUE)
				{
					if (g_DllInfo)
					{
						for (int i = 0; i < g_DllInfo->module_size; i++)
						{
							if ((uintptr_t)lpBaseAddress >= g_DllInfo->list[i].DllBase && (uintptr_t)lpBaseAddress < g_DllInfo->list[i].DllBase + (uintptr_t)g_DllInfo->list[i].DllSize)
							{
								//LOG(u8"csi64 ReadMemory %x|%x|%x|%x\r\n", hProcess, lpBaseAddress, lpBuffer, nSize);
								DedbgA("ATS64 rpm 读核心 %p|%p|%p|%p", hProcess, lpBaseAddress, lpBuffer, nSize);
								memset(lpBuffer, 0, nSize);
							}
						}
					}


					if (Utils::is_address_in_module((uintptr_t)lpBaseAddress, g_game_info) && nSize)
					{
						DedbgA("ATS64 rpm 读游戏 %p|%p|%p|%p  offset %p", hProcess, lpBaseAddress, lpBuffer, nSize, (uintptr_t)lpBaseAddress - g_game_info.base_address);

						for (auto hi : Ace_Patch::hooked_list)
						{
							if (hi->addr >= (uintptr_t)lpBaseAddress && hi->addr < (uintptr_t)lpBaseAddress + nSize)
							{
								auto offset = hi->addr - g_game_info.base_address - ((uintptr_t)lpBaseAddress - g_game_info.base_address);
								DedbgA("buffer原字节:%02x", *(unsigned char*)((uintptr_t)lpBuffer + offset));
								memcpy((void*)((uintptr_t)lpBuffer + offset), hi->org_code_buf, hi->code_size);
								DedbgA("buffer新字节:%02x", *(unsigned char*)((uintptr_t)lpBuffer + offset));
								DedbgA("修复 %p | offset %p | org %02x", hi->addr, offset, hi->org_code_buf[0]);
							}
						}
					}

					if (Utils::is_address_in_module((uintptr_t)lpBaseAddress, g_csi64_info) && nSize)
					{
						DedbgA("ATS64 rpm 读csi64 %p|%p|%p|%p  offset %p", hProcess, lpBaseAddress, lpBuffer, nSize, (uintptr_t)lpBaseAddress - g_csi64_info.base_address);

						for (auto hi : Ace_Patch::hooked_list)
						{
							if (hi->addr >= (uintptr_t)lpBaseAddress && hi->addr < (uintptr_t)lpBaseAddress + nSize)
							{
								auto offset = hi->addr - g_csi64_info.base_address - ((uintptr_t)lpBaseAddress - g_csi64_info.base_address);
								DedbgA("buffer原字节:%02x", *(unsigned char*)((uintptr_t)lpBuffer + offset));
								memcpy((void*)((uintptr_t)lpBuffer + offset), hi->org_code_buf, hi->code_size);
								DedbgA("buffer新字节:%02x", *(unsigned char*)((uintptr_t)lpBuffer + offset));
								DedbgA("修复 %p | offset %p | org %02x", hi->addr, offset, hi->org_code_buf[0]);
							}
						}
					}

					if (Utils::is_address_in_module((uintptr_t)lpBaseAddress, g_ats64_info) && nSize)
					{
						DedbgA("ATS64 rpm 读ats64 %p|%p|%p|%p  offset %p", hProcess, lpBaseAddress, lpBuffer, nSize, (uintptr_t)lpBaseAddress - g_ats64_info.base_address);

						for (auto hi : Ace_Patch::hooked_list)
						{
							if (hi->addr >= (uintptr_t)lpBaseAddress && hi->addr < (uintptr_t)lpBaseAddress + nSize)
							{
								auto offset = hi->addr - g_ats64_info.base_address - ((uintptr_t)lpBaseAddress - g_ats64_info.base_address);
								DedbgA("buffer原字节:%02x", *(unsigned char*)((uintptr_t)lpBuffer + offset));
								memcpy((void*)((uintptr_t)lpBuffer + offset), hi->org_code_buf, hi->code_size);
								DedbgA("buffer新字节:%02x", *(unsigned char*)((uintptr_t)lpBuffer + offset));
								DedbgA("修复 %p | offset %p | org %02x", hi->addr, offset, hi->org_code_buf[0]);
							}
						}
					}

					/*if (Utils::is_address_in_module((uintptr_t)lpBaseAddress, g_pbc_game64_info) && nSize)
					{
						DedbgA("ATS64 rpm 读pbc_game64 %p|%p|%p|%p  offset %p", hProcess, lpBaseAddress, lpBuffer, nSize, (uintptr_t)lpBaseAddress - g_pbc_game64_info.base_address);

						for (auto hi : Ace_Patch::hooked_list)
						{
							if (hi->addr >= (uintptr_t)lpBaseAddress && hi->addr < (uintptr_t)lpBaseAddress + nSize)
							{
								auto offset = hi->addr - g_pbc_game64_info.base_address - ((uintptr_t)lpBaseAddress - g_pbc_game64_info.base_address);
								DedbgA("buffer原字节:%02x", *(unsigned char*)((uintptr_t)lpBuffer + offset));
								memcpy((void*)((uintptr_t)lpBuffer + offset), hi->org_code_buf, hi->code_size);
								DedbgA("buffer新字节:%02x", *(unsigned char*)((uintptr_t)lpBuffer + offset));
								DedbgA("修复 %p | offset %p | org %02x", hi->addr, offset, hi->org_code_buf[0]);
							}
						}
					}*/
				}
			}

			return r;
		}


		BOOL  WINAPI CSI64_ReadProcessMemory(
			_In_ HANDLE hProcess,
			_In_ LPCVOID lpBaseAddress,
			_Out_writes_bytes_to_(nSize, *lpNumberOfBytesRead) LPVOID lpBuffer,
			_In_ SIZE_T nSize,
			_Out_opt_ SIZE_T* lpNumberOfBytesRead
		)
		{
			auto r = base::std_call<BOOL>(real::CSI64ReadProcessMemory, hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
			
			auto pid = GetProcessId(hProcess);
			if (hProcess == GetCurrentProcess() || pid == GetCurrentProcessId())
			{
				if (r == TRUE)
				{
					if (g_DllInfo)
					{
						for (int i = 0; i < g_DllInfo->module_size; i++)
						{
							if ((uintptr_t)lpBaseAddress >= g_DllInfo->list[i].DllBase && (uintptr_t)lpBaseAddress < g_DllInfo->list[i].DllBase + (uintptr_t)g_DllInfo->list[i].DllSize)
							{
								//LOG(u8"csi64 ReadMemory %x|%x|%x|%x\r\n", hProcess, lpBaseAddress, lpBuffer, nSize);
								DedbgA("CSI64 rpm 读核心 %p|%p|%p|%p", hProcess, lpBaseAddress, lpBuffer, nSize);
								memset(lpBuffer, 0, nSize);
							}
						}
					}
				
				
					if (Utils::is_address_in_module((uintptr_t)lpBaseAddress, g_game_info) && nSize)
					{
						DedbgA("CSI64 rpm 读游戏 %p|%p|%p|%p  offset %p", hProcess, lpBaseAddress, lpBuffer, nSize, (uintptr_t)lpBaseAddress - g_game_info.base_address);
						
						for (auto hi : Ace_Patch::hooked_list)
						{
							if (hi->addr >= (uintptr_t)lpBaseAddress && hi->addr < (uintptr_t)lpBaseAddress + nSize)
							{
								auto offset = hi->addr - g_game_info.base_address - ((uintptr_t)lpBaseAddress - g_game_info.base_address);
								DedbgA("buffer原字节:%02x", *(unsigned char*)((uintptr_t)lpBuffer + offset));
								memcpy((void*)((uintptr_t)lpBuffer + offset), hi->org_code_buf, hi->code_size);
								DedbgA("buffer新字节:%02x", *(unsigned char*)((uintptr_t)lpBuffer + offset));
								DedbgA("修复 %p | offset %p | org %02x", hi->addr, offset, hi->org_code_buf[0]);
							}
						}
					}

					if (Utils::is_address_in_module((uintptr_t)lpBaseAddress, g_csi64_info) && nSize)
					{
						DedbgA("CSI64 rpm 读csi64 %p|%p|%p|%p  offset %p", hProcess, lpBaseAddress, lpBuffer, nSize, (uintptr_t)lpBaseAddress - g_csi64_info.base_address);
						
						for (auto hi : Ace_Patch::hooked_list)
						{
							if (hi->addr >= (uintptr_t)lpBaseAddress && hi->addr < (uintptr_t)lpBaseAddress + nSize)
							{
								auto offset = hi->addr - g_csi64_info.base_address - ((uintptr_t)lpBaseAddress - g_csi64_info.base_address);
								DedbgA("buffer原字节:%02x", *(unsigned char*)((uintptr_t)lpBuffer + offset));
								memcpy((void*)((uintptr_t)lpBuffer + offset), hi->org_code_buf, hi->code_size);
								DedbgA("buffer新字节:%02x", *(unsigned char*)((uintptr_t)lpBuffer + offset));
								DedbgA("修复 %p | offset %p | org %02x", hi->addr, offset, hi->org_code_buf[0]);
							}
						}
					}

					if (Utils::is_address_in_module((uintptr_t)lpBaseAddress, g_ats64_info) && nSize)
					{
						DedbgA("CSI64 rpm 读ats64 %p|%p|%p|%p  offset %p", hProcess, lpBaseAddress, lpBuffer, nSize, (uintptr_t)lpBaseAddress - g_ats64_info.base_address);
						
						for (auto hi : Ace_Patch::hooked_list)
						{
							if (hi->addr >= (uintptr_t)lpBaseAddress && hi->addr < (uintptr_t)lpBaseAddress + nSize)
							{
								auto offset = hi->addr - g_ats64_info.base_address - ((uintptr_t)lpBaseAddress - g_ats64_info.base_address);
								DedbgA("buffer原字节:%02x", *(unsigned char*)((uintptr_t)lpBuffer + offset));
								memcpy((void*)((uintptr_t)lpBuffer + offset), hi->org_code_buf, hi->code_size);
								DedbgA("buffer新字节:%02x", *(unsigned char*)((uintptr_t)lpBuffer + offset));
								DedbgA("修复 %p | offset %p | org %02x", hi->addr, offset, hi->org_code_buf[0]);
							}
						}
					}

					/*if (Utils::is_address_in_module((uintptr_t)lpBaseAddress, g_pbc_game64_info) && nSize)
					{
						DedbgA("CSI64 rpm 读pbc_game64 %p|%p|%p|%p  offset %p", hProcess, lpBaseAddress, lpBuffer, nSize, (uintptr_t)lpBaseAddress - g_pbc_game64_info.base_address);
						
						for (auto hi : Ace_Patch::hooked_list)
						{
							if (hi->addr >= (uintptr_t)lpBaseAddress && hi->addr < (uintptr_t)lpBaseAddress + nSize)
							{
								auto offset = hi->addr - g_pbc_game64_info.base_address - ((uintptr_t)lpBaseAddress - g_pbc_game64_info.base_address);
								DedbgA("buffer原字节:%02x", *(unsigned char*)((uintptr_t)lpBuffer + offset));
								memcpy((void*)((uintptr_t)lpBuffer + offset), hi->org_code_buf, hi->code_size);
								DedbgA("buffer新字节:%02x", *(unsigned char*)((uintptr_t)lpBuffer + offset));
								DedbgA("修复 %p | offset %p | org %02x", hi->addr, offset, hi->org_code_buf[0]);
							}
						}
					}*/
				}
			}

			return r;

		}



		SIZE_T WINAPI VirtualQueryEx(
			_In_ HANDLE hProcess,
			_In_opt_ LPCVOID lpAddress,
			_Out_writes_bytes_to_(dwLength, return) PMEMORY_BASIC_INFORMATION lpBuffer,
			_In_ SIZE_T dwLength
		) {

			SIZE_T v_ret_val = base::std_call<SIZE_T>(real::CSI64VirtualQueryEx, hProcess, lpAddress, lpBuffer, dwLength);
			if (hProcess == GetCurrentProcess() && g_game_info.base_address > 0)
			{
				if (g_DllInfo)
				{
					for (int i = 0; i < g_DllInfo->module_size; i++)
					{
						if ((uintptr_t)lpAddress >= g_DllInfo->list[i].DllBase && (uintptr_t)lpAddress < g_DllInfo->list[i].DllBase + (uintptr_t)g_DllInfo->list[i].DllSize)
						{

							//LOG(u8"csi64 memmove_0 %x|%x|%x", Dst, Src, MaxCount);
							//DedbgA("CSI64 memmove_0 %p|%p|%p", Dst, Src, MaxCount);
							DedbgA("CSI64 VirtualQueryEx 识别到查询核心内存:%p|%p|%p|%p", lpBuffer->AllocationBase, lpBuffer->BaseAddress, lpBuffer->RegionSize, lpBuffer->State);
							lpBuffer->Protect = PAGE_NOACCESS;
						}
					}
				}
			}


			return  v_ret_val;
		}

		SIZE_T WINAPI VirtualQuery(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength)
		{
			SIZE_T v_ret_val = base::std_call<SIZE_T>(real::CSI64VirtualQuery, lpAddress, lpBuffer, dwLength);
			if (g_DllInfo)
			{
				for (int i = 0; i < g_DllInfo->module_size; i++)
				{
					if ((uintptr_t)lpAddress >= g_DllInfo->list[i].DllBase && (uintptr_t)lpAddress < g_DllInfo->list[i].DllBase + (uintptr_t)g_DllInfo->list[i].DllSize)
					{

						//LOG(u8"csi64 memmove_0 %x|%x|%x", Dst, Src, MaxCount);
						//DedbgA("CSI64 memmove_0 %p|%p|%p", Dst, Src, MaxCount);
						DedbgA("CSI64 VirtualQuery 识别到查询核心内存:%p|%p|%p|%p", lpBuffer->AllocationBase, lpBuffer->BaseAddress, lpBuffer->RegionSize, lpBuffer->State);
						lpBuffer->Protect = PAGE_NOACCESS;
					}
				}
			}
			return  v_ret_val;
		}


		NTSTATUS
			NTAPI
			NtQueryVirtualMemory(
				IN HANDLE ProcessHandle,
				IN PVOID BaseAddress,
				IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
				OUT PVOID MemoryInformation,
				IN SIZE_T MemoryInformationLength,
				OUT PSIZE_T ReturnLength OPTIONAL
			)
		{
			auto r = base::std_call<NTSTATUS>(real::CSI64NtQueryVirtualMemory, ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);
			if (NT_SUCCESS(r))
			{
				auto pid = GetProcessId(ProcessHandle);
				if (ProcessHandle == GetCurrentProcess() || pid == GetCurrentProcessId())
				{
					auto m = reinterpret_cast<PMEMORY_BASIC_INFORMATION64>(MemoryInformation);

					for (int i = 0; i < g_DllInfo->module_size; i++)
					{
						bool one = m->AllocationBase >= g_DllInfo->list[i].DllBase && m->AllocationBase < g_DllInfo->list[i].DllBase + g_DllInfo->list[i].DllSize;
						bool two = m->BaseAddress >= g_DllInfo->list[i].DllBase && m->BaseAddress < g_DllInfo->list[i].DllBase + g_DllInfo->list[i].DllSize;
						if (one || two)
						{
							DedbgA("CSI64 NtQueryVirtualMemory查询核心内存：%p| 原属性 %p", m->AllocationBase, m->Protect);
							m->AllocationBase = 0;
							m->AllocationProtect = 0;
							m->State = MEM_FREE;
							m->Protect = PAGE_NOACCESS;
							m->Type = 0;
							break;
						}
					}
				}
			}

			return r;

		}

	}

	namespace hooks
	{
		std::vector<uintptr_t> hooked_address;

		static void* __cdecl memmove_0(void* Dst, const void* Src, size_t MaxCount)
		{
			if (g_DllInfo)
			{
				for (int i = 0; i < g_DllInfo->module_size; i++)
				{
					if ((uintptr_t)Src >= g_DllInfo->list[i].DllBase && (uintptr_t)Src <= g_DllInfo->list[i].DllBase + (uintptr_t)g_DllInfo->list[i].DllSize)
					{
						DedbgA("CSI64 memmove_0 读核心 %p|%p|%p", Dst, Src, MaxCount);
						return 0;
					}
				}
			}


			if (Utils::is_address_in_module((uintptr_t)Src, g_game_info) && MaxCount)
			{
				DedbgA("CSI64 memmove_0 读游戏 %p|%p|%p", Dst, Src, MaxCount);
				CopyFixedHookedList(g_game_info, Dst, MaxCount, (uintptr_t)Src - g_game_info.base_address);
				return 0;
			}

			if (Utils::is_address_in_module((uintptr_t)Src, g_csi64_info) && MaxCount)
			{
				DedbgA("CSI64 memmove_0 读csi64 %p|%p|%p", Dst, Src, MaxCount);
				CopyFixedHookedList(g_csi64_info, Dst, MaxCount, (uintptr_t)Src - g_csi64_info.base_address);
				return 0;
			}

			if (Utils::is_address_in_module((uintptr_t)Src, g_ats64_info) && MaxCount)
			{
				DedbgA("CSI64 memmove_0 读ats64 %p|%p|%p", Dst, Src, MaxCount);
				CopyFixedHookedList(g_ats64_info, Dst, MaxCount, (uintptr_t)Src - g_ats64_info.base_address);
				return 0;
			}

			/*	if (Utils::is_address_in_module((uintptr_t)Src, g_pbc_game64_info) && MaxCount)
				{
					DedbgA("CSI64 memmove_0 读pbc-game64 %p|%p|%p", Dst, Src, MaxCount);
					CopyFixedHookedList(g_pbc_game64_info, Dst, MaxCount, (uintptr_t)Src - g_pbc_game64_info.base_address);
					return 0;
				}*/

				/*if (dwVMTCrcBase)
				{
					if ((uintptr_t)Src == g_game_info.base_address && MaxCount == 0x1E00000)
					{
						DedbgA("CSI64 memmove_0 读游戏 %p|%p|%p", Dst, Src, MaxCount);
						memcpy(Dst, (void*)dwVMTCrcBase, MaxCount);
						return 0;
					}
				}

				if (dwVMTCsi64Base)
				{
					if ((uintptr_t)Src == g_csi64_info.base_address && MaxCount == g_csi64_info.module_size)
					{
						DedbgA("CSI64 memmove_0 读csi64 %p|%p|%p", Dst, Src, MaxCount);
						memcpy(Dst, (void*)dwVMTCsi64Base, MaxCount);
						return 0;
					}
				}

				if (dwVMTAts64Base)
				{
					if ((uintptr_t)Src == g_ats64_info.base_address && MaxCount == g_ats64_info.module_size)
					{
						DedbgA("CSI64 memmove_0 读ats64 %p|%p|%p", Dst, Src, MaxCount);
						memcpy(Dst, (void*)dwVMTAts64Base, MaxCount);
						return 0;
					}
				}*/


				/*if (Utils::is_address_in_module((uintptr_t)Src, g_csi64_info) && MaxCount)
				{
					DedbgA("CSI64 memmove_0 读csi64 %p|%p|%p", Dst, Src, MaxCount);
					return 0;
				}

				if (Utils::is_address_in_module((uintptr_t)Src, g_ats64_info) && MaxCount)
				{
					DedbgA("CSI64 memmove_0 读ats64 %p|%p|%p", Dst, Src, MaxCount);
					return 0;
				}*/

			return base::c_call<void*>(real::Csi64MemmoveProc, Dst, Src, MaxCount);
		}

		//static  HMODULE WINAPI LoadLibraryExW(_In_ LPCWSTR lpLibFileName, _Reserved_ HANDLE hFile, _In_ DWORD dwFlags)
		//{
		//	auto v_ret_val = base::std_call<HMODULE>(real::LoadLibraryExW, lpLibFileName, hFile, dwFlags);
		//	
		//	if (v_ret_val)
		//	{
		//		if (v_ret_val == GetModuleHandleW(L"ACE-DRV64.dll") && g_drv64_info.base_address == 0)
		//		{
		//			g_drv64_info = Utils::get_module_info(v_ret_val);
		//			if (umc::send_request(umc::code_acebypass_patch, 0, 0))
		//			{
		//				DedbgA("patch on------------");
		//			}
		//		}
		//		if (v_ret_val == GetModuleHandleW(L"ACE-Base64.dll") && g_base64_info.base_address == 0)
		//		{
		//			g_game_info = Utils::get_module_info(GetModuleHandle(nullptr));
		//			g_base64_info = Utils::get_module_info(v_ret_val);

		//		}

		//		if (v_ret_val == GetModuleHandleW(L"ACE-Pbc-Game64.dll") && g_pbc_game64_info.base_address == 0)
		//		{
		//			g_pbc_game64_info = Utils::get_module_info(v_ret_val);

		//			uintptr_t GetModuleHandleAPtr = g_pbc_game64_info.base_address + 0xC6018;
		//			real::GetModuleHandleA = (uintptr_t)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetModuleHandleA");
		//			if (!Utils::Memory::WPM<uintptr_t>(GetModuleHandleAPtr, reinterpret_cast<uintptr_t>(vmt_hook::GetModuleHandleA)))
		//			{
		//				MessageBoxA(0, "error init0", 0, 0);
		//				exit(0);
		//			}
		//		}

		//		if (v_ret_val == GetModuleHandleW(L"ACE-ATS64.dll") && g_ats64_info.base_address == 0)
		//		{
		//			g_ats64_info = Utils::get_module_info(v_ret_val);
		//			auto* v_mod_nedll_base = GetModuleHandleW(L"ntdll.dll");
		//			real::ATS64NtDeviceIoControlFile = reinterpret_cast<uintptr_t>(GetProcAddress(v_mod_nedll_base, "NtDeviceIoControlFile"));
		//			uintptr_t NtDeviceIoControlFilePtr = g_ats64_info.base_address + 0x1FB940;
		//			//Utils::Memory::WPM<uintptr_t>(NtDeviceIoControlFilePtr, reinterpret_cast<uintptr_t>(vmt_hook::ATS64NtDeviceIoControlFile));
		//			*(uint64_t*)NtDeviceIoControlFilePtr = reinterpret_cast<uintptr_t>(vmt_hook::ATS64NtDeviceIoControlFile);

		//			if (umc::unlock_protect(GetCurrentProcessId(), g_ats64_info.base_address + 0x1445F0 + 0x20))
		//			{			
		//				if (Utils::Memory::WPM<uintptr_t>(g_ats64_info.base_address + 0x1445F0 + 0x20, reinterpret_cast<uintptr_t>(vmt_hook::ATS64InitNtdll)))
		//				{
		//					DedbgA("ats64 强写成功");
		//				}
		//				else
		//				{
		//					MessageBoxA(0, "error init1", 0, 0);
		//					exit(0);
		//				}
		//				
		//			}
		//			else
		//			{
		//				MessageBoxA(0, "error init2", 0, 0);
		//				exit(0);
		//			}
		//			
		//			//*(uint64_t*)(g_ats64_info.base_address + 0x1445F0 + 0x20) = tmp;
		//			//*(uint8_t*)(g_ats64_info.base_address + 0x1FC9AC) = 0;
		//		}
		//		if (v_ret_val == GetModuleHandleW(L"ACE-CSI64.dll") && g_csi64_info.base_address == 0)
		//		{
		//			g_csi64_info = Utils::get_module_info(v_ret_val);

		//			auto* v_mod_nedll_base = GetModuleHandleW(L"ntdll.dll");
		//			real::CSI64NtDeviceIoControlFile = reinterpret_cast<uintptr_t>(GetProcAddress(v_mod_nedll_base, "NtDeviceIoControlFile"));

		//			uintptr_t NtDeviceIoControlFilePtr = g_csi64_info.base_address + 0x714370;
		//			if (!Utils::Memory::WPM<uintptr_t>(NtDeviceIoControlFilePtr, reinterpret_cast<uintptr_t>(vmt_hook::CSI64NtDeviceIoControlFile)))
		//			{
		//				MessageBoxA(0, "error init3", 0, 0);
		//				exit(0);
		//			}

		//			uintptr_t ReadProcessMemoryPtr = g_csi64_info.base_address + 0x4E0160;
		//			real::CSI64ReadProcessMemory = (uintptr_t)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "ReadProcessMemory");
		//			if (!Utils::Memory::WPM<uintptr_t>(ReadProcessMemoryPtr, reinterpret_cast<uintptr_t>(vmt_hook::ReadProcessMemory)))
		//			{
		//				MessageBoxA(0, "error init4", 0, 0);
		//				exit(0);
		//			}

		//			////"ACE-CSI64.dll" + 4E0950
		//			//uintptr_t NtQueryVirtualMemoryPtr = g_csi64_info.base_address + 0x4E0950;
		//			//real::CSI64NtQueryVirtualMemory = (uintptr_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryVirtualMemory");
		//			//Utils::Memory::WPM<uintptr_t>(NtQueryVirtualMemoryPtr, reinterpret_cast<uintptr_t>(vmt_hook::NtQueryVirtualMemory));

		//			real::Csi64MemmoveProc = g_csi64_info.base_address + 0x19B410;
		//			if (0 != real::Csi64MemmoveProc)
		//			{					
		//				base::hook::install(&real::Csi64MemmoveProc, reinterpret_cast<uintptr_t>(memmove_0));
		//			}

		//		}
		//		if (g_base64_info.base_address != 0 && g_pbc_game64_info.base_address != 0 && g_ats64_info.base_address != 0 && g_csi64_info.base_address != 0 && g_drv64_info.base_address != 0)
		//		{				
		//			base::hook::uninstall(&hook_t::LoadLibraryExW);
		//		}
		//	}

		//	return v_ret_val;
		//}



		static SIZE_T WINAPI VirtualQueryEx(
			_In_ HANDLE hProcess,
			_In_opt_ LPCVOID lpAddress,
			_Out_writes_bytes_to_(dwLength, return) PMEMORY_BASIC_INFORMATION lpBuffer,
			_In_ SIZE_T dwLength
		) {

			SIZE_T v_ret_val = base::std_call<SIZE_T>(real::VirtualQueryEx, hProcess, lpAddress, lpBuffer, dwLength);
			if (hProcess == GetCurrentProcess() && g_game_info.base_address > 0)
			{
				if (is_address_in_module((uintptr_t)lpAddress, g_game_info))
				{
					//DedbgA("ATS64 VirtualQueryEx 识别到查询游戏内存:%p|%p|%p|%p", lpBuffer->AllocationBase, lpBuffer->BaseAddress, lpBuffer->RegionSize, lpBuffer->State);
					lpBuffer->AllocationBase = 0;
					lpBuffer->AllocationProtect = 0;
					lpBuffer->State = MEM_FREE;
					lpBuffer->Protect = PAGE_NOACCESS;
					lpBuffer->Type = 0;
				}
				if (is_address_in_module((uintptr_t)lpAddress, g_csi64_info))
				{
					//DedbgA("ATS64 VirtualQueryEx 识别到查询CSI64内存:%p|%p|%p|%p", lpBuffer->AllocationBase, lpBuffer->BaseAddress, lpBuffer->RegionSize, lpBuffer->State);
					lpBuffer->AllocationBase = 0;
					lpBuffer->AllocationProtect = 0;
					lpBuffer->State = MEM_FREE;
					lpBuffer->Protect = PAGE_NOACCESS;
					lpBuffer->Type = 0;
				}
				if (is_address_in_module((uintptr_t)lpAddress, g_ats64_info))
				{
					// DedbgA("ATS64 VirtualQueryEx 识别到查询CSI64内存:%p|%p|%p|%p", lpBuffer->AllocationBase, lpBuffer->BaseAddress, lpBuffer->RegionSize, lpBuffer->State);
					lpBuffer->AllocationBase = 0;
					lpBuffer->AllocationProtect = 0;
					lpBuffer->State = MEM_FREE;
					lpBuffer->Protect = PAGE_NOACCESS;
					lpBuffer->Type = 0;
				}
			}

			//auto v_address = (uintptr_t)_ReturnAddress();
			//SIZE_T v_ret_val = base::std_call<SIZE_T>(real::VirtualQueryEx, hProcess, lpAddress, lpBuffer, dwLength);
			//if (hProcess == GetCurrentProcess() && g_game_info.base_address > 0)
			//{
			//	if (g_ats64_info.base_address > 0)
			//	{
			//		if (is_address_in_module(v_address, g_ats64_info))
			//		{
			//			if (is_address_in_module((uintptr_t)lpAddress, g_game_info))
			//			{
			//				//DedbgA("VirtualQueryEx 识别到查询游戏内存:%p|%p|%p|%p", lpBuffer->AllocationBase, lpBuffer->BaseAddress, lpBuffer->RegionSize, lpBuffer->State);
			//				lpBuffer->Protect = PAGE_NOACCESS;

			//			}
			//			if (is_address_in_module((uintptr_t)lpAddress, g_csi64_info))
			//			{
			//				//DedbgA("VirtualQueryEx 识别到查询CSI32内存:%p|%p|%p|%p", lpBuffer->AllocationBase, lpBuffer->BaseAddress, lpBuffer->RegionSize, lpBuffer->State);
			//				lpBuffer->Protect = PAGE_NOACCESS;
			//			}
			//		}
			//	}
			//}


			return  v_ret_val;
		}

		void GetLastError(AceHookContext* Context)
		{
			PTEB teb = NtCurrentTeb();
			if (teb->LastErrorValue == 5 && *(BYTE*)(Context->rsp + 0x1f8) == 0x65)
			{
				teb->LastErrorValue = 0x420;
				*(BYTE*)(Context->rsp + 0x1f8) = 0x67;
			}

		}



		typedef HANDLE(WINAPI* fnCreateThread)(
			_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
			_In_ SIZE_T dwStackSize,
			_In_ LPTHREAD_START_ROUTINE lpStartAddress,
			_In_opt_ __drv_aliasesMem LPVOID lpParameter,
			_In_ DWORD dwCreationFlags,
			_Out_opt_ LPDWORD lpThreadId
			);


		HANDLE
			WINAPI
			HookCreateThread(
				_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
				_In_ SIZE_T dwStackSize,
				_In_ LPTHREAD_START_ROUTINE lpStartAddress,
				_In_opt_ __drv_aliasesMem LPVOID lpParameter,
				_In_ DWORD dwCreationFlags,
				_Out_opt_ LPDWORD lpThreadId
			)
		{


			uintptr_t _ret_address = (uintptr_t)_ReturnAddress();
			if (Utils::is_address_in_module(_ret_address, g_bot_info))
			{




				uintptr_t address = ntdll_memory;
				uintptr_t FakeThreadAddress = address;
				BYTE shell_code[] = { 0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
				//MessageBoxA(0, 0, 0, 0);
				memcpy((LPVOID)FakeThreadAddress, shell_code, sizeof(shell_code));
				*(uintptr_t*)(FakeThreadAddress + 0x2) = (uintptr_t)lpParameter;

				auto JmpAddr = FakeThreadAddress + sizeof(shell_code);
				*(uint32_t*)JmpAddr = 0x25FF;
				*(uint16_t*)(JmpAddr + 4) = 0;
				*(uintptr_t*)(JmpAddr + 6) = (uintptr_t)lpStartAddress;

				lpStartAddress = (LPTHREAD_START_ROUTINE)FakeThreadAddress;
				lpParameter = 0;

				ntdll_memory += 40;


			}

			fnCreateThread pfnCreateThread = (fnCreateThread)real::CreateThread;

			return pfnCreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);


		}


		typedef LPVOID(WINAPI* fnVirtualAlloc)(
			_In_opt_ LPVOID lpAddress,
			_In_ SIZE_T dwSize,
			_In_ DWORD flAllocationType,
			_In_ DWORD flProtect
			);




		typedef ULONG(NTAPI* fnRtlNtStatusToDosError)(NTSTATUS Status);

		fnRtlNtStatusToDosError pfnRtlNtStatusToDosError = nullptr;

		typedef VOID(NTAPI* fnRtlSetLastWin32Error)(ULONG WinError);

		fnRtlSetLastWin32Error pfnRtlSetLastWin32Error = nullptr;

		int64_t __fastcall BaseSetLastNTError(NTSTATUS a1)
		{
			ULONG v1; // ebx
			if (pfnRtlNtStatusToDosError == nullptr)
			{
				pfnRtlNtStatusToDosError = reinterpret_cast<fnRtlNtStatusToDosError>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlNtStatusToDosError"));
			}

			if (pfnRtlSetLastWin32Error == nullptr)
			{
				pfnRtlSetLastWin32Error = reinterpret_cast<fnRtlSetLastWin32Error>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlSetLastWin32Error"));
			}

			v1 = pfnRtlNtStatusToDosError(a1);
			pfnRtlSetLastWin32Error(v1);
			return v1;
		}

		LPVOID __stdcall MyVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
		{
			NTSTATUS v4;          // eax
			PVOID BaseAddress;    // [rsp+40h] [rbp+8h] BYREF
			ULONG_PTR RegionSize; // [rsp+48h] [rbp+10h] BYREF

			RegionSize = dwSize;
			BaseAddress = lpAddress;
			if (lpAddress && (unsigned __int64)lpAddress < (unsigned int)65536)
			{

				if (pfnRtlSetLastWin32Error == nullptr)
				{
					pfnRtlSetLastWin32Error = reinterpret_cast<fnRtlSetLastWin32Error>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlSetLastWin32Error"));
				}
				pfnRtlSetLastWin32Error(0x57u);
			}
			else
			{



				v4 = NtAllocateVirtualMemory(
					(HANDLE)0xFFFFFFFFFFFFFFFFi64,
					&BaseAddress,
					0i64,
					&RegionSize,
					flAllocationType & 0xFFFFFFC0,
					flProtect);
				if (v4 >= 0)
					return BaseAddress;
				BaseSetLastNTError((unsigned int)v4);
			}
			return 0i64;
		}





		LPVOID WINAPI HookVirtualAlloc(
			_In_opt_ LPVOID lpAddress,
			_In_ SIZE_T dwSize,
			_In_ DWORD flAllocationType,
			_In_ DWORD flProtect
		)
		{
			uintptr_t _ret_address = (uintptr_t)_ReturnAddress();
			if (Utils::is_address_in_module(_ret_address, g_bot_info))
			{
				auto t = MyVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
				if (t)
				{
					Ace_Patch::AddModuleInfo({ (uintptr_t)t, dwSize });
				}

				return t;
			}


			fnVirtualAlloc pfnVirtualAlloc = (fnVirtualAlloc)(real::VirtualAlloc);
			return pfnVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);

		}

		NTSTATUS
			NTAPI
			HookNtAllocateVirtualMemory(
				IN HANDLE ProcessHandle,
				IN OUT PVOID* BaseAddress,
				IN ULONG ZeroBits,
				IN OUT PSIZE_T RegionSize,
				IN ULONG AllocationType,
				IN ULONG Protect
			)
		{
			uintptr_t _ret_address = (uintptr_t)_ReturnAddress();
			if (Utils::is_address_in_module(_ret_address, g_bot_info))
			{
				auto t = base::std_call<NTSTATUS>(real::NtAllocateVirtualMemory, ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
				if (NT_SUCCESS(t))
				{
					DedbgA("保护nt内存 %p|%p", (uintptr_t)*BaseAddress, *RegionSize);
					Ace_Patch::AddModuleInfo({ (uintptr_t)*BaseAddress, *RegionSize });
				}

				return t;
			}

			return base::std_call<NTSTATUS>(real::NtAllocateVirtualMemory, ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
		}
	}


	typedef LRESULT(__fastcall* evtPbcGame64WndProc)(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
	IssueOrderType last_order;

	bool AceMouseMessage(const Vector3& position, IssueOrderType order)
	{
		//#define USELIMITATION
				/*
				 * 限制频率
				 */
#ifdef USELIMITATION 
		if ((last_order == IssueOrderType::AttackUnit && order == IssueOrderType::AttackUnit))
		{
			auto CurrentTick = g_Common->TickCount() - LastMoveTick;
			if (CurrentTick < 250.f)
			{
				return  false;
			}
		}

		else if ((order == IssueOrderType::MoveTo) || (last_order != IssueOrderType::AttackUnit && order == IssueOrderType::AttackUnit))
		{
			auto CurrentTick = g_Common->TickCount() - LastMoveTick;
			if (CurrentTick < 120.f)
			{
				return  false;
			}
		}

		LastMoveTick = g_Common->TickCount();
		last_order = order;
#endif

		//#define USERMSG

				/*
				 * 使用WndProc消息
				 */

		Vector2 out_pos = position.WorldToScreen();
#ifdef USERMSG
		auto pevtPbcGame64WndProc = reinterpret_cast<evtPbcGame64WndProc>(g_pbc_game64_info.base_address + static_cast<uintptr_t>(OFFSET_PBC64::evtPbcGame64WndProc));

		static HWND game_hwnd = nullptr;
		if (game_hwnd == nullptr)
		{
			game_hwnd = FindWindowA(0, "League of Legends (TM) Client");
		}
		pevtPbcGame64WndProc(game_hwnd, WM_RBUTTONDOWN, static_cast<WPARAM>(2), MAKELPARAM(static_cast<int>(out_pos.x), static_cast<int>(out_pos.y)));
#endif

		typedef uintptr_t(__fastcall* evtMoveCallRpcs)(uintptr_t state, uintptr_t x, uintptr_t y);
		const auto pevtMoveCallRpcs = reinterpret_cast<evtMoveCallRpcs>(g_pbc_game64_info.base_address + static_cast<uintptr_t>(OFFSET_PBC64::evtMoveCallRpcs));


		typedef bool(__fastcall* evtIsInitData)(uintptr_t ptr, uintptr_t index);

		evtIsInitData pevtIsInitData = (evtIsInitData)(g_pbc_game64_info.base_address + 0x53460);
		if (pevtIsInitData(g_pbc_game64_info.base_address + 0x11ED60, 9))
		{
			pevtMoveCallRpcs(0, (int)out_pos.x, (int)out_pos.y);
			//pevtMoveCallRpcs(1, 0xffffffff, 0xffffffff);
		}
			
		return true;

	}



	bool AceKeyMessage(int Slot)
	{

		typedef uintptr_t(__fastcall* evtCastSpellCallRpcs)(float tick2, uintptr_t slot, uintptr_t mode, uintptr_t state);
		evtCastSpellCallRpcs pevtCastSpellCallRpcs = (evtCastSpellCallRpcs)(g_pbc_game64_info.base_address + static_cast<uintptr_t>(OFFSET_PBC64::evtCastSpellCallRpcs));


		std::random_device rd;
		std::mt19937 gen(rd());
		std::uniform_real_distribution<float> dis(0.1f, 0.12f);
		float sleep_tick = dis(gen);

		static HWND game_hwnd = 0;
		if (game_hwnd == nullptr)
		{
			game_hwnd = FindWindowA(nullptr, "League of Legends (TM) Client");
		}


		//auto pevtPbcGame64WndProc = reinterpret_cast<evtPbcGame64WndProc>(g_pbc_game64_info.base_address + static_cast<uintptr_t>(OFFSET_PBC64::evtPbcGame64WndProc));
		//Imsg_info msg_info_ax(0, Slot);
		//pevtPbcGame64WndProc(game_hwnd, msg_info_ax.u_msg, msg_info_ax.w_param, msg_info_ax.l_param);

		//Utils::Out::Dedbg_ExA("按下: %d", Slot);
		float tick2 = Common::GetInstance()->Time2();
		pevtCastSpellCallRpcs(tick2, Slot, 2, 0);

		Common::GetInstance()->DelayAction(sleep_tick * 1000, [=]()
			{
				//Utils::Out::Dedbg_ExA("抬起: %d", Slot);
				//Imsg_info msg_info_ax(1, Slot);
				//pevtPbcGame64WndProc(game_hwnd, msg_info_ax.u_msg, msg_info_ax.w_param, msg_info_ax.l_param);
				float tmp_tick2 = Common::GetInstance()->Time2();
				pevtCastSpellCallRpcs(tmp_tick2, Slot, 2, 1);
			});

		return  true;


	}


	float CastSpellTick[14] = { 0 };
	spell_info CastSpellInfo[14] = { 0 };

	struct key_info
	{
		std::string evt_name;
		UINT v_key;
	};

	std::unordered_map<int, key_info> evt_map;
	//DWORD mapSpellV4[] = { 0x51, 0x57, 0x45, 0x52, 0x44, 0x46, 0x31, 0x32, 0x33, 0x35, 0x36, 0x37, 0x34, 0x42 };

	bool IsChargingSpell(DWORD SlotID)
	{
		auto me = Common::GetInstance()->GetLocalPlayer()->mBaseCharacterData->SkinHash;
		if (me == Character::Galio && SlotID == 1)
		{
			return true;
		}

		if (me == Character::Irelia && SlotID == 1)
		{
			return true;
		}

		if (me == Character::Pantheon && SlotID == 0)
		{
			return true;
		}

		if (me == Character::Poppy && SlotID == 3)
		{
			return true;
		}

		if (me == Character::Pyke && SlotID == 0)
		{
			return true;
		}

		if (me == Character::Sion && SlotID == 0)
		{
			return true;
		}

		if (me == Character::Varus && SlotID == 0)
		{
			return true;
		}

		if (me == Character::Vi && SlotID == 0)
		{
			return true;
		}

		if (me == Character::Vladimir && SlotID == 2)
		{
			return true;
		}

		if (me == Character::Xerath && SlotID == 0)
		{
			return true;
		}

		if (me == Character::Zac && SlotID == 2)
		{
			return true;
		}

		if (me == Character::Zac && SlotID == 3)
		{
			return true;
		}

		if (me == Character::KSante && SlotID == 1)
		{
			return true;
		}

		return false;
	}

	bool IsLineSpell(DWORD SlotID)
	{
		auto me = Common::GetInstance()->GetLocalPlayer()->mBaseCharacterData->SkinHash;
		if (me == Character::Viktor && SlotID == 2)
		{
			return true;
		}

		if (me == Character::Rumble && SlotID == 3)
		{
			return true;
		}

		return false;
	}	

	bool is_init_spell;

	bool AceHudCastSpell(int slot, TargetingClientData* ClientData)
	{

		if (!is_init_spell)
		{
			DedbgA("is_init_spell faile");
			return false;
		}

		if (Ace_Patch::CastSpellInfo[(int)slot].is_down)
		{
			return false;
		}

		static HWND game_hwnd = 0;
		if (game_hwnd == nullptr)
		{
			game_hwnd = FindWindowA(0, "League of Legends (TM) Client");
		}

		if (game_hwnd == 0 || game_hwnd != ::GetForegroundWindow())
		{
			return false;
		}

		std::random_device rd;
		std::mt19937 gen(rd());
		std::uniform_real_distribution<float> dis(0.07f, 0.12f);
		float sleep_tick = dis(gen);

		Ace_Patch::CastSpellInfo[(int)slot].slot = (int)slot;
		Ace_Patch::CastSpellInfo[(int)slot].is_set = true;
		Ace_Patch::CastSpellInfo[(int)slot].mouse1 = ClientData->TargetPosition;
		Ace_Patch::CastSpellInfo[(int)slot].mouse2 = ClientData->MousePosition2;
		if (!Ace_Patch::CastSpellInfo[(int)slot].mouse2.IsValid())
		{
			Ace_Patch::CastSpellInfo[(int)slot].mouse2 = Ace_Patch::CastSpellInfo[(int)slot].mouse1;
		}



		DedbgA("mouse1 %s | mouse2 %s", Ace_Patch::CastSpellInfo[(int)slot].mouse1.ToString().c_str(), Ace_Patch::CastSpellInfo[(int)slot].mouse2.ToString().c_str());

		keybd_event((BYTE)evt_map[(int)slot].v_key, (BYTE)MapVirtualKey(evt_map[(int)slot].v_key, 0), 0, 0);
		//AceKeyDown(evt_map[(int)slot].v_key);


		if (!IsChargingSpell(slot))
		{
	
			Common::GetInstance()->DelayAction(sleep_tick * 1000, [=]()
				{
				
					keybd_event((BYTE)evt_map[(int)slot].v_key, (BYTE)MapVirtualKey(evt_map[(int)slot].v_key, 0), KEYEVENTF_KEYUP, 0);
					//AceKeyUp(evt_map[(int)slot].v_key);
				});
		}

		return  true;
	}

	int AceHudKbdEvent(uintptr_t HudThisPtr, SpellSlot slot, int mode, int state)
	{
		int ret = 2;
		uintptr_t ptr = *(uintptr_t*)DEFINE_RVA(Offsets::HudManager::ClientPosInstance);
		POINT* PosData = (POINT*)(ptr + (uintptr_t)Offsets::HudManager::PosOffset);

		if ((int)slot == 13)
		{
			return ret;
		}

		if (state == 0)
		{
			if (Ace_Patch::CastSpellInfo[(int)slot].is_down)
			{
				return 0;
			}
			DedbgA("[+]按下键盘 %d", slot);
			if (Ace_Patch::CastSpellInfo[(int)slot].is_set)
			{
				PosData->x = (int)Ace_Patch::CastSpellInfo[(int)slot].mouse1.WorldToScreen().x;
				PosData->y = (int)Ace_Patch::CastSpellInfo[(int)slot].mouse1.WorldToScreen().y;
				//Common::GetInstance()->SetCursorPosition(Ace_Patch::CastSpellInfo[(int)slot].mouse1);
				ret = 1;
				//Utils::Out::Dedbg_ExA("[+]设置坐标 %s", Ace_Patch::CastSpellInfo[(int)slot].mouse1.ToString().c_str());
			}
			else
			{
				ret = 2;
			}
			Ace_Patch::CastSpellInfo[(int)slot].is_down = true;
		}
		else
		{
			if (!Ace_Patch::CastSpellInfo[(int)slot].is_down)
			{
				return 0;
			}
			DedbgA("[-]抬起键盘 %d", slot);
			if (Ace_Patch::CastSpellInfo[(int)slot].is_set)
			{
				PosData->x = (int)Ace_Patch::CastSpellInfo[(int)slot].mouse2.WorldToScreen().x;
				PosData->y = (int)Ace_Patch::CastSpellInfo[(int)slot].mouse2.WorldToScreen().y;
				//Common::GetInstance()->SetCursorPosition(Ace_Patch::CastSpellInfo[(int)slot].mouse2);
				Ace_Patch::CastSpellInfo[(int)slot].is_set = false;
				ret = 1;
				//Utils::Out::Dedbg_ExA("[-]抬起设置坐标 %s", Ace_Patch::CastSpellInfo[(int)slot].mouse2.ToString().c_str());
			}
			else
			{
				ret = 2;
			}

			Ace_Patch::CastSpellInfo[(int)slot].is_down = false;
		}

		return ret;

	}

	void AceKeyDown(UINT v_key)
	{
		USHORT key = MapVirtualKey(v_key, 0);
		umc::send_request(umc::code_keyboard_sendinput_down, &key, sizeof(key));
	}

	void AceKeyUp(UINT v_key)
	{
		USHORT key = MapVirtualKey(v_key, 0);
		umc::send_request(umc::code_keyboard_sendinput_up, &key, sizeof(key));
	}


	bool AceInitKey()
	{
		
		evt_map[0] = { "evtCastSpell1" , (UINT)Common::GetInstance()->GetGameInputVal(evtCastSpell1) };
		evt_map[1] = { "evtCastSpell2" , (UINT)Common::GetInstance()->GetGameInputVal(evtCastSpell2) };
		evt_map[2] = { "evtCastSpell3" , (UINT)Common::GetInstance()->GetGameInputVal(evtCastSpell3) };
		evt_map[3] = { "evtCastSpell4" , (UINT)Common::GetInstance()->GetGameInputVal(evtCastSpell4) };
		evt_map[4] = { "evtCastAvatarSpell1" , (UINT)Common::GetInstance()->GetGameInputVal(evtCastAvatarSpell1) };
		evt_map[5] = { "evtCastAvatarSpell2" , (UINT)Common::GetInstance()->GetGameInputVal(evtCastAvatarSpell2) };
		evt_map[6] = { "evtUseItem1" , (UINT)Common::GetInstance()->GetGameInputVal(evtUseItem1) };
		evt_map[7] = { "evtUseItem2" , (UINT)Common::GetInstance()->GetGameInputVal(evtUseItem2) };
		evt_map[8] = { "evtUseItem3" , (UINT)Common::GetInstance()->GetGameInputVal(evtUseItem3) };
		evt_map[9] = { "evtUseItem4" , (UINT)Common::GetInstance()->GetGameInputVal(evtUseItem4) };
		evt_map[10] = { "evtUseItem5" , (UINT)Common::GetInstance()->GetGameInputVal(evtUseItem5) };
		evt_map[11] = { "evtUseItem6" , (UINT)Common::GetInstance()->GetGameInputVal(evtUseItem6) };
		evt_map[12] = { "evtUseVisionItem" , (UINT)Common::GetInstance()->GetGameInputVal(evtUseVisionItem) };
		evt_map[13] = { "evtUseItem7" , (UINT)Common::GetInstance()->GetGameInputVal(evtUseItem7) };

		UINT default_key[] = { 0x51, 0x57, 0x45, 0x52, 0x44, 0x46, 0x31, 0x32, 0x33, 0x35, 0x36, 0x37, 0x34, 0x42 };

		for (int i = 0; i < 14; i++)
		{
			if (evt_map[i].v_key == 0)
			{
				evt_map[i].v_key = default_key[i];
			}
		}
		is_init_spell = true;

		//AceUnhookPatch();

		return is_init_spell;
	}

	void AceResetKey(std::string event_name, UINT val)
	{
		for (auto& info : evt_map)
		{
			if (info.second.evt_name == event_name)
			{
				info.second.v_key = val;
				break;
			}
		}
	}

	bool AceEvadeFilter(Vector3 point)
	{
		//float angle = 360.0f;
		//auto  currentPath = g_LocalPlayer->GetWaypoints();

		//if (currentPath.size() > 1 && g_Common->PathLengthEx(currentPath) > 100) {
		//	auto movePath = g_LocalPlayer->CreatePath(point);
		//	if (movePath.size() > 1) {
		//		Vector3 v1 = currentPath[1] - currentPath[0];
		//		Vector3 v2 = movePath[1] - movePath[0];
		//		angle = v1.AngleBetween(v2);
		//		float distance = movePath.back().Distance(currentPath.back(), true);

		//		//if (distance < 50 * 50)
		//		//{
		//		//	//LOG(u8"躲避 d < 50，已屏蔽");
		//		//	return true;
		//		//}
		//		if (angle < 10)
		//		{
		//			//LOG(u8"躲避角度<10");
		//			return true;
		//		}

		//	}
		//}

		return false;
	}


	DWORD GetProcessIDByName(const std::wstring& processName) {
		DWORD processID = 0;
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

		if (hSnapshot != INVALID_HANDLE_VALUE) {
			PROCESSENTRY32 processEntry;
			processEntry.dwSize = sizeof(PROCESSENTRY32);

			if (Process32First(hSnapshot, &processEntry)) {
				do {
					if (processName == processEntry.szExeFile) {
						processID = processEntry.th32ProcessID;
						break;
					}
				} while (Process32Next(hSnapshot, &processEntry));
			}
		}

		CloseHandle(hSnapshot);
		return processID;
	}

	void AceUnhookPatch()
	{
		//LOG("ZwCallbackReturn org %02x", *(BYTE*)real::ZwCallbackReturn);
		/*auto drv64 = GetModuleHandleA("ACE-DRV64.dll");
		if (drv64)
		{
			*(uint64_t*)((uint64_t)drv64 + 0x673368) = 0;
		}*/
		DedbgA(" AceUnhookPatch");
		if (*(BYTE*)real::ZwCallbackReturn != real::ZwCallbackReturn_byte[0])
		{
			DWORD old_protect = 0;
			if (!VirtualProtect((LPVOID)real::ZwCallbackReturn, 14, PAGE_EXECUTE_READWRITE,
				&old_protect)) {
				return;
			}

			DedbgA("ZwCallbackReturn org %02x", *(BYTE*)real::ZwCallbackReturn);
			memmove((LPVOID)real::ZwCallbackReturn, real::ZwCallbackReturn_byte, 14);
			DedbgA("ZwCallbackReturn new %02x", *(BYTE*)real::ZwCallbackReturn);

			VirtualProtect((LPVOID)real::ZwCallbackReturn, 14, old_protect, &old_protect);
		}

		// 获取目标进程的名称（请替换为您感兴趣的进程）
		std::wstring processName = L"dwm.exe";

		// 根据进程名称获取进程ID
		DWORD processID = GetProcessIDByName(processName);

		// 打开目标进程
		HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, processID);

		if (hProcess == NULL) {
			DedbgA("OpenProcess failed");
			return;
		}

		// 要读取的内存地址（请替换为您感兴趣的地址）
		LPCVOID addressToRead = (LPCVOID)real::ZwCallbackReturn; // 示例地址
		SIZE_T bytesRead = 0;
		BYTE buffer = 0;

		// 读取目标进程的内存
		if (ReadProcessMemory(hProcess, addressToRead, &buffer, 1, &bytesRead)) {
			//LOG("dwm byte %02x", buffer);
		}
		else
		{
			DedbgA("ReadProcessMemory failed");
			return;
		}

		if (buffer != real::ZwCallbackReturn_byte[0])
		{
			// 要写入的内存地址和数据（请替换为您感兴趣的地址和数据）
			LPVOID addressToWrite = (LPVOID)real::ZwCallbackReturn; // 示例地址
			SIZE_T bytesWritten = 0;


			DWORD oldProtect;
			if (VirtualProtectEx(hProcess, addressToWrite, 14, PAGE_EXECUTE_READWRITE, &oldProtect)) {
				// 写入目标进程的内存
				if (WriteProcessMemory(hProcess, addressToWrite, real::ZwCallbackReturn_byte, 14, &bytesWritten)) {
					DedbgA("write dwm success");
				}
				else {
					DedbgA("write dwm fail");
				}

				// 恢复原始内存保护属性
				DWORD temp;
				VirtualProtectEx(hProcess, addressToWrite, sizeof(int), oldProtect, &temp);
			}
			else {
				DedbgA("VirtualProtectEx dwm fail");
			}
		}


		// 关闭进程句柄
		CloseHandle(hProcess);

	}

	bool AceHudUpdateChargeableSpell(int slot, Vector3 position, bool ReleaseCast)
	{
		if (ReleaseCast)
		{
			Ace_Patch::CastSpellInfo[(int)slot].slot = (int)slot;
			Ace_Patch::CastSpellInfo[(int)slot].mouse2 = position;
			Ace_Patch::CastSpellInfo[(int)slot].is_set = true;
			keybd_event((BYTE)evt_map[(int)slot].v_key, (BYTE)MapVirtualKey(evt_map[(int)slot].v_key, 0), KEYEVENTF_KEYUP, 0);
			//AceKeyUp(evt_map[(int)slot].v_key);
			return true;
		}

		return false;
	}


	void AceHudOnUpdateCheck(int slot)
	{
		if (IsChargingSpell(slot))
		{
			if (Ace_Patch::CastSpellInfo[(int)slot].is_down && Ace_Patch::CastSpellInfo[(int)slot].is_set)
			{
				DedbgA("抬起");
				Ace_Patch::CastSpellInfo[(int)slot].is_set = false;
				keybd_event((BYTE)evt_map[(int)slot].v_key, (BYTE)MapVirtualKey(evt_map[(int)slot].v_key, 0), KEYEVENTF_KEYUP, 0);
				//AceKeyUp(evt_map[(int)slot].v_key);
				//Utils::Out::Dedbg_ExA("强制抬起技能 %d", slot);
			}
		}
	}

	bool IsInit()
	{
		return g_base64_info.base_address != 0 && g_pbc_game64_info.base_address != 0 && g_ats64_info.base_address != 0 && g_csi64_info.base_address != 0 && g_drv64_info.base_address != 0;
	}

#if defined(VT_EPT)

	enum class ioctl_access : uint32_t
	{
		none = 0,
		read = 1,
		write = 2,

		read_write = read | write
	};

	constexpr inline auto
		make_ioctl_code_windows(
			uint32_t id,
			ioctl_access access,
			uint32_t size
		) noexcept
	{
		//
		// "Size" isn't part of the IOCTL code on Windows.
		//
		(void)(size);

		//
		// Taken from CTL_CODE() macro.
		//
		constexpr auto ctl_code_impl = [](
			uint32_t DeviceType,
			uint32_t Method,
			uint32_t Function,
			uint32_t Access
			) noexcept -> uint32_t {
				return (DeviceType << 16)
					| (Access << 14)
					| (Function << 2)
					| (Method);
		};

		//
		// DeviceType
		//   Identifies the device type.  This value must match the
		//   value that is set in the DeviceType member of the driver's
		//   DEVICE_OBJECT structure.  (See Specifying Device Types).
		//   Values of less than 0x8000 are reserved for Microsoft.
		//   Values of 0x8000 and higher can be used by vendors.
		//   Note that the vendor-assigned values set the Common bit.
		//
		// FunctionCode
		//   Identifies the function to be performed by the driver.
		//   Values of less than 0x800 are reserved for Microsoft.
		//   Values of 0x800 and higher can be used by vendors.
		//   Note that the vendor-assigned values set the Custom bit.
		//
		// (ref: https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/defining-i-o-control-codes)
		//

		return ctl_code_impl(0x00000022,         // FILE_DEVICE_UNKNOWN
			0,                  // METHOD_BUFFERED
			0x800 | id,
			uint32_t(access));
	}

	constexpr inline auto
		make_ioctl_code_linux(
			uint32_t id,
			ioctl_access access,
			uint32_t size
		) noexcept
	{
		//
		// Taken from Linux source code (include/uapi/asm-generic/ioctl.h).
		//
		constexpr auto ctl_code_impl = [](
			uint32_t dir,
			uint32_t type,
			uint32_t nr,
			uint32_t size
			) noexcept -> uint32_t {
				return ((dir) << 0)   // IOC_DIRSHIFT
					| ((type) << 8)   // IOC_TYPESHIFT
					| ((nr) << 16)   // IOC_NRSHIFT
					| ((size) << 30);  // IOC_SIZESHIFT
		};

		return ctl_code_impl(uint32_t(access), 'H', id, size);
	}

	constexpr inline auto
		make_ioctl_code(
			uint32_t id,
			ioctl_access access,
			uint32_t size
		) noexcept
	{
#ifdef _WIN32
		return make_ioctl_code_windows(id, access, size);
#elif __linux__
		return make_ioctl_code_linux(id, access, size);
#else
#error Unsupported operating system!
#endif
	}

	template <
		uint32_t Id,
		ioctl_access Access,
		uint32_t Size
	>
	struct ioctl_t
	{
		static constexpr uint32_t code = make_ioctl_code(Id, Access, Size);
		static constexpr uint32_t size = Size;
	};

	template <uint32_t Id>
	using ioctl_none_t = ioctl_t<Id, ioctl_access::none, 0>;

	template <uint32_t Id, uint32_t Size>
	using ioctl_read_t = ioctl_t<Id, ioctl_access::read, Size>;

	template <uint32_t Id, uint32_t Size>
	using ioctl_write_t = ioctl_t<Id, ioctl_access::write, Size>;

	template <uint32_t Id, uint32_t Size>
	using ioctl_read_write_t = ioctl_t<Id, ioctl_access::read_write, Size>;


	void get_aligned_pages(PVOID p, size_t size, std::vector<PVOID>& pages)
	{
		if (!p)
		{
			return;
		}

		PVOID p_range = (PVOID)((uintptr_t)p + size);
		PVOID page_pointer = PAGE_ALIGN(p);

		while (true)
		{
			pages.push_back(page_pointer);
			page_pointer = (PVOID)((uintptr_t)page_pointer + PAGE_SIZE);

			if (page_pointer >= p_range)
			{
				break;
			}
		}
	}

	void get_text_section(PCHAR base, PCHAR* p_addr, SIZE_T* p_size)
	{
		PIMAGE_NT_HEADERS headers = (PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
		PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);
		for (DWORD i = 0; i < headers->FileHeader.NumberOfSections; ++i) {
			PIMAGE_SECTION_HEADER section = &sections[i];
			if (*(PINT)section->Name == 'EGAP' || memcmp(section->Name, ".text", 5) == 0)
			{
				*p_addr = base + section->VirtualAddress;
				*p_size = section->Misc.VirtualSize;
			}
		}

		return;
	}

	void FlushAndLockPage(void* start_address)
	{
		DWORD old_protect = 0;
		if (!VirtualProtect(start_address, 32, PAGE_EXECUTE_READWRITE,
			&old_protect)) {
			return;
		}
		memmove(start_address, start_address, 32);
		FlushInstructionCache(GetCurrentProcess(), start_address, 32);
		if (!VirtualProtect(start_address, 32, old_protect,
			&old_protect)) {
			return;
		}

		// Lock the address to a physical page. This prevents a page from paged out
		if (!VirtualLock(start_address, 32)) {
			return;
		}
	}

	//Ercvf_xxx
	using ioctl_add_hook_t = ioctl_read_write_t<2, sizeof(uint16_t)>;
	void ru_add_hook(UINT64 PageRead, UINT64 PageExecute)
	{
		HANDLE DeviceHandle;

		DeviceHandle = CreateFile(TEXT("\\\\.\\Ercvf_xxx"),
			GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL,
			OPEN_EXISTING,
			0,
			NULL);

		if (DeviceHandle == INVALID_HANDLE_VALUE)
		{
			Out::Dedbg_ExA("Error while opening 'Ercvf_xxx' device!\n");
			return;
		}

		typedef struct {
			ULONG64 PageRead;
			ULONG64 PageExecute;
		} CONTEXT_SHADOWHOOK;

		CONTEXT_SHADOWHOOK cs = { PageRead, PageExecute };

		DWORD BytesReturned;
		DeviceIoControl(DeviceHandle,
			ioctl_add_hook_t::code,
			&cs,
			sizeof(cs),
			&cs,
			sizeof(cs),
			&BytesReturned,
			NULL);

		CloseHandle(DeviceHandle);
	}

	void hide_text_section(PVOID h_module)
	{
		PCHAR base = 0;
		SIZE_T size = 0;

		get_text_section((PCHAR)h_module, &base, &size);
		if (!base || !size)
		{
			return;
		}

		std::vector<PVOID> text_section_pages;
		get_aligned_pages(base, size, text_section_pages);
		//DedbgA("total pages hiding %p", text_section_pages.size());

		PVOID fake_mem = VirtualAlloc(0, PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE);
		memcpy((PVOID)((ULONG64)fake_mem), (PVOID)((ULONG64)base), PAGE_SIZE);

		//std::vector<PVOID> fake_text_section_pages;
		//get_aligned_pages(fake_mem, text_section_pages.size() * PAGE_SIZE, fake_text_section_pages);

		////Dedbg_Ex("total fake pages hiding %x", fake_text_section_pages.size());

		//for (int i = 0; i < text_section_pages.size(); i++)
		//{
		//	if (i == 0)
		//	{
		//		PVOID page_exec_aligned = PAGE_ALIGN(text_section_pages[i]);
		//		PVOID page_read_aligned = PAGE_ALIGN(fake_text_section_pages[i]);
		//		FlushAndLockPage(page_exec_aligned);
		//		FlushAndLockPage(page_read_aligned);
		//		//1. 假页
		//		//2. 真页
		//		ru_add_hook((UINT64)page_read_aligned, (UINT64)page_exec_aligned);
		//	}

		//}

		PVOID page_exec_aligned = PAGE_ALIGN(base);
		PVOID page_read_aligned = PAGE_ALIGN(fake_mem);
		FlushAndLockPage(page_exec_aligned);
		FlushAndLockPage(page_read_aligned);
		//1. 假页
		//2. 真页
		ru_add_hook((UINT64)page_read_aligned, (UINT64)page_exec_aligned);
		DedbgA("ru_hook exec:%p | read:%p", page_exec_aligned, page_read_aligned);
	}

	void add_ept(uintptr_t addr)
	{
		PVOID page_exec_aligned = PAGE_ALIGN(addr);
		PVOID fake_mem = VirtualAlloc(0, PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE);
		memcpy((PVOID)((ULONG64)fake_mem), (PVOID)((ULONG64)page_exec_aligned), PAGE_SIZE);

		PVOID page_read_aligned = PAGE_ALIGN(fake_mem);
		FlushAndLockPage(page_exec_aligned);
		FlushAndLockPage(page_read_aligned);
		//1. 假页
		//2. 真页
		ru_add_hook((UINT64)page_read_aligned, (UINT64)page_exec_aligned);

		DedbgA("ept addr：%p | exec %p read %p", addr, page_exec_aligned, page_read_aligned);
	}

#endif

	bool CreateFakeThread(std::string module, void* routine)
	{
		auto mod_info = get_module_info(GetModuleHandleA(module.c_str()));
		if (!mod_info.base_address || !mod_info.module_size)
		{
			return false;
		}

		std::vector<uint64_t> ResultArray = {};
		const char* code = "FF E1";
		MemorySearch::SearchMemory(GetCurrentProcess(), code, (uint64_t)mod_info.base_address, (uint64_t)mod_info.base_address + mod_info.module_size, ResultArray, 10);
		if (!ResultArray.empty())
		{
			uintptr_t address = ResultArray.front();

			return umc::create_thread(GetCurrentProcessId(), address, (uintptr_t)routine);
		}

		return false;
	}

	DWORD AceInitThread(LPVOID p)
	{
		while (!IsInit())
		{
			if (GetModuleHandleW(L"ACE-DRV64.dll") && g_drv64_info.base_address == 0)
			{
				g_drv64_info = Utils::get_module_info(GetModuleHandleW(L"ACE-DRV64.dll"));

		/*		auto* v_mod_nedll_base = GetModuleHandleW(L"ntdll.dll");
				real::DRV64NtDeviceIoControlFile = reinterpret_cast<uintptr_t>(GetProcAddress(v_mod_nedll_base, "NtDeviceIoControlFile"));

				uintptr_t NtDeviceIoControlFilePtr = g_drv64_info.base_address + 0x673460;
				AddToHookedList(NtDeviceIoControlFilePtr, 8);
				if (!Utils::Memory::WPM<uintptr_t>(NtDeviceIoControlFilePtr, reinterpret_cast<uintptr_t>(vmt_hook::DRV64NtDeviceIoControlFile)))
				{
					MessageBoxA(0, "error init0", 0, 0);
					exit(0);
				}

				uintptr_t FlagAddress = g_drv64_info.base_address + 0x65A898;
				if (!Utils::Memory::WPM<uintptr_t>(FlagAddress, 0))
				{
					MessageBoxA(0, "error init0", 0, 0);
					exit(0);
				}*/

				if (umc::send_request(umc::code_acebypass_patch, 0, 0))
				{
					DedbgA("patch on------------");
				}



			}
			if (GetModuleHandleW(L"ACE-Base64.dll") && g_base64_info.base_address == 0)
			{

				g_game_info = Utils::get_module_info(GetModuleHandle(nullptr));
				g_base64_info = Utils::get_module_info(GetModuleHandleW(L"ACE-Base64.dll"));

				real_RpcsCallBack = g_base64_info.base_address + 0x26DF40;
				//auto AceHookPtr = g_base64_info.base_address + 0x3C37A8;
				//Ace_Hook::real::AceHookGameCallBack = *(uintptr_t*)AceHookPtr;
				//Utils::Memory::WPM<uintptr_t>(AceHookPtr, reinterpret_cast<uintptr_t>(Ace_Hook::AceHookGameCallBack));
			}

			if (GetModuleHandleW(L"ACE-Pbc-Game64.dll") && g_pbc_game64_info.base_address == 0)  
			{
				g_pbc_game64_info = Utils::get_module_info(GetModuleHandleW(L"ACE-Pbc-Game64.dll"));
				 
				//uintptr_t GetModuleHandleAPtr = g_pbc_game64_info.base_address + 0xD1018;
				//AddToHookedList(GetModuleHandleAPtr, 8);

				//real::GetModuleHandleA = (uintptr_t)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetModuleHandleA");
				//Utils::Memory::WPM<uintptr_t>(GetModuleHandleAPtr, reinterpret_cast<uintptr_t>(vmt_hook::GetModuleHandleA));
			}

			if (GetModuleHandleW(L"ACE-ATS64.dll") && g_ats64_info.base_address == 0)  //ATS负责查游戏段 CSI64
			{
				g_ats64_info = Utils::get_module_info(GetModuleHandleW(L"ACE-ATS64.dll"));

				//Ace_Patch::dwVMTAts64Base = Utils::GetMemoryMirror((HMODULE)Ace_Patch::g_ats64_info.base_address);

				auto* v_mod_nedll_base = GetModuleHandleW(L"ntdll.dll");
				real::ATS64NtDeviceIoControlFile = reinterpret_cast<uintptr_t>(GetProcAddress(v_mod_nedll_base, "NtDeviceIoControlFile"));
				uintptr_t NtDeviceIoControlFilePtr = g_ats64_info.base_address + 0x1FBA00;
				AddToHookedList(NtDeviceIoControlFilePtr, 8);

				//Utils::Memory::WPM<uintptr_t>(NtDeviceIoControlFilePtr, reinterpret_cast<uintptr_t>(vmt_hook::ATS64NtDeviceIoControlFile));
				*(uint64_t*)NtDeviceIoControlFilePtr = reinterpret_cast<uintptr_t>(vmt_hook::ATS64NtDeviceIoControlFile);

				if (umc::unlock_protect(GetCurrentProcessId(), g_ats64_info.base_address + 0x1445F0 + 0x20))
				{
					AddToHookedList(g_ats64_info.base_address + 0x1445F0 + 0x20, 8);
					if (Utils::Memory::WPM<uintptr_t>(g_ats64_info.base_address + 0x1445F0 + 0x20, reinterpret_cast<uintptr_t>(vmt_hook::ATS64InitNtdll)))
					{
						DedbgA("ats64 强写成功1");
					}
					else
					{
						MessageBoxA(0, "error init1", 0, 0);
						__fastfail(0);
					}
				}
				else
				{
					MessageBoxA(0, "error init2", 0, 0);
					__fastfail(0);
				}

				real::VirtualQueryEx = (uintptr_t)GetProcAddress(GetModuleHandle(L"KERNEL32.dll"), "VirtualQueryEx");
				if (umc::unlock_protect(GetCurrentProcessId(), g_ats64_info.base_address + 0x1401B0))
				{
					AddToHookedList(g_ats64_info.base_address + 0x1401B0, 8);
					if (Utils::Memory::WPM<uintptr_t>(g_ats64_info.base_address + 0x1401B0, reinterpret_cast<uintptr_t>(hooks::VirtualQueryEx)))
					{
						DedbgA("ats64 强写成功2");
					}
					else
					{
						MessageBoxA(0, "error init3", 0, 0);
						__fastfail(0);
					}
				}
				else
				{
					MessageBoxA(0, "error init4", 0, 0);
					__fastfail(0);
				}

				real::ATS64ReadProcessMemory = (uintptr_t)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "ReadProcessMemory");
				if (umc::unlock_protect(GetCurrentProcessId(), g_ats64_info.base_address + 0x1401C0))
				{
					AddToHookedList(g_ats64_info.base_address + 0x1401C0, 8);
					if (Utils::Memory::WPM<uintptr_t>(g_ats64_info.base_address + 0x1401C0, reinterpret_cast<uintptr_t>(vmt_hook::ATS64_ReadProcessMemory)))
					{
						DedbgA("ats64 强写成功3");
					}
					else
					{
						MessageBoxA(0, "error init5", 0, 0);
						__fastfail(0);
					}
				}
				else
				{
					MessageBoxA(0, "error init6", 0, 0);
					__fastfail(0);
				}

				//*(uint64_t*)(g_ats64_info.base_address + 0x1445F0 + 0x20) = tmp;
				//*(uint8_t*)(g_ats64_info.base_address + 0x1FC9AC) = 0;
			}
			if (GetModuleHandleW(L"ACE-CSI64.dll") && g_csi64_info.base_address == 0) //CSI负责查第三方模块
			{
				g_csi64_info = Utils::get_module_info(GetModuleHandleW(L"ACE-CSI64.dll"));

				//Ace_Patch::dwVMTCsi64Base = Utils::GetMemoryMirror((HMODULE)Ace_Patch::g_csi64_info.base_address);

				auto* v_mod_nedll_base = GetModuleHandleW(L"ntdll.dll");
				real::CSI64NtDeviceIoControlFile = reinterpret_cast<uintptr_t>(GetProcAddress(v_mod_nedll_base, "NtDeviceIoControlFile"));

				uintptr_t NtDeviceIoControlFilePtr = g_csi64_info.base_address + 0x73A500;
				AddToHookedList(NtDeviceIoControlFilePtr, 8);
				if (!Utils::Memory::WPM<uintptr_t>(NtDeviceIoControlFilePtr, reinterpret_cast<uintptr_t>(vmt_hook::CSI64NtDeviceIoControlFile)))
				{
					MessageBoxA(0, "error init3", 0, 0);
					__fastfail(0);
				}

				uintptr_t ReadProcessMemoryPtr = g_csi64_info.base_address + 0x4FD160;
				AddToHookedList(ReadProcessMemoryPtr, 8);
				real::CSI64ReadProcessMemory = (uintptr_t)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "ReadProcessMemory");
				if (!Utils::Memory::WPM<uintptr_t>(ReadProcessMemoryPtr, reinterpret_cast<uintptr_t>(vmt_hook::CSI64_ReadProcessMemory)))
				{
					MessageBoxA(0, "error init4", 0, 0);
					__fastfail(0);
				}


				uintptr_t NtQueryVirtualMemoryPtr = g_csi64_info.base_address + 0x4FD9B8;
				AddToHookedList(NtQueryVirtualMemoryPtr, 8);
				real::CSI64NtQueryVirtualMemory = (uintptr_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryVirtualMemory");
				Utils::Memory::WPM<uintptr_t>(NtQueryVirtualMemoryPtr, reinterpret_cast<uintptr_t>(vmt_hook::NtQueryVirtualMemory));



				/*uintptr_t VirtualQueryPtr = g_csi64_info.base_address + 0x4FD428;
				real::CSI64VirtualQuery = (uintptr_t)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "VirtualQuery");
				Utils::Memory::WPM<uintptr_t>(VirtualQueryPtr, reinterpret_cast<uintptr_t>(vmt_hook::VirtualQuery));



				uintptr_t VirtualQueryExPtr = g_csi64_info.base_address + 0x4FD190;
				real::CSI64VirtualQueryEx = (uintptr_t)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "VirtualQueryEx");
				Utils::Memory::WPM<uintptr_t>(VirtualQueryExPtr, reinterpret_cast<uintptr_t>(vmt_hook::VirtualQueryEx));*/


				real::Csi64MemmoveProc = g_csi64_info.base_address + 0x1B5CB0;
				if (0 != real::Csi64MemmoveProc)
				{
					AddToHookedList(real::Csi64MemmoveProc, 15);
					/*PVOID page_exec_aligned = PAGE_ALIGN(real::Csi64MemmoveProc);
					PVOID fake_mem = VirtualAlloc(0, PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE);
					memcpy((PVOID)((ULONG64)fake_mem), (PVOID)((ULONG64)page_exec_aligned), PAGE_SIZE);*/
					DedbgA("memmove_0 %p", real::Csi64MemmoveProc);
					base::hook::install(&real::Csi64MemmoveProc, reinterpret_cast<uintptr_t>(hooks::memmove_0));

					//PVOID page_read_aligned = PAGE_ALIGN(fake_mem);
					//FlushAndLockPage(page_exec_aligned);
					//FlushAndLockPage(page_read_aligned);
					////1. 假页
					////2. 真页
					//ru_add_hook((UINT64)page_read_aligned, (UINT64)page_exec_aligned);
				}
			}
		}
		DedbgA("AceInitThread 完毕");
		//DedbgA("csi fake %p | ats fake %p", Ace_Patch::dwVMTCsi64Base, Ace_Patch::dwVMTAts64Base);
		return 0;
	}

	std::vector<hooked_info*> hooked_list;
	void AddToHookedList(uintptr_t addr, size_t code_size)
	{
		auto hi = new hooked_info();
		hi->addr = addr;
		hi->code_size = code_size;
		memcpy(hi->org_code_buf, (void*)addr, code_size);

		hooked_list.push_back(hi);

		DedbgA("添加hook列表:%p|%p", hi->addr, hi->code_size);
	}

	void CopyFixedHookedList(Utils::module_info mod_info, void* buffer, size_t MaxCount, size_t mod_offset)
	{
		auto p = new char[mod_info.module_size];
		memset(p, 0, mod_info.module_size);

		for (uintptr_t i = 0; i < mod_info.module_size; i += 4096)
		{
			ReadProcessMemory(GetCurrentProcess(), (void*)(mod_info.base_address + i), (void*)(p + i), 4096, nullptr);
		}

		for (auto hi : Ace_Patch::hooked_list)
		{
			if (Utils::is_address_in_module(hi->addr, mod_info))
			{
				auto offset = hi->addr - mod_info.base_address;
				memcpy((void*)(p + offset), hi->org_code_buf, hi->code_size);
				DedbgA("Fix: %p | org %02x", hi->addr, hi->org_code_buf[0]);
			}
		}

		memcpy(buffer, p + mod_offset, MaxCount);
		delete[] p;	
	}


	bool ProtectMemory(uintptr_t address, size_t size, uint32_t NewProtection, uint32_t* oldProtection)
	{

		if (oldProtection == NULL)
		{
			uint32_t ol = {};
			oldProtection = &ol;
		}
		NTSTATUS status = syscall::call(syscall::index("ZwProtectVirtualMemory"), GetCurrentProcess(),
			&address,
			&size,
			NewProtection,
			oldProtection);

		if (status != 0)
		{
			Utils::msg::error_msg("error", 0);
			return false;
		}
		return true;
	}

	bool Initialize(HMODULE patch_module)
	{
	
		/*SECURITY_ATTRIBUTES out = {};
		CreateFileW(L"AntiCheatExpert\\InGame\\x64\\ACE-DFS64.dll", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &out, OPEN_EXISTING, 0x80, 0);*/

		auto pass_module_info = Utils::get_module_info(patch_module);
		g_file_mapping = new CFileMapping;

		BOOL IsCreated = FALSE;
		bool is_create = g_file_mapping->Create(("EAB55EAB5932"), sizeof(PatchDllInfo), &IsCreated);
		
		if (is_create) {

			g_DllInfo = (PatchDllInfo*)g_file_mapping->GetBase();
			DedbgA("is_create%p", g_DllInfo);

			memset(g_DllInfo, 0, sizeof(PatchDllInfo));

			g_DllInfo->pid = GetCurrentProcessId();
			g_DllInfo->module_size = 0;
		}
	
		DllInfo di = { 0 };
		di.DllBase = pass_module_info.base_address;
		di.DllSize = pass_module_info.module_size;

		DedbgA("dll %p|%p ==", di.DllBase, di.DllSize);

		//hide_text_section((PVOID)pass_module_info.base_address);
		//#ifdef DEVELOPER
		//		hide_text_section((PVOID)pass_module_info.base_address);
		//
		//		char* p_new = new char[0x3000];
		//
		//		const char* str = "AutoMata在技能准备好时绘制范围";
		//
		//		memcpy(p_new + 0x1000, str, strlen(str));
		//
		//		PVOID fake_mem = VirtualAlloc(0, PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE);
		//	
		//		PVOID page_exec_aligned = PAGE_ALIGN(p_new + 0x1000);
		//		memcpy((PVOID)((ULONG64)fake_mem), (PVOID)((ULONG64)page_exec_aligned), PAGE_SIZE);
		//
		//		PVOID page_read_aligned = PAGE_ALIGN(fake_mem);
		//		FlushAndLockPage(page_exec_aligned);
		//		FlushAndLockPage(page_read_aligned);
		//		//1. 假页
		//		//2. 真页
		//		ru_add_hook((UINT64)page_read_aligned, (UINT64)page_exec_aligned);
		//
		//		Out::Dedbg_ExA("new 内存：%p | fake :%p", p_new + 0x1000, fake_mem);
		//
		//#endif

		AddModuleInfo(di);

		bool is_requst = umc::send_request(umc::code_keyboard_on, 0, 0);

		/*real::LoadLibraryExW = (uintptr_t)GetProcAddress(GetModuleHandle(L"KERNELBASE.dll"), "LoadLibraryExW");
		if (real::LoadLibraryExW != 0)
		{
			base::hook::install(&real::LoadLibraryExW, reinterpret_cast<uintptr_t>(hooks::LoadLibraryExW), &hook_t::LoadLibraryExW);
		}*/
	
		//DedbgA("只有VirtualQueryEx,hook里面没功能");
		/*real::VirtualQueryEx = (uintptr_t)GetProcAddress(GetModuleHandle(L"KERNEL32.dll"), "VirtualQueryEx");
		if (real::VirtualQueryEx != 0)
		{
			base::hook::install(&real::VirtualQueryEx, reinterpret_cast<uintptr_t>(hooks::VirtualQueryEx));
		}*/

		//CloseHandle(CreateThread(0, 0, (LPTHREAD_START_ROUTINE)AceInitThread, 0, 0, 0));

		//unhook ZwCallbackReturn
		/*real::ZwCallbackReturn = (uintptr_t)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "ZwCallbackReturn");
		memcpy(real::ZwCallbackReturn_byte, (void*)real::ZwCallbackReturn, 14);*/

		real_NewIssueOrder = static_cast<uintptr_t>(OFFSET_PBC64::NewIssueOrder);
		real_NewCastSpell = static_cast<uintptr_t>(OFFSET_PBC64::NewCastSpell);
		real_NewSmoothPath = static_cast<uintptr_t>(OFFSET_PBC64::NewSmoothPath);

		if (ntdll_memory == 0)
		{
			auto ntdll_mod_info = Utils::get_module_info(GetModuleHandleA("ntdll.dll"));
			if (!ntdll_mod_info.base_address || !ntdll_mod_info.module_size)
			{
				__fastfail(0);
			}

			std::vector<uint64_t> ResultArray = {};
			const char* code = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";
			Utils::MemorySearch::SearchMemory(GetCurrentProcess(), code, (uint64_t)ntdll_mod_info.base_address, (uint64_t)ntdll_mod_info.base_address + ntdll_mod_info.module_size, ResultArray, 10);
			if (!ResultArray.empty())
			{
				ntdll_memory = ResultArray.front();
				ProtectMemory(ntdll_memory, 0x2000, PAGE_EXECUTE_READWRITE);
			}
		}

		real::CreateThread = reinterpret_cast<uintptr_t>(GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateThread"));
		if (real::CreateThread)
		{
			base::hook::install(&real::CreateThread, reinterpret_cast<uintptr_t>(hooks::HookCreateThread));

		}
		real::VirtualAlloc = reinterpret_cast<uintptr_t>(GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualAlloc"));
		if (real::VirtualAlloc)
		{
			base::hook::install(&real::VirtualAlloc, reinterpret_cast<uintptr_t>(hooks::HookVirtualAlloc));
		}

		real::NtAllocateVirtualMemory = reinterpret_cast<uintptr_t>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory"));
		if (real::NtAllocateVirtualMemory)
		{
			base::hook::install(&real::NtAllocateVirtualMemory, reinterpret_cast<uintptr_t>(hooks::HookNtAllocateVirtualMemory));
		}

		return Ace_Patch::CreateFakeThread("ntdll.dll", AceInitThread) && is_requst;
	}
}
#pragma optimize( "", on )