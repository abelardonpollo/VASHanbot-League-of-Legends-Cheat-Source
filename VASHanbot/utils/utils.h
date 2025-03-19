#pragma once
#include <Windows.h>
#include <cstdint>
#include <stdio.h>
#include <string>
#include <vector>
#include <sstream>

#ifndef DEVELOPER
#include ".././permit/VMProtectSDK.h"
#endif


#ifdef DEVELOPER
#define DedbgA(...) Utils::Out::Dedbg_ExA(__VA_ARGS__)
#define DedbgW(...) Utils::Out::Dedbg_ExW(__VA_ARGS__)
#define ens_a(s) s
#define ens_w(s) s
#else
#define DedbgA(...)
#define DedbgW(...)
#define ens_a(s) VMProtectDecryptStringA(s)
#define ens_w(s) VMProtectDecryptStringW(s)
#endif

namespace  Utils
{

	void r_ini(const char* _key, char* rbuf, const char* _def);
	void w_ini(const char* _key, const char* _val);

	std::wstring string_to_wstring(const std::string& narrowString);

#pragma pack(push, 1)
	struct module_info {
		uintptr_t base_address;
		size_t    module_size;       
		module_info(void)
			: base_address(0), module_size(0) {
		}

		module_info(const uintptr_t _base_address, const uint32_t _module_size)
			: base_address(_base_address), module_size(_module_size) {
		}
	};

	module_info get_module_info(HMODULE Module);
	BOOL is_address_in_module(uintptr_t a_address, module_info a_which_module);

	std::string string_format(const char* format, ...);

#pragma pack(pop)

	namespace Memory
	{
		template<typename T> T RPM(uintptr_t address) {
			if (IsBadReadPtr(reinterpret_cast<void*>(address), 4) == 1)
			{
				return 0;
			}
			return 	*(T*)(address);
		}

		template<typename T> bool WPM(uintptr_t address, T data) {
			if (IsBadReadPtr(reinterpret_cast<void*>(address), 4) == 1)
			{
				return false;
			}

			DWORD TempProtectVar = NULL;
			if (VirtualProtect(reinterpret_cast<LPVOID>(address), sizeof(T), PAGE_EXECUTE_READWRITE, &TempProtectVar))
			{
				*(T*)(address) = data;

				VirtualProtect(reinterpret_cast<LPVOID>(address), sizeof(T), TempProtectVar, &TempProtectVar);
				if (*(T*)(address) == data)
				{
					return true;
				}
			}
			return false;
		}

		inline void Hook_Jmp(uintptr_t dwHookAddr, DWORD dwEip)
		{
			uintptr_t dwJmp = dwEip - dwHookAddr - 5;
			BYTE pCode[5] = { 0 };
			pCode[0] = 0xe9;
			DWORD lpflOldProtect = NULL;
			VirtualProtect(reinterpret_cast<LPVOID>(dwHookAddr), 5, PAGE_EXECUTE_READWRITE, &lpflOldProtect);
			memcpy(&pCode[1], &dwJmp, 4);
			memcpy(reinterpret_cast<LPVOID>(dwHookAddr), pCode, 5);
			VirtualProtect(reinterpret_cast<LPVOID>(dwHookAddr), 5, lpflOldProtect, &lpflOldProtect);
		}

		inline void Hook_Call(uintptr_t dwHookAddr, DWORD dwEip)
		{
			uintptr_t dwJmp = dwEip - dwHookAddr - 5;
			BYTE pCode[5] = { 0 };
			pCode[0] = 0xe8;
			DWORD lpflOldProtect = NULL;
			VirtualProtect(reinterpret_cast<LPVOID>(dwHookAddr), 5, PAGE_EXECUTE_READWRITE, &lpflOldProtect);
			memcpy(&pCode[1], &dwJmp, 4);
			memcpy(reinterpret_cast<LPVOID>(dwHookAddr), pCode, 5);
			VirtualProtect(reinterpret_cast<LPVOID>(dwHookAddr), 5, lpflOldProtect, &lpflOldProtect);
		}


	}


	namespace msg
	{
		inline void error_msg(const std::string & error_msg,uint32_t val)
		{
			std::stringstream error_val_msg;
			error_val_msg << "error [ " << val << " ]";
			MessageBoxA(nullptr, error_msg.c_str(), error_val_msg.str().c_str(), MB_ICONQUESTION);

		}
	}

	namespace file
	{
		void* read_file(std::wstring_view fileName, size_t* fileSize);
	}


	namespace pe
	{
		bool hide_module(HMODULE hModule);
		module_info is_module(std::string_view name);
		HMODULE LdrLoad(std::wstring_view dll_path,ULONG falg_ = 0);
	}


	namespace Out
	{
		void Dedbg_ExA(const char* szFormat, ...);
		void Dedbg_ExW(const wchar_t* szFormat, ...);
	}


	uintptr_t GetMemoryMirror(HMODULE Module);

	uintptr_t GetMirrorBase(uintptr_t NewBase, uintptr_t base, DWORD dwAddr);

	std::string GenerateRandomString(int length);
	
	namespace Math {
		template<class T> T __ROL__(T value, int count) {
			const uint64_t nbits = sizeof(T) * 8;

			if (count > 0) {
				count %= nbits;
				T high = value >> (nbits - count);
				if (T(-1) < 0)
					high &= ~(T(-1) << count);
				value <<= count;
				value |= high;
			}
			else {
				count = -count % nbits;
				T low = value << (nbits - count);
				value >>= count;
				value |= low;
			}
			return value;
		}

		inline uint8_t __ROL1__(uint8_t value, int count) { return __ROL__(value, count); }
		inline uint8_t __ROR1__(uint8_t value, int count) { return __ROL__(value, -count); }

		inline uint16_t __ROL2__(uint16_t value, int count) { return __ROL__(value, count); }
		inline uint16_t __ROR2__(uint16_t value, int count) { return __ROL__(value, -count); }

		inline uint32_t __ROL4__(uint32_t value, int count) { return __ROL__(value, count); }
		inline uint32_t __ROR4__(uint32_t value, int count) { return __ROL__(value, -count); }

		inline uint64_t __ROL8__(uint64_t value, int count) { return __ROL__(value, count); }
		inline uint64_t __ROR8__(uint64_t value, int count) { return __ROL__(value, -count); }
	}


	namespace MemorySearch
	{
		size_t SearchMemory(HANDLE hProcess, const char* Tzm, uint64_t StartAddress, uint64_t EndAddress,  std::vector<uint64_t>& ResultArray, int InitSize = 10);
	}
}
