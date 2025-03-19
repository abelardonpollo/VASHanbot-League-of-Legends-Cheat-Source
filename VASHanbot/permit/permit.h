#pragma once
#include <string>
#include <Windows.h>
//#include "XAntiDebug/XAntiDebug.h"
#include <iostream>
#include <vector>

#define  mt_softver 2

#define ErrCode_A   0xA //参数错误
#define ErrCode_B   0xB //取软件信息失败
#define ErrCode_No  0xBB //NoErr

namespace permit
{
	extern uintptr_t* g_dumyArray;
	//extern XAntiDebug antiDebug;
	extern std::string end_time_str;
	int OnInitKs();
	void install(HMODULE h_module);

}


namespace BotSDK
{
	void Initialize();
}

EXTERN_C __forceinline void auth_xxx();
EXTERN_C __forceinline uintptr_t auth_get_rsp();
EXTERN_C __forceinline uintptr_t auth_get_teb_tlsp();
EXTERN_C __forceinline uintptr_t auth_get_teb_pid();
EXTERN_C __forceinline uintptr_t auth_get_teb_tid();
EXTERN_C __forceinline uintptr_t auth_get_peb_osver();