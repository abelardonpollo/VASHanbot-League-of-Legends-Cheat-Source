#include <cstdint>

#include "BotSDK.h"
#include "GameData/Offsets.h"
#include "Ace/Ace_Patch.h"
#include "utils/syscall.h"
#include "utils/utils.h"
#include "permit/permit.h"
#include "utils/ntdll.h"

namespace BotSDK
{
	extern PVOID g_ReservedMemory;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        BaseAddress = reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr));

        if (GetModuleHandle(L"League of Legends.exe") == nullptr)
        {
            return false;
        }
   
		SIZE_T RegionSize = 300 * 1024 * 1024; // at least 100MB, 200-300 is recommanded


		NTSTATUS status = syscall::call(syscall::index("NtAllocateVirtualMemory"), GetCurrentProcess(),
			&BotSDK::g_ReservedMemory,
			1,
			&RegionSize,
			MEM_RESERVE | MEM_COMMIT,
			PAGE_READWRITE); // reserved memory


		if (!NT_SUCCESS(status) || !BotSDK::g_ReservedMemory)
		{
			// error and exit, your bypass should be injected as soon as possible to reserve the memory
			__fastfail(0);
		}

		auto b = umc::send_request(umc::code_monitor_inject_state, 0, 0);
		auto b_ace = umc::send_request(umc::code_acebypass_check, 0, 0);

		DedbgA("%d|%d", b, b_ace);
		if (b && b_ace)
		{
			Ace_Patch::Initialize(hModule);
		}

#ifndef DEVELOPER
		Ace_Patch::CreateFakeThread("ntdll.dll", permit::install);
#else
		Ace_Patch::CreateFakeThread("ntdll.dll", BotSDK::BotInit);
#endif

    }

    return true;
}
