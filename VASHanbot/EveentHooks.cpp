#include "EveentHooks.h"
#include <intrin.h>
#include "BotSDK.h"
#include "Common.h"
#include "Ace/AceHook.h"
#include "Ace/Ace_Patch.h"
#include "GameData/Offsets.h"
#include "utils/fp_call.h"
#include "Utils/inline.h"
#include "permit/permit.h"

namespace EventHooks
{
	namespace real
	{
		uintptr_t OnUpdate = 0;
		uintptr_t OnIssueOrder = 0;
		uintptr_t OnGameCheck = 0;
		uintptr_t OnCastSpell = 0;
		uintptr_t evtCastSpellInputVal = 0;
		uintptr_t evtPlayerCastClickKeyboardTriggered = 0;
		uintptr_t OnProcessSpell = 0;
	}




	//uintptr_t __fastcall OnGameCheck(uintptr_t a1, uintptr_t* RerurnAddress)
	//{
	//    if (RerurnAddress)
	//    {
	//         RerurnAddress 是一个指针只想回溯地址 如果是bot调用的话就处理
	//        if (!utils::is_address_in_module(*RerurnAddress, stub::g_game_info))
	//        {
	//            auto tmp_val = *RerurnAddress;
	//             修改成游戏模块内的地址再调用
	//            *RerurnAddress = DEFINE_RVA(Offsets::Hooks::SpoofAddress);
	//            auto r_v = return_spoofer::spoof_call((void*)DEFINE_RVA(Offsets::Hooks::SpoofAddress), (decltype(OnGameCheck)*)real::OnGameCheck, a1, RerurnAddress);
	//            *RerurnAddress = tmp_val;
	//            return r_v;
	//        }
	//    }

	//    return return_spoofer::spoof_call((void*)DEFINE_RVA(Offsets::Hooks::SpoofAddress), (decltype(OnGameCheck)*)real::OnGameCheck, a1, RerurnAddress);
	//}



	class ProcessSpellVmt
	{
	public:
		DWORD64 N00000001; //0x0000 
		DWORD64 N00000002; //0x0008 
		DWORD64 N00000003; //0x0010 
		DWORD64 N00000004; //0x0018 
		DWORD64 N00000005; //0x0020 
		DWORD64 N00000006; //0x0028 
		char pad_0x0030[0x810]; //0x0030

	}; //Size=0x0840

	ProcessSpellVmt game_vmt = {};
	ProcessSpellVmt* hanbot_vmt = nullptr;

	uintptr_t BotProcessSpellCallBack = 0;


	uintptr_t __fastcall OnUpdate(void* ptr)
	{
		static bool OnGameStartCallBack = false;

		if (!OnGameStartCallBack)
		{
			BotSDK::LoadBot();
			game_vmt = *(ProcessSpellVmt*)DEFINE_RVA(0x1EB9330);
			hanbot_vmt = (ProcessSpellVmt*)DEFINE_RVA(0x1EB9330);
			OnGameStartCallBack = true;
		}

		if (hanbot_vmt)
		{
			if (!Utils::is_address_in_module(hanbot_vmt->N00000002, Ace_Patch::g_game_info))
			{
				if (BotProcessSpellCallBack == 0)
				{
					auto address = hanbot_vmt->N00000002 + 0x13;
					if (*(BYTE*)address == 0xe8)
					{
						int32_t offset = *(int32_t*)(address + 1);
						uintptr_t target = address + offset + 5;

						BotProcessSpellCallBack = target;
					}
				}




				DedbgA("vmt1 %p", hanbot_vmt->N00000002);
				uint32_t ol = {};
				Ace_Patch::ProtectMemory((uintptr_t)&hanbot_vmt->N00000002, 1, 0x40, &ol);
				hanbot_vmt->N00000002 = game_vmt.N00000002;
				Ace_Patch::ProtectMemory((uintptr_t)&hanbot_vmt->N00000002, 1, ol, &ol);
			}
			if (!Utils::is_address_in_module(hanbot_vmt->N00000006, Ace_Patch::g_game_info))
			{
				if (BotProcessSpellCallBack == 0)
				{
					auto address = hanbot_vmt->N00000006 + 0x13;
					if (*(BYTE*)address == 0xe8)
					{
						int32_t offset = *(int32_t*)(address + 1);
						uintptr_t target = address + offset + 5;

						BotProcessSpellCallBack = target;
					}
				}
				DedbgA("vmt2 %p", hanbot_vmt->N00000006);
				uint32_t ol = {};
				Ace_Patch::ProtectMemory((uintptr_t)&hanbot_vmt->N00000006, 1, 0x40, &ol);
				hanbot_vmt->N00000006 = game_vmt.N00000006;
				Ace_Patch::ProtectMemory((uintptr_t)&hanbot_vmt->N00000006, 1, ol, &ol);
			}
		}
	
		static HWND LOL_HWND = nullptr;
		static bool is_pause = false;

		if (LOL_HWND == nullptr)
		{
			LOL_HWND = FindWindow(nullptr, L"League of Legends (TM) Client");
		}

		if (Common::GetInstance()->IsChatting() || LOL_HWND != GetForegroundWindow())
		{
			if (!is_pause)
			{
				umc::send_request(umc::code_keyboard_check_pause, 0, 0);
				is_pause = true;
			}
			
		}
		else
		{
			if (is_pause)
			{
				umc::send_request(umc::code_keyboard_check_resume, 0, 0);
				is_pause = false;
			}
		}
	

		Common::GetInstance()->OnUpdata();

		return base::fast_call<uintptr_t>(real::OnUpdate, ptr);
	}

	bool __fastcall evtCastSpellInputVal(uintptr_t input_json_ptr, const char* name, const char* value)
	{
		for (;;)
		{
			std::vector<std::string> events = { "evtCastAvatarSpell1","evtCastAvatarSpell2",\
			"evtCastSpell1", "evtCastSpell2", "evtCastSpell3", "evtCastSpell4",\
			"evtUseItem1", "evtUseItem2", "evtUseItem3", "evtUseItem4", "evtUseItem5", "evtUseItem6", "evtUseItem7", "evtUseVisionItem" };


			auto event_iter = std::find_if(events.begin(), events.end(), [name](std::string& key)
				{
					return key == name;
				});

			if (event_iter != events.end())
			{
				std::string event_str = *event_iter;
				std::string evt_val = value;
				if (!evt_val.empty())
				{
					std::string::size_type pos = evt_val.find('[');
					while (pos != std::string::npos) {
						std::string::size_type end_pos = evt_val.find(']', pos);
						if (end_pos == std::string::npos) {
							break;
						}
						std::string val_str = evt_val.substr(pos + 1, end_pos - pos - 1);


#ifdef IS_ACE
						if (val_str.length() > 1)
						{
							if (val_str == "Space")
							{
								Ace_Patch::AceResetKey(event_str, 0x20);
							}
						}
						else
						{
							if (val_str[0] >= 'a' && val_str[1] <= 'z')
							{
								val_str[0] -= 32;
							}
							Ace_Patch::AceResetKey(event_str, val_str[0]);
						}
#endif

						DedbgA("name:%s | value:%s", name, value);
						break;
					}
				}

			}
			break;
		}
		return base::fast_call<bool>(real::evtCastSpellInputVal, input_json_ptr, name, value);

	}


	uintptr_t __fastcall evtPlayerCastClickKeyboardTriggered(uintptr_t HudThisPtr, SpellSlot Slot, int mode, int state)
	{

		auto ret = Ace_Patch::AceHudKbdEvent(HudThisPtr, Slot, mode, state);
		if (ret == 0)
		{
			return false;
		}
		if (ret == 1)
		{
			return base::fast_call<uintptr_t>(real::evtPlayerCastClickKeyboardTriggered, HudThisPtr, Slot, 2, state);
		}
		return base::fast_call<uintptr_t>(real::evtPlayerCastClickKeyboardTriggered, HudThisPtr, Slot, mode, state);

	}


	ace_hook vmt_processSpell;


	void __fastcall OnVmtProcessSpell(AceHookContext* context)
	{
		if(BotProcessSpellCallBack)
		{
			typedef void(__fastcall* fnBotProcessSpell)(uintptr_t CastInfo);
			fnBotProcessSpell pfnBotProcessSpell = (fnBotProcessSpell)(BotProcessSpellCallBack);

			pfnBotProcessSpell(context->rdx);

		}


		return vmt_processSpell.vmt_orgfunc(context);
	}

	void ApplyHooks()
	{
#ifndef DEVELOPER 
		//暗装
		if ((permit::g_dumyArray[200] ^ permit::g_dumyArray[201]) != ((uintptr_t)permit::g_dumyArray & 0x7fffffff))
		{
			while (1) {};
		}
#endif
		real::OnUpdate = DEFINE_RVA(Offsets::Hooks::OnUpdate);
		if (real::OnUpdate != 0)
		{
			Ace_Patch::AddToHookedList(real::OnUpdate, 15);
			if (!base::hook::install(&real::OnUpdate, reinterpret_cast<uintptr_t>(OnUpdate)))
			{
				MessageBoxA(0, "init err 1", 0, 0);
				__fastfail(0);
			}
		}


		real::evtCastSpellInputVal = DEFINE_RVA(Offsets::Functions::evtCastSpellInputVal);

		if (real::evtCastSpellInputVal != 0)
		{
			Ace_Patch::AddToHookedList(real::evtCastSpellInputVal, 15);
			if (!base::hook::install(&real::evtCastSpellInputVal, reinterpret_cast<uintptr_t>(evtCastSpellInputVal)))
			{
				MessageBoxA(0, "init err 2", 0, 0);
				__fastfail(0);
			}
		}

		real::evtPlayerCastClickKeyboardTriggered = DEFINE_RVA(Offsets::Functions::evtPlayerCastClickKeyboardTriggered);
		if (real::evtPlayerCastClickKeyboardTriggered != 0)
		{
			Ace_Patch::AddToHookedList(real::evtPlayerCastClickKeyboardTriggered, 15);
			if (!base::hook::install(&real::evtPlayerCastClickKeyboardTriggered, reinterpret_cast<uintptr_t>(evtPlayerCastClickKeyboardTriggered)))
			{
				MessageBoxA(0, "init err 3", 0, 0);
				__fastfail(0);
			}
		}

		real::OnProcessSpell = DEFINE_RVA(Offsets::Hooks::OnProcessSpell);
		if(real::OnProcessSpell)
		{
			if (!vmt_processSpell.vmt_hook(real::OnProcessSpell, OnVmtProcessSpell))
			{
				MessageBoxA(0, "init err 4", 0, 0);
				__fastfail(0);
			}
		}

		DedbgA("hook done");
		//real::OnGameCheck = DEFINE_RVA(Offsets::ByPass::OnGameCheck);
		//if (real::OnGameCheck != 0)
		//{
		//    base::hook::install(&real::OnGameCheck, reinterpret_cast<uintptr_t>(OnGameCheck));
		//}
	}
}
