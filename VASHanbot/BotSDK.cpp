#define WIN32_LEAN_AND_MEAN

#include "Common.h"
#include "./DarkLoadLibrary\darkloadlibrary.h"
#include "EveentHooks.h"
#include "./DarkLoadLibrary\pebutils.h"
#include "Ace/Ace_Patch.h"
#include "Gamedata/Offsets.h"
#include "GameData/OffsetsChina.h"
#include "utils/fp_call.h"


#include "utils/syscall.h"
#include "utils/utils.h"
#include "permit/permit.h"

namespace BotSDK
{
    PVOID g_ReservedMemory = nullptr;

    bool QueryVirtualMemory(LPVOID address, PMEMORY_BASIC_INFORMATION64 MemoryInformation)
    {

        if ((uintptr_t)address >= 0x7fffffffffff)
        {
            return false;
        }
        SIZE_T returnLength = 0;
        NTSTATUS status = syscall::call(syscall::index("ZwQueryVirtualMemory"), GetCurrentProcess(),
            address,
            0,
            MemoryInformation,
            sizeof(MEMORY_BASIC_INFORMATION),
            &returnLength);

        if (status != 0)
        {
            return false;
        }
        return true;
    }

    void ProtectHanbotLuaMemory()
    {
        MEMORY_BASIC_INFORMATION64 mbi;
        if (QueryVirtualMemory((LPVOID)g_ReservedMemory, &mbi))
        {
            DedbgA("±£»¤lua %p|%p", mbi.BaseAddress, mbi.RegionSize);
            Ace_Patch::AddModuleInfo({ mbi.BaseAddress, mbi.RegionSize });
        }
    }


    bool IsScreenPointOnScreen(Vector2 const& point, float offsetX = 0.f, float offsetY = 0.f)
    {
        auto window_info = Common::GetInstance()->GetWindowInfo();
        return point.x > -offsetX && point.x < ((float)window_info.x + offsetX) && point.y > -offsetY && point.y < ((float)window_info.y + offsetY);
    }

    float LastAttackCommandT = 0;
    float LastMoveCommandT = 0;
    IssueOrderType last_order = IssueOrderType::MoveTo;
    Vector3 last_move_point = {};

    bool __fastcall HookIssueOrder(GameObject* this_, IssueOrderType order, void* pos, void* target, int isAttackMove, int isPetMove, int unknown0)
    {
        if (order != IssueOrderType::AttackUnit && order != IssueOrderType::MoveTo && order != IssueOrderType::AttackTo)
        {
            DedbgA("·Ç·¨order %d", order);
            return 0;
        }

        using fnIssueOrder = uintptr_t(__fastcall*)(GameObject* unit, IssueOrderType order, void* position, void* target, bool attackMove, bool a6, bool a7);
  
        if (Ace_Patch::IsInit() && this_->mNetworkId == Common::GetInstance()->GetLocalPlayer()->mNetworkId)
        {
            Vector3 CurrentPos = *(Vector3*)pos;


			if (order == IssueOrderType::AttackUnit && Common::GetInstance()->TickCount() - LastAttackCommandT < ISSUEORDER_TICK + 100.f)
			{
               // DedbgA("issue 3 Ì«¿ì");
				return 0;
			}

            auto cursor_pos = Common::GetInstance()->GetCursorPosition();
            if (order == IssueOrderType::MoveTo)
            { 
                if (CurrentPos.Distance(cursor_pos) > 50.f)
                {
					if (Common::GetInstance()->TickCount() - LastAttackCommandT < ISSUEORDER_TICK * 5)
					{
                        DedbgA("×ß¿³-¶ã±ÜÑË¸î");
						return 0;
					}

					if (Common::GetInstance()->TickCount() - LastMoveCommandT < ISSUEORDER_TICK + 50.f)
					{
                        DedbgA("ÒÆ¶¯-¶ã±ÜÑË¸î");
						return 0;
					}
                   // DedbgA("µ÷ÓÃÒÆ¶¯-¶ã±Ü");
                }
                else
                {
					if (Common::GetInstance()->TickCount() - LastMoveCommandT < ISSUEORDER_TICK + 50.f)
					{
                        //DedbgA("issue 2 Ì«¿ì");
						return 0;
					}
                   // DedbgA("µ÷ÓÃÒÆ¶¯-ÆÕÍ¨");
                }
				
                if (order == last_order)
                {
                    if (CurrentPos.x == last_move_point.x && CurrentPos.z == last_move_point.z)
                    {
                        DedbgA("ÏàÍ¬×ø±ê£¬ÒÑÆÁ±Î");
                        return 0;
                    }
                }
            }

            auto pfnIssueOrder = reinterpret_cast<fnIssueOrder>(reinterpret_cast<uintptr_t>(NewIssueOrder));
            Vector2 Outpos = CurrentPos.WorldToScreen();
            if (!IsScreenPointOnScreen(Outpos))
            {
                return  0;
            }

            if (!Ace_Patch::AceMouseMessage(CurrentPos, order))
            {
                return  0;
            }

			if (order == IssueOrderType::AttackUnit || order == IssueOrderType::AttackTo)
			{
				LastAttackCommandT = Common::GetInstance()->TickCount();        
			}
			if (order == IssueOrderType::MoveTo)
			{
				LastMoveCommandT = Common::GetInstance()->TickCount();
			}

            last_order = order;
            last_move_point = CurrentPos;

            return pfnIssueOrder(this_, order, pos, target, isAttackMove, isPetMove, unknown0);
        }
        return true;

    }






    SpellDataInst* GetSpell(void* this_, void* spellDataClient)
    {
        typedef SpellDataInst*(__fastcall* fnGetSpellSlot)(void* ptr, void* spellDataClient);
        fnGetSpellSlot pfnGetSpell = (fnGetSpellSlot)(DEFINE_RVA(Offsets::SpellDataFunctions::GetSpell));
        return pfnGetSpell(this_, spellDataClient);
    }



    SpellSlot GetSpellSlot(void* this_, void* spellDataClient)
    {
        typedef SpellSlot(__fastcall* fnGetSpellSlot)(void* ptr, void* sdata);
        fnGetSpellSlot pfnGetSpellSlot = (fnGetSpellSlot)(DEFINE_RVA(Offsets::SpellDataFunctions::GetSpellSlot));
        return pfnGetSpellSlot(this_, spellDataClient);
    }


    bool __fastcall HookSendSpellCastPacket(void* this_, void* spellDataClient)
    {
        DedbgA("¼¼ÄÜ");

        auto data = GetSpell(this_, spellDataClient);
        if(data)
        {
            auto slot = GetSpellSlot(this_, spellDataClient);

            auto GetSpellPositionData =  data->GetSpellPositionData->GetData();
            DedbgA("%d|%x|%x|%s|%s|%s|%s", slot, GetSpellPositionData->SourceIndex, GetSpellPositionData->TargetIndex, 
                GetSpellPositionData->PlayerPosition.ToString().c_str(), 
                GetSpellPositionData->TargetPosition.ToString().c_str(), 
                GetSpellPositionData->MousePosition.ToString().c_str(), 
                GetSpellPositionData->MousePosition2.ToString().c_str()
            );

			float v_time_now = Common::GetInstance()->TickCount();
			const auto v_time_interval = v_time_now - Ace_Patch::CastSpellTick[(int)slot];
			float limit_rate = 300;
			if (v_time_interval < limit_rate)
			{
				return false;
			}

            if (Ace_Patch::IsInit())
            {
                if (!Ace_Patch::AceHudCastSpell((int)slot, data->GetSpellPositionData->GetData()))
                {
                    return false;
                }
                Ace_Patch::CastSpellTick[(int)slot] = v_time_now;
                return true;
            }
            else
            {
                DedbgA("IsInit");
            }
        }
        else
        {
            DedbgA("data");
        }

        return false;
    }


    bool __fastcall HookUpdateChargedSpell(void* this_, void* spellInst, int slot, void* pos, bool bForceStop)
    {
        auto r = base::fast_call<uintptr_t>(DEFINE_RVA(Offsets::Functions::UpdateChargeableSpell), this_, spellInst, slot, pos, bForceStop);
        if(bForceStop)
        {
  
            Ace_Patch::AceHudOnUpdateCheck(slot);
        }
        return r;

    }

    SHORT WINAPI HookGetKeyState(_In_ int vKey)
    {
        if (vKey == 'Z' || vKey == 'X' || vKey == 'C' || vKey == 'V')
        {
			USHORT key_scan = MapVirtualKey(vKey, 0);
			bool is_down = false;
			if (umc::send_request(umc::code_keyboard_check_filter_key, &key_scan, sizeof(key_scan), &is_down, sizeof(bool)))
			{
				if (is_down)
				{
					//g_Log->Log("Mixed");
					return 0x8000;
				}
                else
                {
                    return 0;
                }
			}
        }

        return GetAsyncKeyState(vKey);
    }

    void LoadBot()
    {
        struct bypass_load_data
        {
            void* bot_module;
            char bot_directory[MAX_PATH];
            char bot_user[40];

            // same as GetAsyncKeyState
            void* fn_get_key_state;

            // should return TRUE if calling successfully
            // bool __fastcall IssueOrder(void* this_, int order, void* pos, void* target, int isAttackMove, int isPetMove, int unknown0)
            void* fn_issue_order;

            // should return TRUE if calling successfully
            // bool __fastcall SendSpellCastPacket(void* this_, void* spellDataClient)
            void* fn_cast_spell;

            // should return TRUE if calling successfully
            // bool __fastcall UpdateChargedSpell(void* this_, void* spellInst, int slot, void* pos, int bForceStop)
            void* fn_update_spell;

            // the internal configer
            bool use_configer;

            // reserved and dont use
            bool reserved_0[7];
            void* reserved_1;
            void* reserved_2;
            void* reserved_3;
            void* reserved_4;
        } request = {};

		char abot_path[MAX_PATH] = { };
		Utils::r_ini(ens_a("hanbot_path"), abot_path, "");

		char abot_key[40] = {};
        Utils::r_ini(ens_a("hanbot_key"), abot_key, "");

        std::string bot_path = abot_path;
        auto wbot_path = Utils::string_to_wstring(bot_path);
   
		auto bot_core = bot_path + ens_a("core_cn.dll");

		auto config_ini = bot_path + ens_a("config.ini");

        std::wstring hanbot_core_path = Utils::string_to_wstring(bot_core);

        size_t core_size = 0;
        void * core_buff =  Utils::file::read_file(hanbot_core_path, &core_size);
        if (core_buff)
        {
            /*GETPROCESSHEAP pGetProcessHeap = (GETPROCESSHEAP)GetFunctionAddress(IsModulePresent(L"Kernel32.dll"), "GetProcessHeap");
            HEAPFREE pHeapFree = (HEAPFREE)GetFunctionAddress(IsModulePresent(L"Kernel32.dll"), "HeapFree");*/

#ifndef DEVELOPER 
			//°µ×°
			if ((permit::g_dumyArray[200] ^ permit::g_dumyArray[201]) != ((uintptr_t)permit::g_dumyArray & 0x7fffffff))
			{
				while (1) {};
			}
#endif
			//ÐÞ¸Äini£¬½ûÖ¹¸üÐÂ
			//WritePrivateProfileStringA(("app"), "auto_update", "0", config_ini.c_str());
					// free the reserved memory and let core take it.

			if (g_ReservedMemory)
			{
                DedbgA("ÊÍ·Åg_ReservedMemory");
				VirtualFree(g_ReservedMemory, 0, MEM_RELEASE);
				//g_ReservedMemory = NULL;
		    }

            PDARKMODULE DarkModule = DarkLoadLibrary(
                LOAD_MEMORY | NO_LINK,
                (LPWSTR)hanbot_core_path.data(),
                core_buff,
                core_size,
                (LPWSTR)hanbot_core_path.data()
            );


            //ProtectHanbotLuaMemory();
            if (!DarkModule->bSuccess)
            {
                Utils::msg::error_msg("error", 10);
                //pHeapFree(pGetProcessHeap(), 0, DarkModule->ErrorMsg);
                //pHeapFree(pGetProcessHeap(), 0, DarkModule);
                return;
            }

            free(core_buff);

            request.bot_module = (void*)DarkModule->ModuleBase;
			strcpy_s(request.bot_directory, abot_path); // the directory ends with "\"
			strcpy_s(request.bot_user, abot_key);

            request.fn_issue_order = HookIssueOrder;
            request.fn_cast_spell = HookSendSpellCastPacket;
            request.fn_update_spell = HookUpdateChargedSpell;

			USHORT keyz = MapVirtualKey('Z', 0);
			umc::send_request(umc::code_keyboard_add_filter_key, &keyz, sizeof(keyz));

            USHORT keyx = MapVirtualKey('X', 0);
			umc::send_request(umc::code_keyboard_add_filter_key, &keyx, sizeof(keyx));

			USHORT keyc = MapVirtualKey('C', 0);
			umc::send_request(umc::code_keyboard_add_filter_key, &keyc, sizeof(keyc));

			USHORT keyv = MapVirtualKey('V', 0);
			umc::send_request(umc::code_keyboard_add_filter_key, &keyv, sizeof(keyv));

            request.fn_get_key_state = HookGetKeyState;

            char setupName[] = "setup";  // Array olduğundan değiştirilebilir
            auto pStartRoutine = GetFunctionAddress((HMODULE)DarkModule->ModuleBase, setupName);
            if (!pStartRoutine)
            {
				Utils::msg::error_msg(ens_a("error"), 165);
				__fastfail(0);
            }

            reinterpret_cast<int(_cdecl*)(PVOID, DWORD_PTR, DWORD_PTR, DWORD_PTR)>(pStartRoutine)(&request, 0, 0, 0);
        }
		else
		{
			Utils::msg::error_msg(ens_a("error"), 15);
			__fastfail(0);
		}
    }

    DWORD BotInit(_In_ PVOID ThreadParameter) {

        while (!Ace_Patch::IsInit())
        {
            Sleep(500);
        }

        EventHooks::ApplyHooks();

		while (!Common::GetInstance()->IsGameReady())
		{
			Sleep(500);
		}

        Sleep(3000);

		if (Ace_Patch::g_base64_info.base_address && Ace_Patch::AceInitKey())
		{
			Common::GetInstance()->PrintChat(u8"[Ä§Í¯HANBOT] ¼ÓÔØ³É¹¦", 0xe0f030);
		}
		else
		{
			Common::GetInstance()->PrintChat(u8"[Ä§Í¯HANBOT] ¼ÓÔØÊ§°Ü", 0xf03030);
		}

        return 0;
    }

}
