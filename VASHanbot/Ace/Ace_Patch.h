#pragma once
#include "../BotSDK.h"
#include "../Utils/Utils.h"




#define GameDebug 0
#define IS_ACE	 //ÊÇ·ñ·À·â

#ifdef IS_ACE
#define ISSUEORDER_TICK 100.f
#else
#define ISSUEORDER_TICK 30.f
#endif

namespace umc
{
	enum
	{
		code_check_exist = 1,

		code_keyboard_on = 100,
		code_keyboard_off = 101,
		code_keyboard_add_filter_key = 102,
		code_keyboard_remove_filter_key = 103,
		code_keyboard_check_filter_key = 104,
		code_keyboard_check_pause = 105,
		code_keyboard_check_resume = 106,
		code_keyboard_sendinput_down = 107,
		code_keyboard_sendinput_up = 108,
		code_keyboard_sendinput_init = 109,
		code_keyboard_set_kbdclass_rva = 110,

		code_monitor_inject_on = 200,
		code_monitor_inject_off = 201,
		code_monitor_inject_set_dll_x86 = 202,
		code_monitor_inject_set_dll_x64_cn = 203,
		code_monitor_inject_set_dll_x64_riot = 204,
		code_monitor_inject_state = 205,

		code_acebypass_check = 300,
		code_acebypass_on = 301,
		code_acebypass_off = 302,
		code_acebypass_patch = 303,
		code_acebypass_unpatch = 304,

		code_util_protect_memory = 400,
		code_util_write_memory = 401,
		code_util_unlock_protect = 402,
		code_util_create_thread = 403,
		code_util_remove_vad = 404,
		code_util_clean_unloaded_drivers = 405,

		code_protect_add_driver = 500,
		code_protect_remove_driver = 501,
		code_protect_add_process = 502,
		code_protect_remove_process = 503,
		code_protect_add_file = 504,
		code_protect_remove_file = 505,
		code_protect_add_whitelist = 506,
		code_protect_remove_whitelist = 507,
		code_protect_add_memory = 508,
		code_protect_remove_memory = 509,
	};

	enum protect_type
	{
		READ_VIRTUAL_MEMORY = 0,
		QUERY_VIRTUAL_MEMORY = 1,
	};

	bool send_request(int code, void* in_buffer, size_t in_size, void* out_buffer = nullptr, size_t out_size = 0);
	bool write_process_memory(uint32_t pid, void* addr, void* buffer, size_t size);
	bool unlock_protect(uint32_t pid, uintptr_t address);
	bool create_thread(uint32_t pid, uintptr_t routine, uintptr_t param);
	bool remove_vad(uint32_t pid, uintptr_t address);

	void protect_add_driver(std::string driver_name);
	void protect_remove_driver(std::string driver_name);
	void protect_add_file(std::wstring file_name);
	void protect_remove_file(std::wstring file_name);
	void protect_add_process(ULONG64 pid);
	void protect_remove_process(ULONG64 pid);
	void protect_add_whitelist(ULONG64 pid);
	void protect_remove_whitelist(ULONG64 pid);
	void protect_add_memory(int pid, ULONG64 addr, ULONG64 size, protect_type p_type);
	void protect_remove_memory(int pid, ULONG64 addr, ULONG64 size, protect_type p_type);
}


extern "C" void NewIssueOrder();
extern "C" void NewCastSpell();
extern "C" void NewSmoothPath();
extern "C" void NewRpcsCallBack();

namespace Ace_Patch
{


	extern float LastMoveTick;


	extern bool limit_mode;
	extern int debug_mode;

	struct DllInfo {
		uintptr_t DllBase;
		uintptr_t DllSize;
	};

	struct PatchDllInfo {
		uintptr_t     pid;
		uintptr_t     module_size;
		DllInfo list[1000];
	};

	extern PatchDllInfo* g_DllInfo;

	enum spell_slot
	{
		Q,
		W,
		E,
		R,
		D,
		F,
		n1,
		n2,
		n3,
		n4,
		n5,
		n6,
		n7
	};
	class Imsg_info
	{

	public:
		int slot;
		WPARAM w_param;
		LPARAM l_param;
		UINT u_msg;
		Imsg_info() = default;
		Imsg_info(BYTE state, int _slot);
	};




	extern Utils::module_info g_bot_info;
	extern Utils::module_info g_game_info;
	extern Utils::module_info g_base64_info;
	extern Utils::module_info g_pbc_game64_info;
	extern Utils::module_info g_ats64_info;
	extern Utils::module_info g_csi64_info;
	extern Utils::module_info g_drv64_info;
	extern uintptr_t  dwVMTCrcBase;
	//extern uintptr_t  dwVMTCsi64Base;
	//extern uintptr_t  dwVMTAts64Base;

	enum class OFFSET_PBC64 : uintptr_t
	{
		evtPbcGame64WndProc = 0x56280,
		evtMoveCallRpcs = 0x6C810,
		evtCastSpellCallRpcs = 0x4EF30,

		NewIssueOrder = 0x140221963,
		NewCastSpell = 0x14073A79F,
		NewSmoothPath = 0x1402BF35E,
	};


	void AddModuleInfo(const DllInfo& info);
	void DelModuleInfo(uintptr_t mod_base);

	struct hooked_info
	{
		uintptr_t addr;
		size_t code_size;
		unsigned char org_code_buf[16];
	};

	extern std::vector<hooked_info*> hooked_list;
	void AddToHookedList(uintptr_t addr, size_t code_size);
	void CopyFixedHookedList(Utils::module_info mod_info, void* buffer, size_t MaxCount, size_t mod_offset);

	struct spell_info
	{
		int slot;
		bool is_down;
		bool is_set;
		Vector3 mouse1;
		Vector3 mouse2;
	};

	extern float CastSpellTick[14];
	extern spell_info CastSpellInfo[14];

	bool AceMouseMessage(const Vector3& position, IssueOrderType order);
	bool AceKeyMessage(int slot);
	bool AceHudCastSpell(int slot, TargetingClientData* ClientData);

	bool AceHudUpdateChargeableSpell(int slot, Vector3 position, bool ReleaseCast);
	void AceHudOnUpdateCheck(int slot);
	int AceHudKbdEvent(uintptr_t HudThisPtr, SpellSlot slot, int mode, int state);
	void AceKeyDown(UINT v_key);
	void AceKeyUp(UINT v_key);
	bool AceInitKey();
	void AceResetKey(std::string event_name, UINT val);
	bool AceEvadeFilter(Vector3 point);
	void AceUnhookPatch();

	bool IsInit();
	bool Initialize(HMODULE patch_module);

	bool CreateFakeThread(std::string module, void* routine);

	bool ProtectMemory(uintptr_t address, size_t size, uint32_t NewProtection, uint32_t* oldProtection = 0);

#define PAGE_SIZE       4096
#define PAGE_ALIGN(Va)  ((PVOID)((ULONG_PTR)(Va) & ~(PAGE_SIZE - 1)))

#if defined(VT_EPT)
	void hide_text_section(PVOID h_module);
	void add_ept(uintptr_t addr);
	void FlushAndLockPage(void* start_address);
	void ru_add_hook(UINT64 PageRead, UINT64 PageExecute);
#endif
}