#pragma once
#include <windows.h>
#include <xmmintrin.h>



class AceHookContext
{
public:
	ULONG_PTR CustomArg1;
	ULONG_PTR CustomArg2;
	__m128 xmm3;
	__m128 xmm2;
	__m128 xmm1;
	__m128 xmm0;
	ULONG_PTR rflag;
	ULONG_PTR r15;
	ULONG_PTR r14;
	ULONG_PTR r13;
	ULONG_PTR r12;
	ULONG_PTR r11;
	ULONG_PTR r10;
	ULONG_PTR r9;
	ULONG_PTR r8;
	ULONG_PTR rdi;
	ULONG_PTR rsi;
	ULONG_PTR rbp;
	ULONG_PTR rdx;
	ULONG_PTR rcx;
	ULONG_PTR rbx;
	ULONG_PTR rax;
	ULONG_PTR rsp;
};

class AceHookChain
{
public:
	AceHookChain* Next;
	ULONG_PTR unk;
	ULONG_PTR CustomArg1;
	ULONG_PTR CustomArg2;
	PVOID HookHandler;
};

class AceHookInfo
{
public:
	PVOID OriginalFunction;
	ULONG_PTR TrampolineBegin;
	ULONG_PTR TrampolineEnd;//the address of "C3 ret" + 1
	AceHookChain* HookChain;
};

typedef void(__fastcall* AceCallBack)(AceHookContext*);


class ace_hook
{


public:
	ace_hook() = default;
	ace_hook(bool is_func_hook)
	{
		func_hook = is_func_hook;
	}
	~ace_hook();

	bool install(uintptr_t pointer_ptr, AceCallBack detour);
	void set_hook_type(bool is_func_hook)
	{
		func_hook = is_func_hook;
	}
	bool uninstall();

	bool vmt_hook(uintptr_t address, AceCallBack call_back_func);

	AceCallBack vmt_orgfunc;

private:

	struct hook_info {
		uintptr_t pointer_ptr;
		uintptr_t  detour;
		uintptr_t hook;
		uintptr_t* org;
	};

	hook_info hi;
	bool func_hook;
};


