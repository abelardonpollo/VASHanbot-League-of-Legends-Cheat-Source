.code



EXTERN real_NewIssueOrder :dq

NewIssueOrder proc
	mov qword ptr [rsp+20h],r9
	mov qword ptr [rsp+18h],r8
	push rbp
	push rsi
	push rdi
	push r13
	push r14
	push r15
	jmp [real_NewIssueOrder]

NewIssueOrder endp





EXTERN real_NewCastSpell :dq

NewCastSpell proc
    mov     rax, rsp
	mov     [rax+20h], r9
	push rbp
	push rbx
	push r12
	push r13
	push r15
	jmp [real_NewCastSpell]

NewCastSpell endp





EXTERN real_NewSmoothPath :dq

NewSmoothPath proc
	mov qword ptr [rsp+8],rbx
	mov qword ptr [rsp+10h],rsi
	push rdi
	sub rsp,30h
	mov rsi,rcx
	mov rbx,rdx
	jmp [real_NewSmoothPath]

NewSmoothPath endp





EXTERN real_RpcsCallBack :dq
EXTERN real_RpcsAceHookInfoPtr :dq

NewRpcsCallBack proc
	call fixup;
fixup:
	lea rsp, qword ptr [rsp+8h];
	push rsp
    push rax
    push rbx
    push rcx
    push rdx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    pushfq
    sub rsp,40h
	movups xmmword ptr [rsp+30h], xmm0
	movups xmmword ptr [rsp+20h], xmm1
	movups xmmword ptr [rsp+10h], xmm2
	movups xmmword ptr [rsp], xmm3
	mov rax, 0h
	push rax
	mov rax, 0h
	push rax
	mov rcx, [real_RpcsAceHookInfoPtr]
	lea rdx, qword ptr [rsp]
	test rsp, 08h
	jz tab_a
	mov rax, 0FEDCBA9876543210h
	push rax
tab_a:
	sub rsp, 20h
	mov rax, [real_RpcsCallBack]
	call rax
	add rsp, 20h
	mov rax, 0FEDCBA9876543210h
	cmp qword ptr [rsp], rax
	jnz tab_b
	pop rax
tab_b:
	add rsp, 10h
	movups xmm3, xmmword ptr [rsp]
	movups xmm2, xmmword ptr [rsp+10h]
	movups xmm1, xmmword ptr [rsp+20h]
	movups xmm0, xmmword ptr [rsp+30h]
	add rsp, 40h
	popfq
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rdx
    pop rcx
    pop rbx
    pop rax
    pop rsp
	ret



NewRpcsCallBack endp


end





