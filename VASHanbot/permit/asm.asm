.CODE

auth_xxx PROC

	mov eax, 1;
	cpuid;
	nop;
	rdtsc;
	ret;

auth_xxx ENDP

auth_get_rsp PROC

	xor		rax, rax;
	mov		rdx, rdx;
	mov		rax, rsp;
	ret;

auth_get_rsp ENDP

auth_get_teb_tlsp PROC

	mov     rax, qword ptr gs : [030h] ;
	mov     rax, qword ptr[rax + 058h];
	ret;

auth_get_teb_tlsp ENDP

auth_get_teb_pid PROC

	mov     rax, qword ptr gs : [030h] ;
	mov     rax, qword ptr[rax + 040h];
	ret;

auth_get_teb_pid ENDP

auth_get_teb_tid PROC

	mov     rax, qword ptr gs : [030h] ;
	mov     rax, qword ptr[rax + 048h];
	ret;

auth_get_teb_tid ENDP

auth_get_peb_osver PROC

	mov     rdx, qword ptr gs : [060h]; 
	xor		rax, rax;
	mov     eax, dword ptr[rdx + 0124h];  //PEB.OSPlatformId
	movzx   rcx, word ptr[rdx + 0120h];   //PEB.OSBuildNumber
	xor		rax, 0FFFFFFFFFFFFFFFEh;  //PEB.OSPlatformId ^ 0xFFFFFFFE
	shl     rax, 0Eh;     //
	or		rax, rcx;
	shl     rax, 08h;
	or		eax, dword ptr[rdx + 011Ch];     //OSMinorVersion
	shl     rax, 08h;
	or		eax, dword ptr[rdx + 0118h];  //OSMajorVersion
	ret;

auth_get_peb_osver ENDP

END