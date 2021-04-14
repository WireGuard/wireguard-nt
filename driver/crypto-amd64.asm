; SPDX-License-Identifier: GPL-2.0 OR MIT
;
; Copyright (C) 2006-2020 Andy Polyakov <appro@cryptogams.org>.
; Copyright (C) 2015-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
;
; This is a modified version of:
;     https://github.com/dot-asm/cryptogams/blob/master/x86_64/chacha-x86_64.pl
;     https://github.com/dot-asm/cryptogams/blob/master/x86_64/poly1305-x86_64.pl
;

OPTION	DOTNAME
.text$	SEGMENT ALIGN(256) 'CODE'
EXTERN	__imp_RtlVirtualUnwind:NEAR

ALIGN	64
$L$zero::
	DD	0,0,0,0
$L$one::
	DD	1,0,0,0
$L$inc::
	DD	0,1,2,3
$L$four::
	DD	4,4,4,4
$L$incy::
	DD	0,2,4,6,1,3,5,7
$L$eight::
	DD	8,8,8,8,8,8,8,8
$L$rot16::
DB	02h,03h,00h,01h,06h,07h,04h,05h,0ah,0bh,08h,09h,0eh,0fh,0ch,0dh
$L$rot24::
DB	03h,00h,01h,02h,07h,04h,05h,06h,0bh,08h,09h,0ah,0fh,0ch,0dh,0eh
$L$twoy::
	DD	2,0,0,0,2,0,0,0
ALIGN	64
$L$zeroz::
	DD	0,0,0,0,1,0,0,0,2,0,0,0,3,0,0,0
$L$fourz::
	DD	4,0,0,0,4,0,0,0,4,0,0,0,4,0,0,0
$L$incz::
	DD	0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
$L$sixteen::
	DD	16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16
$L$sigma::
DB	101,120,112,97,110,100,32,51,50,45,98,121,116,101,32,107
DB	0
PUBLIC	ChaCha20ALU

ALIGN	64
ChaCha20ALU	PROC PUBLIC
	DB	243,15,30,250
	mov	QWORD PTR[8+rsp],rdi	;WIN64 prologue
	mov	QWORD PTR[16+rsp],rsi
	mov	rax,rsp
$L$SEH_begin_chacha20_ctr32::
	mov	rdi,rcx
	mov	rsi,rdx
	mov	rdx,r8
	mov	rcx,r9
	mov	r8,QWORD PTR[40+rsp]
	cmp	rdx,0
	je	$L$chacha20_no_data
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	sub	rsp,64+24

$L$ctr32_body::
	mov	rbp,rdx
	mov	r12,QWORD PTR[rcx]
	mov	r13,QWORD PTR[8+rcx]
	mov	r14,QWORD PTR[16+rcx]
	mov	r15,QWORD PTR[24+rcx]
	mov	rax,QWORD PTR[r8]
	mov	rdx,QWORD PTR[8+r8]
	mov	QWORD PTR[16+rsp],r12
	mov	QWORD PTR[24+rsp],r13
	mov	QWORD PTR[rsp],r14
	mov	QWORD PTR[8+rsp],r15
	mov	QWORD PTR[48+rsp],rax
	mov	QWORD PTR[56+rsp],rdx
	jmp	$L$chacha20_loop_outer

ALIGN	32
$L$chacha20_loop_outer::
	mov	eax,061707865h
	mov	ebx,03320646eh
	mov	ecx,079622d32h
	mov	edx,06b206574h
	mov	r8d,DWORD PTR[16+rsp]
	mov	r9d,DWORD PTR[20+rsp]
	mov	r10d,DWORD PTR[24+rsp]
	mov	r11d,DWORD PTR[28+rsp]
	mov	r12d,DWORD PTR[48+rsp]
	mov	r13d,DWORD PTR[52+rsp]
	mov	r14d,DWORD PTR[56+rsp]
	mov	QWORD PTR[40+rsp],r15
	mov	r15d,DWORD PTR[60+rsp]
	mov	QWORD PTR[((64+0))+rsp],rbp
	mov	QWORD PTR[((64+8))+rsp],rsi
	mov	esi,DWORD PTR[rsp]
	mov	QWORD PTR[((64+16))+rsp],rdi
	mov	edi,DWORD PTR[4+rsp]
	mov	ebp,10
	jmp	$L$chacha20_loop

ALIGN	32
$L$chacha20_loop::
	add	eax,r8d
	xor	r12d,eax
	rol	r12d,16
	add	ebx,r9d
	xor	r13d,ebx
	rol	r13d,16
	add	esi,r12d
	xor	r8d,esi
	rol	r8d,12
	add	edi,r13d
	xor	r9d,edi
	rol	r9d,12
	add	eax,r8d
	xor	r12d,eax
	rol	r12d,8
	add	ebx,r9d
	xor	r13d,ebx
	rol	r13d,8
	add	esi,r12d
	xor	r8d,esi
	rol	r8d,7
	add	edi,r13d
	xor	r9d,edi
	rol	r9d,7
	mov	DWORD PTR[32+rsp],esi
	mov	DWORD PTR[36+rsp],edi
	mov	esi,DWORD PTR[40+rsp]
	mov	edi,DWORD PTR[44+rsp]
	add	ecx,r10d
	xor	r14d,ecx
	rol	r14d,16
	add	edx,r11d
	xor	r15d,edx
	rol	r15d,16
	add	esi,r14d
	xor	r10d,esi
	rol	r10d,12
	add	edi,r15d
	xor	r11d,edi
	rol	r11d,12
	add	ecx,r10d
	xor	r14d,ecx
	rol	r14d,8
	add	edx,r11d
	xor	r15d,edx
	rol	r15d,8
	add	esi,r14d
	xor	r10d,esi
	rol	r10d,7
	add	edi,r15d
	xor	r11d,edi
	rol	r11d,7
	add	eax,r9d
	xor	r15d,eax
	rol	r15d,16
	add	ebx,r10d
	xor	r12d,ebx
	rol	r12d,16
	add	esi,r15d
	xor	r9d,esi
	rol	r9d,12
	add	edi,r12d
	xor	r10d,edi
	rol	r10d,12
	add	eax,r9d
	xor	r15d,eax
	rol	r15d,8
	add	ebx,r10d
	xor	r12d,ebx
	rol	r12d,8
	add	esi,r15d
	xor	r9d,esi
	rol	r9d,7
	add	edi,r12d
	xor	r10d,edi
	rol	r10d,7
	mov	DWORD PTR[40+rsp],esi
	mov	DWORD PTR[44+rsp],edi
	mov	esi,DWORD PTR[32+rsp]
	mov	edi,DWORD PTR[36+rsp]
	add	ecx,r11d
	xor	r13d,ecx
	rol	r13d,16
	add	edx,r8d
	xor	r14d,edx
	rol	r14d,16
	add	esi,r13d
	xor	r11d,esi
	rol	r11d,12
	add	edi,r14d
	xor	r8d,edi
	rol	r8d,12
	add	ecx,r11d
	xor	r13d,ecx
	rol	r13d,8
	add	edx,r8d
	xor	r14d,edx
	rol	r14d,8
	add	esi,r13d
	xor	r11d,esi
	rol	r11d,7
	add	edi,r14d
	xor	r8d,edi
	rol	r8d,7
	dec	ebp
	jnz	$L$chacha20_loop
	add	esi,DWORD PTR[rsp]
	add	edi,DWORD PTR[4+rsp]
	mov	rbp,QWORD PTR[64+rsp]
	mov	DWORD PTR[32+rsp],esi
	mov	rsi,QWORD PTR[((64+8))+rsp]
	mov	DWORD PTR[36+rsp],edi
	mov	rdi,QWORD PTR[((64+16))+rsp]
	add	eax,061707865h
	add	ebx,03320646eh
	add	ecx,079622d32h
	add	edx,06b206574h
	add	r8d,DWORD PTR[16+rsp]
	add	r9d,DWORD PTR[20+rsp]
	add	r10d,DWORD PTR[24+rsp]
	add	r11d,DWORD PTR[28+rsp]
	add	r12d,DWORD PTR[48+rsp]
	add	r13d,DWORD PTR[52+rsp]
	add	r14d,DWORD PTR[56+rsp]
	add	r15d,DWORD PTR[60+rsp]
	cmp	rbp,64
	jb	$L$tail
	xor	eax,DWORD PTR[rsi]
	xor	ebx,DWORD PTR[4+rsi]
	xor	ecx,DWORD PTR[8+rsi]
	xor	edx,DWORD PTR[12+rsi]
	mov	DWORD PTR[rdi],eax
	mov	eax,DWORD PTR[32+rsp]
	mov	DWORD PTR[4+rdi],ebx
	mov	ebx,DWORD PTR[36+rsp]
	mov	DWORD PTR[8+rdi],ecx
	mov	ecx,DWORD PTR[40+rsp]
	mov	DWORD PTR[12+rdi],edx
	mov	edx,DWORD PTR[44+rsp]
	xor	r8d,DWORD PTR[16+rsi]
	add	ecx,DWORD PTR[8+rsp]
	xor	r9d,DWORD PTR[20+rsi]
	add	edx,DWORD PTR[12+rsp]
	xor	r10d,DWORD PTR[24+rsi]
	xor	r11d,DWORD PTR[28+rsi]
	xor	eax,DWORD PTR[32+rsi]
	xor	ebx,DWORD PTR[36+rsi]
	xor	ecx,DWORD PTR[40+rsi]
	xor	edx,DWORD PTR[44+rsi]
	xor	r12d,DWORD PTR[48+rsi]
	xor	r13d,DWORD PTR[52+rsi]
	xor	r14d,DWORD PTR[56+rsi]
	xor	r15d,DWORD PTR[60+rsi]
	lea	rsi,QWORD PTR[64+rsi]
	add	DWORD PTR[48+rsp],1
	mov	DWORD PTR[16+rdi],r8d
	mov	DWORD PTR[20+rdi],r9d
	mov	DWORD PTR[24+rdi],r10d
	mov	DWORD PTR[28+rdi],r11d
	mov	DWORD PTR[32+rdi],eax
	mov	DWORD PTR[36+rdi],ebx
	mov	DWORD PTR[40+rdi],ecx
	mov	DWORD PTR[44+rdi],edx
	mov	DWORD PTR[48+rdi],r12d
	mov	DWORD PTR[52+rdi],r13d
	mov	DWORD PTR[56+rdi],r14d
	mov	DWORD PTR[60+rdi],r15d
	lea	rdi,QWORD PTR[64+rdi]
	mov	r15,QWORD PTR[8+rsp]
	sub	rbp,64
	jnz	$L$chacha20_loop_outer
	jmp	$L$done

ALIGN	16
$L$tail::
	mov	DWORD PTR[rsp],eax
	mov	eax,DWORD PTR[8+rsp]
	mov	DWORD PTR[4+rsp],ebx
	mov	ebx,DWORD PTR[12+rsp]
	mov	DWORD PTR[8+rsp],ecx
	add	eax,DWORD PTR[40+rsp]
	mov	DWORD PTR[12+rsp],edx
	add	ebx,DWORD PTR[44+rsp]
	mov	DWORD PTR[16+rsp],r8d
	mov	DWORD PTR[20+rsp],r9d
	mov	DWORD PTR[24+rsp],r10d
	mov	DWORD PTR[28+rsp],r11d
	mov	DWORD PTR[40+rsp],eax
	mov	DWORD PTR[44+rsp],ebx
	xor	rbx,rbx
	mov	DWORD PTR[48+rsp],r12d
	mov	DWORD PTR[52+rsp],r13d
	mov	DWORD PTR[56+rsp],r14d
	mov	DWORD PTR[60+rsp],r15d

$L$chacha20_loop_tail::
	movzx	eax,BYTE PTR[rbx*1+rsi]
	movzx	edx,BYTE PTR[rbx*1+rsp]
	lea	rbx,QWORD PTR[1+rbx]
	xor	eax,edx
	mov	BYTE PTR[((-1))+rbx*1+rdi],al
	dec	rbp
	jnz	$L$chacha20_loop_tail

$L$done::
	lea	rsi,QWORD PTR[((64+24+48))+rsp]
	mov	r15,QWORD PTR[((-48))+rsi]
	mov	r14,QWORD PTR[((-40))+rsi]
	mov	r13,QWORD PTR[((-32))+rsi]
	mov	r12,QWORD PTR[((-24))+rsi]
	mov	rbp,QWORD PTR[((-16))+rsi]
	mov	rbx,QWORD PTR[((-8))+rsi]
	lea	rsp,QWORD PTR[rsi]

$L$chacha20_no_data::
	mov	rdi,QWORD PTR[8+rsp]	;WIN64 epilogue
	mov	rsi,QWORD PTR[16+rsp]
	DB	0F3h,0C3h		;repret

$L$SEH_end_chacha20_ctr32::
ChaCha20ALU	ENDP
PUBLIC	ChaCha20SSSE3

ALIGN	32
ChaCha20SSSE3	PROC PUBLIC
	DB	243,15,30,250
	mov	QWORD PTR[8+rsp],rdi	;WIN64 prologue
	mov	QWORD PTR[16+rsp],rsi
	mov	rax,rsp
$L$SEH_begin_chacha20_ssse3::
	mov	rdi,rcx
	mov	rsi,rdx
	mov	rdx,r8
	mov	rcx,r9
	mov	r8,QWORD PTR[40+rsp]

$L$chacha20_ssse3::
	mov	r10,rsp
	cmp	rdx,128
	je	$L$chacha20_128
	ja	$L$chacha20_4x

$L$do_sse3_after_all::
	sub	rsp,64+40
	and	rsp,-16
	movaps	XMMWORD PTR[(-40)+r10],xmm6
	movaps	XMMWORD PTR[(-24)+r10],xmm7
$L$ssse3_body::
	movdqa	xmm0,XMMWORD PTR[$L$sigma]
	movdqu	xmm1,XMMWORD PTR[rcx]
	movdqu	xmm2,XMMWORD PTR[16+rcx]
	movdqu	xmm3,XMMWORD PTR[r8]
	movdqa	xmm6,XMMWORD PTR[$L$rot16]
	movdqa	xmm7,XMMWORD PTR[$L$rot24]
	movdqa	XMMWORD PTR[rsp],xmm0
	movdqa	XMMWORD PTR[16+rsp],xmm1
	movdqa	XMMWORD PTR[32+rsp],xmm2
	movdqa	XMMWORD PTR[48+rsp],xmm3
	mov	r8,10
	jmp	$L$chacha20_loop_ssse3

ALIGN	32
$L$chacha20_loop_outer_ssse3::
	movdqa	xmm3,XMMWORD PTR[$L$one]
	movdqa	xmm0,XMMWORD PTR[rsp]
	movdqa	xmm1,XMMWORD PTR[16+rsp]
	movdqa	xmm2,XMMWORD PTR[32+rsp]
	paddd	xmm3,XMMWORD PTR[48+rsp]
	mov	r8,10
	movdqa	XMMWORD PTR[48+rsp],xmm3
	jmp	$L$chacha20_loop_ssse3

ALIGN	32
$L$chacha20_loop_ssse3::
	paddd	xmm0,xmm1
	pxor	xmm3,xmm0
DB	102,15,56,0,222
	paddd	xmm2,xmm3
	pxor	xmm1,xmm2
	movdqa	xmm4,xmm1
	psrld	xmm1,20
	pslld	xmm4,12
	por	xmm1,xmm4
	paddd	xmm0,xmm1
	pxor	xmm3,xmm0
DB	102,15,56,0,223
	paddd	xmm2,xmm3
	pxor	xmm1,xmm2
	movdqa	xmm4,xmm1
	psrld	xmm1,25
	pslld	xmm4,7
	por	xmm1,xmm4
	pshufd	xmm2,xmm2,78
	pshufd	xmm1,xmm1,57
	pshufd	xmm3,xmm3,147
	nop
	paddd	xmm0,xmm1
	pxor	xmm3,xmm0
DB	102,15,56,0,222
	paddd	xmm2,xmm3
	pxor	xmm1,xmm2
	movdqa	xmm4,xmm1
	psrld	xmm1,20
	pslld	xmm4,12
	por	xmm1,xmm4
	paddd	xmm0,xmm1
	pxor	xmm3,xmm0
DB	102,15,56,0,223
	paddd	xmm2,xmm3
	pxor	xmm1,xmm2
	movdqa	xmm4,xmm1
	psrld	xmm1,25
	pslld	xmm4,7
	por	xmm1,xmm4
	pshufd	xmm2,xmm2,78
	pshufd	xmm1,xmm1,147
	pshufd	xmm3,xmm3,57
	dec	r8
	jnz	$L$chacha20_loop_ssse3
	paddd	xmm0,XMMWORD PTR[rsp]
	paddd	xmm1,XMMWORD PTR[16+rsp]
	paddd	xmm2,XMMWORD PTR[32+rsp]
	paddd	xmm3,XMMWORD PTR[48+rsp]
	cmp	rdx,64
	jb	$L$tail_ssse3
	movdqu	xmm4,XMMWORD PTR[rsi]
	movdqu	xmm5,XMMWORD PTR[16+rsi]
	pxor	xmm0,xmm4
	movdqu	xmm4,XMMWORD PTR[32+rsi]
	pxor	xmm1,xmm5
	movdqu	xmm5,XMMWORD PTR[48+rsi]
	lea	rsi,QWORD PTR[64+rsi]
	pxor	xmm2,xmm4
	pxor	xmm3,xmm5
	movdqu	XMMWORD PTR[rdi],xmm0
	movdqu	XMMWORD PTR[16+rdi],xmm1
	movdqu	XMMWORD PTR[32+rdi],xmm2
	movdqu	XMMWORD PTR[48+rdi],xmm3
	lea	rdi,QWORD PTR[64+rdi]
	sub	rdx,64
	jnz	$L$chacha20_loop_outer_ssse3
	jmp	$L$done_ssse3

ALIGN	16
$L$tail_ssse3::
	movdqa	XMMWORD PTR[rsp],xmm0
	movdqa	XMMWORD PTR[16+rsp],xmm1
	movdqa	XMMWORD PTR[32+rsp],xmm2
	movdqa	XMMWORD PTR[48+rsp],xmm3
	xor	r8,r8

$L$chacha20_loop_tail_ssse3::
	movzx	eax,BYTE PTR[r8*1+rsi]
	movzx	ecx,BYTE PTR[r8*1+rsp]
	lea	r8,QWORD PTR[1+r8]
	xor	eax,ecx
	mov	BYTE PTR[((-1))+r8*1+rdi],al
	dec	rdx
	jnz	$L$chacha20_loop_tail_ssse3

$L$done_ssse3::
	movaps	xmm6,XMMWORD PTR[((-40))+r10]
	movaps	xmm7,XMMWORD PTR[((-24))+r10]
	lea	rsp,QWORD PTR[r10]

$L$ssse3_epilogue::
	mov	rdi,QWORD PTR[8+rsp]	;WIN64 epilogue
	mov	rsi,QWORD PTR[16+rsp]
	DB	0F3h,0C3h		;repret

$L$SEH_end_chacha20_ssse3::
ChaCha20SSSE3	ENDP

ALIGN	32
chacha20_128	PROC PRIVATE
	DB	243,15,30,250
	mov	QWORD PTR[8+rsp],rdi	;WIN64 prologue
	mov	QWORD PTR[16+rsp],rsi
	mov	rax,rsp
$L$SEH_begin_chacha20_128::
	mov	rdi,rcx
	mov	rsi,rdx
	mov	rdx,r8
	mov	rcx,r9
	mov	r8,QWORD PTR[40+rsp]

$L$chacha20_128::
	mov	r10,rsp
	sub	rsp,64+104
	and	rsp,-16
	movaps	XMMWORD PTR[(-104)+r10],xmm6
	movaps	XMMWORD PTR[(-88)+r10],xmm7
	movaps	XMMWORD PTR[(-72)+r10],xmm8
	movaps	XMMWORD PTR[(-56)+r10],xmm9
	movaps	XMMWORD PTR[(-40)+r10],xmm10
	movaps	XMMWORD PTR[(-24)+r10],xmm11
$L$128_body::
	movdqa	xmm8,XMMWORD PTR[$L$sigma]
	movdqu	xmm9,XMMWORD PTR[rcx]
	movdqu	xmm2,XMMWORD PTR[16+rcx]
	movdqu	xmm3,XMMWORD PTR[r8]
	movdqa	xmm1,XMMWORD PTR[$L$one]
	movdqa	xmm6,XMMWORD PTR[$L$rot16]
	movdqa	xmm7,XMMWORD PTR[$L$rot24]
	movdqa	xmm10,xmm8
	movdqa	XMMWORD PTR[rsp],xmm8
	movdqa	xmm11,xmm9
	movdqa	XMMWORD PTR[16+rsp],xmm9
	movdqa	xmm0,xmm2
	movdqa	XMMWORD PTR[32+rsp],xmm2
	paddd	xmm1,xmm3
	movdqa	XMMWORD PTR[48+rsp],xmm3
	mov	r8,10
	jmp	$L$chacha20_loop_128

ALIGN	32
$L$chacha20_loop_128::
	paddd	xmm8,xmm9
	pxor	xmm3,xmm8
	paddd	xmm10,xmm11
	pxor	xmm1,xmm10
DB	102,15,56,0,222
DB	102,15,56,0,206
	paddd	xmm2,xmm3
	paddd	xmm0,xmm1
	pxor	xmm9,xmm2
	pxor	xmm11,xmm0
	movdqa	xmm4,xmm9
	psrld	xmm9,20
	movdqa	xmm5,xmm11
	pslld	xmm4,12
	psrld	xmm11,20
	por	xmm9,xmm4
	pslld	xmm5,12
	por	xmm11,xmm5
	paddd	xmm8,xmm9
	pxor	xmm3,xmm8
	paddd	xmm10,xmm11
	pxor	xmm1,xmm10
DB	102,15,56,0,223
DB	102,15,56,0,207
	paddd	xmm2,xmm3
	paddd	xmm0,xmm1
	pxor	xmm9,xmm2
	pxor	xmm11,xmm0
	movdqa	xmm4,xmm9
	psrld	xmm9,25
	movdqa	xmm5,xmm11
	pslld	xmm4,7
	psrld	xmm11,25
	por	xmm9,xmm4
	pslld	xmm5,7
	por	xmm11,xmm5
	pshufd	xmm2,xmm2,78
	pshufd	xmm9,xmm9,57
	pshufd	xmm3,xmm3,147
	pshufd	xmm0,xmm0,78
	pshufd	xmm11,xmm11,57
	pshufd	xmm1,xmm1,147
	paddd	xmm8,xmm9
	pxor	xmm3,xmm8
	paddd	xmm10,xmm11
	pxor	xmm1,xmm10
DB	102,15,56,0,222
DB	102,15,56,0,206
	paddd	xmm2,xmm3
	paddd	xmm0,xmm1
	pxor	xmm9,xmm2
	pxor	xmm11,xmm0
	movdqa	xmm4,xmm9
	psrld	xmm9,20
	movdqa	xmm5,xmm11
	pslld	xmm4,12
	psrld	xmm11,20
	por	xmm9,xmm4
	pslld	xmm5,12
	por	xmm11,xmm5
	paddd	xmm8,xmm9
	pxor	xmm3,xmm8
	paddd	xmm10,xmm11
	pxor	xmm1,xmm10
DB	102,15,56,0,223
DB	102,15,56,0,207
	paddd	xmm2,xmm3
	paddd	xmm0,xmm1
	pxor	xmm9,xmm2
	pxor	xmm11,xmm0
	movdqa	xmm4,xmm9
	psrld	xmm9,25
	movdqa	xmm5,xmm11
	pslld	xmm4,7
	psrld	xmm11,25
	por	xmm9,xmm4
	pslld	xmm5,7
	por	xmm11,xmm5
	pshufd	xmm2,xmm2,78
	pshufd	xmm9,xmm9,147
	pshufd	xmm3,xmm3,57
	pshufd	xmm0,xmm0,78
	pshufd	xmm11,xmm11,147
	pshufd	xmm1,xmm1,57
	dec	r8
	jnz	$L$chacha20_loop_128
	paddd	xmm8,XMMWORD PTR[rsp]
	paddd	xmm9,XMMWORD PTR[16+rsp]
	paddd	xmm2,XMMWORD PTR[32+rsp]
	paddd	xmm3,XMMWORD PTR[48+rsp]
	paddd	xmm1,XMMWORD PTR[$L$one]
	paddd	xmm10,XMMWORD PTR[rsp]
	paddd	xmm11,XMMWORD PTR[16+rsp]
	paddd	xmm0,XMMWORD PTR[32+rsp]
	paddd	xmm1,XMMWORD PTR[48+rsp]
	movdqu	xmm4,XMMWORD PTR[rsi]
	movdqu	xmm5,XMMWORD PTR[16+rsi]
	pxor	xmm8,xmm4
	movdqu	xmm4,XMMWORD PTR[32+rsi]
	pxor	xmm9,xmm5
	movdqu	xmm5,XMMWORD PTR[48+rsi]
	pxor	xmm2,xmm4
	movdqu	xmm4,XMMWORD PTR[64+rsi]
	pxor	xmm3,xmm5
	movdqu	xmm5,XMMWORD PTR[80+rsi]
	pxor	xmm10,xmm4
	movdqu	xmm4,XMMWORD PTR[96+rsi]
	pxor	xmm11,xmm5
	movdqu	xmm5,XMMWORD PTR[112+rsi]
	pxor	xmm0,xmm4
	pxor	xmm1,xmm5
	movdqu	XMMWORD PTR[rdi],xmm8
	movdqu	XMMWORD PTR[16+rdi],xmm9
	movdqu	XMMWORD PTR[32+rdi],xmm2
	movdqu	XMMWORD PTR[48+rdi],xmm3
	movdqu	XMMWORD PTR[64+rdi],xmm10
	movdqu	XMMWORD PTR[80+rdi],xmm11
	movdqu	XMMWORD PTR[96+rdi],xmm0
	movdqu	XMMWORD PTR[112+rdi],xmm1
	movaps	xmm6,XMMWORD PTR[((-104))+r10]
	movaps	xmm7,XMMWORD PTR[((-88))+r10]
	movaps	xmm8,XMMWORD PTR[((-72))+r10]
	movaps	xmm9,XMMWORD PTR[((-56))+r10]
	movaps	xmm10,XMMWORD PTR[((-40))+r10]
	movaps	xmm11,XMMWORD PTR[((-24))+r10]
	lea	rsp,QWORD PTR[r10]

$L$128_epilogue::
	mov	rdi,QWORD PTR[8+rsp]	;WIN64 epilogue
	mov	rsi,QWORD PTR[16+rsp]
	DB	0F3h,0C3h		;repret

$L$SEH_end_chacha20_128::
chacha20_128	ENDP

ALIGN	32
chacha20_4x	PROC PRIVATE
	DB	243,15,30,250
	mov	QWORD PTR[8+rsp],rdi	;WIN64 prologue
	mov	QWORD PTR[16+rsp],rsi
	mov	rax,rsp
$L$SEH_begin_chacha20_4x::
	mov	rdi,rcx
	mov	rsi,rdx
	mov	rdx,r8
	mov	rcx,r9
	mov	r8,QWORD PTR[40+rsp]

$L$chacha20_4x::
	mov	r10,rsp
	mov	r11,r9
	cmp	rdx,192
	ja	$L$proceed4x
	and	r11,71303168
	cmp	r11,4194304
	je	$L$do_sse3_after_all

$L$proceed4x::
	sub	rsp,0140h+168
	and	rsp,-16
	movaps	XMMWORD PTR[(-168)+r10],xmm6
	movaps	XMMWORD PTR[(-152)+r10],xmm7
	movaps	XMMWORD PTR[(-136)+r10],xmm8
	movaps	XMMWORD PTR[(-120)+r10],xmm9
	movaps	XMMWORD PTR[(-104)+r10],xmm10
	movaps	XMMWORD PTR[(-88)+r10],xmm11
	movaps	XMMWORD PTR[(-72)+r10],xmm12
	movaps	XMMWORD PTR[(-56)+r10],xmm13
	movaps	XMMWORD PTR[(-40)+r10],xmm14
	movaps	XMMWORD PTR[(-24)+r10],xmm15
$L$4x_body::
	movdqa	xmm11,XMMWORD PTR[$L$sigma]
	movdqu	xmm15,XMMWORD PTR[rcx]
	movdqu	xmm7,XMMWORD PTR[16+rcx]
	movdqu	xmm3,XMMWORD PTR[r8]
	lea	rcx,QWORD PTR[256+rsp]
	lea	r9,QWORD PTR[$L$rot16]
	lea	r11,QWORD PTR[$L$rot24]
	pshufd	xmm8,xmm11,000h
	pshufd	xmm9,xmm11,055h
	movdqa	XMMWORD PTR[64+rsp],xmm8
	pshufd	xmm10,xmm11,0aah
	movdqa	XMMWORD PTR[80+rsp],xmm9
	pshufd	xmm11,xmm11,0ffh
	movdqa	XMMWORD PTR[96+rsp],xmm10
	movdqa	XMMWORD PTR[112+rsp],xmm11
	pshufd	xmm12,xmm15,000h
	pshufd	xmm13,xmm15,055h
	movdqa	XMMWORD PTR[(128-256)+rcx],xmm12
	pshufd	xmm14,xmm15,0aah
	movdqa	XMMWORD PTR[(144-256)+rcx],xmm13
	pshufd	xmm15,xmm15,0ffh
	movdqa	XMMWORD PTR[(160-256)+rcx],xmm14
	movdqa	XMMWORD PTR[(176-256)+rcx],xmm15
	pshufd	xmm4,xmm7,000h
	pshufd	xmm5,xmm7,055h
	movdqa	XMMWORD PTR[(192-256)+rcx],xmm4
	pshufd	xmm6,xmm7,0aah
	movdqa	XMMWORD PTR[(208-256)+rcx],xmm5
	pshufd	xmm7,xmm7,0ffh
	movdqa	XMMWORD PTR[(224-256)+rcx],xmm6
	movdqa	XMMWORD PTR[(240-256)+rcx],xmm7
	pshufd	xmm0,xmm3,000h
	pshufd	xmm1,xmm3,055h
	paddd	xmm0,XMMWORD PTR[$L$inc]
	pshufd	xmm2,xmm3,0aah
	movdqa	XMMWORD PTR[(272-256)+rcx],xmm1
	pshufd	xmm3,xmm3,0ffh
	movdqa	XMMWORD PTR[(288-256)+rcx],xmm2
	movdqa	XMMWORD PTR[(304-256)+rcx],xmm3
	jmp	$L$chacha20_loop_enter4x

ALIGN	32
$L$chacha20_loop_outer4x::
	movdqa	xmm8,XMMWORD PTR[64+rsp]
	movdqa	xmm9,XMMWORD PTR[80+rsp]
	movdqa	xmm10,XMMWORD PTR[96+rsp]
	movdqa	xmm11,XMMWORD PTR[112+rsp]
	movdqa	xmm12,XMMWORD PTR[((128-256))+rcx]
	movdqa	xmm13,XMMWORD PTR[((144-256))+rcx]
	movdqa	xmm14,XMMWORD PTR[((160-256))+rcx]
	movdqa	xmm15,XMMWORD PTR[((176-256))+rcx]
	movdqa	xmm4,XMMWORD PTR[((192-256))+rcx]
	movdqa	xmm5,XMMWORD PTR[((208-256))+rcx]
	movdqa	xmm6,XMMWORD PTR[((224-256))+rcx]
	movdqa	xmm7,XMMWORD PTR[((240-256))+rcx]
	movdqa	xmm0,XMMWORD PTR[((256-256))+rcx]
	movdqa	xmm1,XMMWORD PTR[((272-256))+rcx]
	movdqa	xmm2,XMMWORD PTR[((288-256))+rcx]
	movdqa	xmm3,XMMWORD PTR[((304-256))+rcx]
	paddd	xmm0,XMMWORD PTR[$L$four]

$L$chacha20_loop_enter4x::
	movdqa	XMMWORD PTR[32+rsp],xmm6
	movdqa	XMMWORD PTR[48+rsp],xmm7
	movdqa	xmm7,XMMWORD PTR[r9]
	mov	eax,10
	movdqa	XMMWORD PTR[(256-256)+rcx],xmm0
	jmp	$L$chacha20_loop4x

ALIGN	32
$L$chacha20_loop4x::
	paddd	xmm8,xmm12
	paddd	xmm9,xmm13
	pxor	xmm0,xmm8
	pxor	xmm1,xmm9
DB	102,15,56,0,199
DB	102,15,56,0,207
	paddd	xmm4,xmm0
	paddd	xmm5,xmm1
	pxor	xmm12,xmm4
	pxor	xmm13,xmm5
	movdqa	xmm6,xmm12
	pslld	xmm12,12
	psrld	xmm6,20
	movdqa	xmm7,xmm13
	pslld	xmm13,12
	por	xmm12,xmm6
	psrld	xmm7,20
	movdqa	xmm6,XMMWORD PTR[r11]
	por	xmm13,xmm7
	paddd	xmm8,xmm12
	paddd	xmm9,xmm13
	pxor	xmm0,xmm8
	pxor	xmm1,xmm9
DB	102,15,56,0,198
DB	102,15,56,0,206
	paddd	xmm4,xmm0
	paddd	xmm5,xmm1
	pxor	xmm12,xmm4
	pxor	xmm13,xmm5
	movdqa	xmm7,xmm12
	pslld	xmm12,7
	psrld	xmm7,25
	movdqa	xmm6,xmm13
	pslld	xmm13,7
	por	xmm12,xmm7
	psrld	xmm6,25
	movdqa	xmm7,XMMWORD PTR[r9]
	por	xmm13,xmm6
	movdqa	XMMWORD PTR[rsp],xmm4
	movdqa	XMMWORD PTR[16+rsp],xmm5
	movdqa	xmm4,XMMWORD PTR[32+rsp]
	movdqa	xmm5,XMMWORD PTR[48+rsp]
	paddd	xmm10,xmm14
	paddd	xmm11,xmm15
	pxor	xmm2,xmm10
	pxor	xmm3,xmm11
DB	102,15,56,0,215
DB	102,15,56,0,223
	paddd	xmm4,xmm2
	paddd	xmm5,xmm3
	pxor	xmm14,xmm4
	pxor	xmm15,xmm5
	movdqa	xmm6,xmm14
	pslld	xmm14,12
	psrld	xmm6,20
	movdqa	xmm7,xmm15
	pslld	xmm15,12
	por	xmm14,xmm6
	psrld	xmm7,20
	movdqa	xmm6,XMMWORD PTR[r11]
	por	xmm15,xmm7
	paddd	xmm10,xmm14
	paddd	xmm11,xmm15
	pxor	xmm2,xmm10
	pxor	xmm3,xmm11
DB	102,15,56,0,214
DB	102,15,56,0,222
	paddd	xmm4,xmm2
	paddd	xmm5,xmm3
	pxor	xmm14,xmm4
	pxor	xmm15,xmm5
	movdqa	xmm7,xmm14
	pslld	xmm14,7
	psrld	xmm7,25
	movdqa	xmm6,xmm15
	pslld	xmm15,7
	por	xmm14,xmm7
	psrld	xmm6,25
	movdqa	xmm7,XMMWORD PTR[r9]
	por	xmm15,xmm6
	paddd	xmm8,xmm13
	paddd	xmm9,xmm14
	pxor	xmm3,xmm8
	pxor	xmm0,xmm9
DB	102,15,56,0,223
DB	102,15,56,0,199
	paddd	xmm4,xmm3
	paddd	xmm5,xmm0
	pxor	xmm13,xmm4
	pxor	xmm14,xmm5
	movdqa	xmm6,xmm13
	pslld	xmm13,12
	psrld	xmm6,20
	movdqa	xmm7,xmm14
	pslld	xmm14,12
	por	xmm13,xmm6
	psrld	xmm7,20
	movdqa	xmm6,XMMWORD PTR[r11]
	por	xmm14,xmm7
	paddd	xmm8,xmm13
	paddd	xmm9,xmm14
	pxor	xmm3,xmm8
	pxor	xmm0,xmm9
DB	102,15,56,0,222
DB	102,15,56,0,198
	paddd	xmm4,xmm3
	paddd	xmm5,xmm0
	pxor	xmm13,xmm4
	pxor	xmm14,xmm5
	movdqa	xmm7,xmm13
	pslld	xmm13,7
	psrld	xmm7,25
	movdqa	xmm6,xmm14
	pslld	xmm14,7
	por	xmm13,xmm7
	psrld	xmm6,25
	movdqa	xmm7,XMMWORD PTR[r9]
	por	xmm14,xmm6
	movdqa	XMMWORD PTR[32+rsp],xmm4
	movdqa	XMMWORD PTR[48+rsp],xmm5
	movdqa	xmm4,XMMWORD PTR[rsp]
	movdqa	xmm5,XMMWORD PTR[16+rsp]
	paddd	xmm10,xmm15
	paddd	xmm11,xmm12
	pxor	xmm1,xmm10
	pxor	xmm2,xmm11
DB	102,15,56,0,207
DB	102,15,56,0,215
	paddd	xmm4,xmm1
	paddd	xmm5,xmm2
	pxor	xmm15,xmm4
	pxor	xmm12,xmm5
	movdqa	xmm6,xmm15
	pslld	xmm15,12
	psrld	xmm6,20
	movdqa	xmm7,xmm12
	pslld	xmm12,12
	por	xmm15,xmm6
	psrld	xmm7,20
	movdqa	xmm6,XMMWORD PTR[r11]
	por	xmm12,xmm7
	paddd	xmm10,xmm15
	paddd	xmm11,xmm12
	pxor	xmm1,xmm10
	pxor	xmm2,xmm11
DB	102,15,56,0,206
DB	102,15,56,0,214
	paddd	xmm4,xmm1
	paddd	xmm5,xmm2
	pxor	xmm15,xmm4
	pxor	xmm12,xmm5
	movdqa	xmm7,xmm15
	pslld	xmm15,7
	psrld	xmm7,25
	movdqa	xmm6,xmm12
	pslld	xmm12,7
	por	xmm15,xmm7
	psrld	xmm6,25
	movdqa	xmm7,XMMWORD PTR[r9]
	por	xmm12,xmm6
	dec	eax
	jnz	$L$chacha20_loop4x
	paddd	xmm8,XMMWORD PTR[64+rsp]
	paddd	xmm9,XMMWORD PTR[80+rsp]
	paddd	xmm10,XMMWORD PTR[96+rsp]
	paddd	xmm11,XMMWORD PTR[112+rsp]
	movdqa	xmm6,xmm8
	punpckldq	xmm8,xmm9
	movdqa	xmm7,xmm10
	punpckldq	xmm10,xmm11
	punpckhdq	xmm6,xmm9
	punpckhdq	xmm7,xmm11
	movdqa	xmm9,xmm8
	punpcklqdq	xmm8,xmm10
	movdqa	xmm11,xmm6
	punpcklqdq	xmm6,xmm7
	punpckhqdq	xmm9,xmm10
	punpckhqdq	xmm11,xmm7
	paddd	xmm12,XMMWORD PTR[((128-256))+rcx]
	paddd	xmm13,XMMWORD PTR[((144-256))+rcx]
	paddd	xmm14,XMMWORD PTR[((160-256))+rcx]
	paddd	xmm15,XMMWORD PTR[((176-256))+rcx]
	movdqa	XMMWORD PTR[rsp],xmm8
	movdqa	XMMWORD PTR[16+rsp],xmm9
	movdqa	xmm8,XMMWORD PTR[32+rsp]
	movdqa	xmm9,XMMWORD PTR[48+rsp]
	movdqa	xmm10,xmm12
	punpckldq	xmm12,xmm13
	movdqa	xmm7,xmm14
	punpckldq	xmm14,xmm15
	punpckhdq	xmm10,xmm13
	punpckhdq	xmm7,xmm15
	movdqa	xmm13,xmm12
	punpcklqdq	xmm12,xmm14
	movdqa	xmm15,xmm10
	punpcklqdq	xmm10,xmm7
	punpckhqdq	xmm13,xmm14
	punpckhqdq	xmm15,xmm7
	paddd	xmm4,XMMWORD PTR[((192-256))+rcx]
	paddd	xmm5,XMMWORD PTR[((208-256))+rcx]
	paddd	xmm8,XMMWORD PTR[((224-256))+rcx]
	paddd	xmm9,XMMWORD PTR[((240-256))+rcx]
	movdqa	XMMWORD PTR[32+rsp],xmm6
	movdqa	XMMWORD PTR[48+rsp],xmm11
	movdqa	xmm14,xmm4
	punpckldq	xmm4,xmm5
	movdqa	xmm7,xmm8
	punpckldq	xmm8,xmm9
	punpckhdq	xmm14,xmm5
	punpckhdq	xmm7,xmm9
	movdqa	xmm5,xmm4
	punpcklqdq	xmm4,xmm8
	movdqa	xmm9,xmm14
	punpcklqdq	xmm14,xmm7
	punpckhqdq	xmm5,xmm8
	punpckhqdq	xmm9,xmm7
	paddd	xmm0,XMMWORD PTR[((256-256))+rcx]
	paddd	xmm1,XMMWORD PTR[((272-256))+rcx]
	paddd	xmm2,XMMWORD PTR[((288-256))+rcx]
	paddd	xmm3,XMMWORD PTR[((304-256))+rcx]
	movdqa	xmm8,xmm0
	punpckldq	xmm0,xmm1
	movdqa	xmm7,xmm2
	punpckldq	xmm2,xmm3
	punpckhdq	xmm8,xmm1
	punpckhdq	xmm7,xmm3
	movdqa	xmm1,xmm0
	punpcklqdq	xmm0,xmm2
	movdqa	xmm3,xmm8
	punpcklqdq	xmm8,xmm7
	punpckhqdq	xmm1,xmm2
	punpckhqdq	xmm3,xmm7
	cmp	rdx,64*4
	jb	$L$tail4x
	movdqu	xmm6,XMMWORD PTR[rsi]
	movdqu	xmm11,XMMWORD PTR[16+rsi]
	movdqu	xmm2,XMMWORD PTR[32+rsi]
	movdqu	xmm7,XMMWORD PTR[48+rsi]
	pxor	xmm6,XMMWORD PTR[rsp]
	pxor	xmm11,xmm12
	pxor	xmm2,xmm4
	pxor	xmm7,xmm0
	movdqu	XMMWORD PTR[rdi],xmm6
	movdqu	xmm6,XMMWORD PTR[64+rsi]
	movdqu	XMMWORD PTR[16+rdi],xmm11
	movdqu	xmm11,XMMWORD PTR[80+rsi]
	movdqu	XMMWORD PTR[32+rdi],xmm2
	movdqu	xmm2,XMMWORD PTR[96+rsi]
	movdqu	XMMWORD PTR[48+rdi],xmm7
	movdqu	xmm7,XMMWORD PTR[112+rsi]
	lea	rsi,QWORD PTR[128+rsi]
	pxor	xmm6,XMMWORD PTR[16+rsp]
	pxor	xmm11,xmm13
	pxor	xmm2,xmm5
	pxor	xmm7,xmm1
	movdqu	XMMWORD PTR[64+rdi],xmm6
	movdqu	xmm6,XMMWORD PTR[rsi]
	movdqu	XMMWORD PTR[80+rdi],xmm11
	movdqu	xmm11,XMMWORD PTR[16+rsi]
	movdqu	XMMWORD PTR[96+rdi],xmm2
	movdqu	xmm2,XMMWORD PTR[32+rsi]
	movdqu	XMMWORD PTR[112+rdi],xmm7
	lea	rdi,QWORD PTR[128+rdi]
	movdqu	xmm7,XMMWORD PTR[48+rsi]
	pxor	xmm6,XMMWORD PTR[32+rsp]
	pxor	xmm11,xmm10
	pxor	xmm2,xmm14
	pxor	xmm7,xmm8
	movdqu	XMMWORD PTR[rdi],xmm6
	movdqu	xmm6,XMMWORD PTR[64+rsi]
	movdqu	XMMWORD PTR[16+rdi],xmm11
	movdqu	xmm11,XMMWORD PTR[80+rsi]
	movdqu	XMMWORD PTR[32+rdi],xmm2
	movdqu	xmm2,XMMWORD PTR[96+rsi]
	movdqu	XMMWORD PTR[48+rdi],xmm7
	movdqu	xmm7,XMMWORD PTR[112+rsi]
	lea	rsi,QWORD PTR[128+rsi]
	pxor	xmm6,XMMWORD PTR[48+rsp]
	pxor	xmm11,xmm15
	pxor	xmm2,xmm9
	pxor	xmm7,xmm3
	movdqu	XMMWORD PTR[64+rdi],xmm6
	movdqu	XMMWORD PTR[80+rdi],xmm11
	movdqu	XMMWORD PTR[96+rdi],xmm2
	movdqu	XMMWORD PTR[112+rdi],xmm7
	lea	rdi,QWORD PTR[128+rdi]
	sub	rdx,64*4
	jnz	$L$chacha20_loop_outer4x
	jmp	$L$done4x

$L$tail4x::
	cmp	rdx,192
	jae	$L$192_or_more4x
	cmp	rdx,128
	jae	$L$128_or_more4x
	cmp	rdx,64
	jae	$L$64_or_more4x
	xor	r9,r9
	movdqa	XMMWORD PTR[16+rsp],xmm12
	movdqa	XMMWORD PTR[32+rsp],xmm4
	movdqa	XMMWORD PTR[48+rsp],xmm0
	jmp	$L$chacha20_loop_tail4x

ALIGN	32
$L$64_or_more4x::
	movdqu	xmm6,XMMWORD PTR[rsi]
	movdqu	xmm11,XMMWORD PTR[16+rsi]
	movdqu	xmm2,XMMWORD PTR[32+rsi]
	movdqu	xmm7,XMMWORD PTR[48+rsi]
	pxor	xmm6,XMMWORD PTR[rsp]
	pxor	xmm11,xmm12
	pxor	xmm2,xmm4
	pxor	xmm7,xmm0
	movdqu	XMMWORD PTR[rdi],xmm6
	movdqu	XMMWORD PTR[16+rdi],xmm11
	movdqu	XMMWORD PTR[32+rdi],xmm2
	movdqu	XMMWORD PTR[48+rdi],xmm7
	je	$L$done4x
	movdqa	xmm6,XMMWORD PTR[16+rsp]
	lea	rsi,QWORD PTR[64+rsi]
	xor	r9,r9
	movdqa	XMMWORD PTR[rsp],xmm6
	movdqa	XMMWORD PTR[16+rsp],xmm13
	lea	rdi,QWORD PTR[64+rdi]
	movdqa	XMMWORD PTR[32+rsp],xmm5
	sub	rdx,64
	movdqa	XMMWORD PTR[48+rsp],xmm1
	jmp	$L$chacha20_loop_tail4x

ALIGN	32
$L$128_or_more4x::
	movdqu	xmm6,XMMWORD PTR[rsi]
	movdqu	xmm11,XMMWORD PTR[16+rsi]
	movdqu	xmm2,XMMWORD PTR[32+rsi]
	movdqu	xmm7,XMMWORD PTR[48+rsi]
	pxor	xmm6,XMMWORD PTR[rsp]
	pxor	xmm11,xmm12
	pxor	xmm2,xmm4
	pxor	xmm7,xmm0
	movdqu	XMMWORD PTR[rdi],xmm6
	movdqu	xmm6,XMMWORD PTR[64+rsi]
	movdqu	XMMWORD PTR[16+rdi],xmm11
	movdqu	xmm11,XMMWORD PTR[80+rsi]
	movdqu	XMMWORD PTR[32+rdi],xmm2
	movdqu	xmm2,XMMWORD PTR[96+rsi]
	movdqu	XMMWORD PTR[48+rdi],xmm7
	movdqu	xmm7,XMMWORD PTR[112+rsi]
	pxor	xmm6,XMMWORD PTR[16+rsp]
	pxor	xmm11,xmm13
	pxor	xmm2,xmm5
	pxor	xmm7,xmm1
	movdqu	XMMWORD PTR[64+rdi],xmm6
	movdqu	XMMWORD PTR[80+rdi],xmm11
	movdqu	XMMWORD PTR[96+rdi],xmm2
	movdqu	XMMWORD PTR[112+rdi],xmm7
	je	$L$done4x
	movdqa	xmm6,XMMWORD PTR[32+rsp]
	lea	rsi,QWORD PTR[128+rsi]
	xor	r9,r9
	movdqa	XMMWORD PTR[rsp],xmm6
	movdqa	XMMWORD PTR[16+rsp],xmm10
	lea	rdi,QWORD PTR[128+rdi]
	movdqa	XMMWORD PTR[32+rsp],xmm14
	sub	rdx,128
	movdqa	XMMWORD PTR[48+rsp],xmm8
	jmp	$L$chacha20_loop_tail4x

ALIGN	32
$L$192_or_more4x::
	movdqu	xmm6,XMMWORD PTR[rsi]
	movdqu	xmm11,XMMWORD PTR[16+rsi]
	movdqu	xmm2,XMMWORD PTR[32+rsi]
	movdqu	xmm7,XMMWORD PTR[48+rsi]
	pxor	xmm6,XMMWORD PTR[rsp]
	pxor	xmm11,xmm12
	pxor	xmm2,xmm4
	pxor	xmm7,xmm0
	movdqu	XMMWORD PTR[rdi],xmm6
	movdqu	xmm6,XMMWORD PTR[64+rsi]
	movdqu	XMMWORD PTR[16+rdi],xmm11
	movdqu	xmm11,XMMWORD PTR[80+rsi]
	movdqu	XMMWORD PTR[32+rdi],xmm2
	movdqu	xmm2,XMMWORD PTR[96+rsi]
	movdqu	XMMWORD PTR[48+rdi],xmm7
	movdqu	xmm7,XMMWORD PTR[112+rsi]
	lea	rsi,QWORD PTR[128+rsi]
	pxor	xmm6,XMMWORD PTR[16+rsp]
	pxor	xmm11,xmm13
	pxor	xmm2,xmm5
	pxor	xmm7,xmm1
	movdqu	XMMWORD PTR[64+rdi],xmm6
	movdqu	xmm6,XMMWORD PTR[rsi]
	movdqu	XMMWORD PTR[80+rdi],xmm11
	movdqu	xmm11,XMMWORD PTR[16+rsi]
	movdqu	XMMWORD PTR[96+rdi],xmm2
	movdqu	xmm2,XMMWORD PTR[32+rsi]
	movdqu	XMMWORD PTR[112+rdi],xmm7
	lea	rdi,QWORD PTR[128+rdi]
	movdqu	xmm7,XMMWORD PTR[48+rsi]
	pxor	xmm6,XMMWORD PTR[32+rsp]
	pxor	xmm11,xmm10
	pxor	xmm2,xmm14
	pxor	xmm7,xmm8
	movdqu	XMMWORD PTR[rdi],xmm6
	movdqu	XMMWORD PTR[16+rdi],xmm11
	movdqu	XMMWORD PTR[32+rdi],xmm2
	movdqu	XMMWORD PTR[48+rdi],xmm7
	je	$L$done4x
	movdqa	xmm6,XMMWORD PTR[48+rsp]
	lea	rsi,QWORD PTR[64+rsi]
	xor	r9,r9
	movdqa	XMMWORD PTR[rsp],xmm6
	movdqa	XMMWORD PTR[16+rsp],xmm15
	lea	rdi,QWORD PTR[64+rdi]
	movdqa	XMMWORD PTR[32+rsp],xmm9
	sub	rdx,192
	movdqa	XMMWORD PTR[48+rsp],xmm3

$L$chacha20_loop_tail4x::
	movzx	eax,BYTE PTR[r9*1+rsi]
	movzx	ecx,BYTE PTR[r9*1+rsp]
	lea	r9,QWORD PTR[1+r9]
	xor	eax,ecx
	mov	BYTE PTR[((-1))+r9*1+rdi],al
	dec	rdx
	jnz	$L$chacha20_loop_tail4x

$L$done4x::
	movaps	xmm6,XMMWORD PTR[((-168))+r10]
	movaps	xmm7,XMMWORD PTR[((-152))+r10]
	movaps	xmm8,XMMWORD PTR[((-136))+r10]
	movaps	xmm9,XMMWORD PTR[((-120))+r10]
	movaps	xmm10,XMMWORD PTR[((-104))+r10]
	movaps	xmm11,XMMWORD PTR[((-88))+r10]
	movaps	xmm12,XMMWORD PTR[((-72))+r10]
	movaps	xmm13,XMMWORD PTR[((-56))+r10]
	movaps	xmm14,XMMWORD PTR[((-40))+r10]
	movaps	xmm15,XMMWORD PTR[((-24))+r10]
	lea	rsp,QWORD PTR[r10]

$L$4x_epilogue::
	mov	rdi,QWORD PTR[8+rsp]	;WIN64 epilogue
	mov	rsi,QWORD PTR[16+rsp]
	DB	0F3h,0C3h		;repret

$L$SEH_end_chacha20_4x::
chacha20_4x	ENDP
PUBLIC	ChaCha20AVX2

ALIGN	32
ChaCha20AVX2	PROC PUBLIC
	DB	243,15,30,250
	mov	QWORD PTR[8+rsp],rdi	;WIN64 prologue
	mov	QWORD PTR[16+rsp],rsi
	mov	rax,rsp
$L$SEH_begin_chacha20_avx2::
	mov	rdi,rcx
	mov	rsi,rdx
	mov	rdx,r8
	mov	rcx,r9
	mov	r8,QWORD PTR[40+rsp]

$L$chacha20_8x::
	mov	r10,rsp
	sub	rsp,0280h+168
	and	rsp,-32
	movaps	XMMWORD PTR[(-168)+r10],xmm6
	movaps	XMMWORD PTR[(-152)+r10],xmm7
	movaps	XMMWORD PTR[(-136)+r10],xmm8
	movaps	XMMWORD PTR[(-120)+r10],xmm9
	movaps	XMMWORD PTR[(-104)+r10],xmm10
	movaps	XMMWORD PTR[(-88)+r10],xmm11
	movaps	XMMWORD PTR[(-72)+r10],xmm12
	movaps	XMMWORD PTR[(-56)+r10],xmm13
	movaps	XMMWORD PTR[(-40)+r10],xmm14
	movaps	XMMWORD PTR[(-24)+r10],xmm15
$L$avx2_body::
	vzeroupper
	vbroadcasti128	ymm11,XMMWORD PTR[$L$sigma]
	vbroadcasti128	ymm3,XMMWORD PTR[rcx]
	vbroadcasti128	ymm15,XMMWORD PTR[16+rcx]
	vbroadcasti128	ymm7,XMMWORD PTR[r8]
	lea	rcx,QWORD PTR[256+rsp]
	lea	rax,QWORD PTR[512+rsp]
	lea	r9,QWORD PTR[$L$rot16]
	lea	r11,QWORD PTR[$L$rot24]
	vpshufd	ymm8,ymm11,000h
	vpshufd	ymm9,ymm11,055h
	vmovdqa	YMMWORD PTR[(128-256)+rcx],ymm8
	vpshufd	ymm10,ymm11,0aah
	vmovdqa	YMMWORD PTR[(160-256)+rcx],ymm9
	vpshufd	ymm11,ymm11,0ffh
	vmovdqa	YMMWORD PTR[(192-256)+rcx],ymm10
	vmovdqa	YMMWORD PTR[(224-256)+rcx],ymm11
	vpshufd	ymm0,ymm3,000h
	vpshufd	ymm1,ymm3,055h
	vmovdqa	YMMWORD PTR[(256-256)+rcx],ymm0
	vpshufd	ymm2,ymm3,0aah
	vmovdqa	YMMWORD PTR[(288-256)+rcx],ymm1
	vpshufd	ymm3,ymm3,0ffh
	vmovdqa	YMMWORD PTR[(320-256)+rcx],ymm2
	vmovdqa	YMMWORD PTR[(352-256)+rcx],ymm3
	vpshufd	ymm12,ymm15,000h
	vpshufd	ymm13,ymm15,055h
	vmovdqa	YMMWORD PTR[(384-512)+rax],ymm12
	vpshufd	ymm14,ymm15,0aah
	vmovdqa	YMMWORD PTR[(416-512)+rax],ymm13
	vpshufd	ymm15,ymm15,0ffh
	vmovdqa	YMMWORD PTR[(448-512)+rax],ymm14
	vmovdqa	YMMWORD PTR[(480-512)+rax],ymm15
	vpshufd	ymm4,ymm7,000h
	vpshufd	ymm5,ymm7,055h
	vpaddd	ymm4,ymm4,YMMWORD PTR[$L$incy]
	vpshufd	ymm6,ymm7,0aah
	vmovdqa	YMMWORD PTR[(544-512)+rax],ymm5
	vpshufd	ymm7,ymm7,0ffh
	vmovdqa	YMMWORD PTR[(576-512)+rax],ymm6
	vmovdqa	YMMWORD PTR[(608-512)+rax],ymm7
	jmp	$L$chacha20_loop_enter8x

ALIGN	32
$L$chacha20_loop_outer8x::
	vmovdqa	ymm8,YMMWORD PTR[((128-256))+rcx]
	vmovdqa	ymm9,YMMWORD PTR[((160-256))+rcx]
	vmovdqa	ymm10,YMMWORD PTR[((192-256))+rcx]
	vmovdqa	ymm11,YMMWORD PTR[((224-256))+rcx]
	vmovdqa	ymm0,YMMWORD PTR[((256-256))+rcx]
	vmovdqa	ymm1,YMMWORD PTR[((288-256))+rcx]
	vmovdqa	ymm2,YMMWORD PTR[((320-256))+rcx]
	vmovdqa	ymm3,YMMWORD PTR[((352-256))+rcx]
	vmovdqa	ymm12,YMMWORD PTR[((384-512))+rax]
	vmovdqa	ymm13,YMMWORD PTR[((416-512))+rax]
	vmovdqa	ymm14,YMMWORD PTR[((448-512))+rax]
	vmovdqa	ymm15,YMMWORD PTR[((480-512))+rax]
	vmovdqa	ymm4,YMMWORD PTR[((512-512))+rax]
	vmovdqa	ymm5,YMMWORD PTR[((544-512))+rax]
	vmovdqa	ymm6,YMMWORD PTR[((576-512))+rax]
	vmovdqa	ymm7,YMMWORD PTR[((608-512))+rax]
	vpaddd	ymm4,ymm4,YMMWORD PTR[$L$eight]

$L$chacha20_loop_enter8x::
	vmovdqa	YMMWORD PTR[64+rsp],ymm14
	vmovdqa	YMMWORD PTR[96+rsp],ymm15
	vbroadcasti128	ymm15,XMMWORD PTR[r9]
	vmovdqa	YMMWORD PTR[(512-512)+rax],ymm4
	mov	eax,10
	jmp	$L$chacha20_loop8x

ALIGN	32
$L$chacha20_loop8x::
	vpaddd	ymm8,ymm8,ymm0
	vpxor	ymm4,ymm8,ymm4
	vpshufb	ymm4,ymm4,ymm15
	vpaddd	ymm9,ymm9,ymm1
	vpxor	ymm5,ymm9,ymm5
	vpshufb	ymm5,ymm5,ymm15
	vpaddd	ymm12,ymm12,ymm4
	vpxor	ymm0,ymm12,ymm0
	vpslld	ymm14,ymm0,12
	vpsrld	ymm0,ymm0,20
	vpor	ymm0,ymm14,ymm0
	vbroadcasti128	ymm14,XMMWORD PTR[r11]
	vpaddd	ymm13,ymm13,ymm5
	vpxor	ymm1,ymm13,ymm1
	vpslld	ymm15,ymm1,12
	vpsrld	ymm1,ymm1,20
	vpor	ymm1,ymm15,ymm1
	vpaddd	ymm8,ymm8,ymm0
	vpxor	ymm4,ymm8,ymm4
	vpshufb	ymm4,ymm4,ymm14
	vpaddd	ymm9,ymm9,ymm1
	vpxor	ymm5,ymm9,ymm5
	vpshufb	ymm5,ymm5,ymm14
	vpaddd	ymm12,ymm12,ymm4
	vpxor	ymm0,ymm12,ymm0
	vpslld	ymm15,ymm0,7
	vpsrld	ymm0,ymm0,25
	vpor	ymm0,ymm15,ymm0
	vbroadcasti128	ymm15,XMMWORD PTR[r9]
	vpaddd	ymm13,ymm13,ymm5
	vpxor	ymm1,ymm13,ymm1
	vpslld	ymm14,ymm1,7
	vpsrld	ymm1,ymm1,25
	vpor	ymm1,ymm14,ymm1
	vmovdqa	YMMWORD PTR[rsp],ymm12
	vmovdqa	YMMWORD PTR[32+rsp],ymm13
	vmovdqa	ymm12,YMMWORD PTR[64+rsp]
	vmovdqa	ymm13,YMMWORD PTR[96+rsp]
	vpaddd	ymm10,ymm10,ymm2
	vpxor	ymm6,ymm10,ymm6
	vpshufb	ymm6,ymm6,ymm15
	vpaddd	ymm11,ymm11,ymm3
	vpxor	ymm7,ymm11,ymm7
	vpshufb	ymm7,ymm7,ymm15
	vpaddd	ymm12,ymm12,ymm6
	vpxor	ymm2,ymm12,ymm2
	vpslld	ymm14,ymm2,12
	vpsrld	ymm2,ymm2,20
	vpor	ymm2,ymm14,ymm2
	vbroadcasti128	ymm14,XMMWORD PTR[r11]
	vpaddd	ymm13,ymm13,ymm7
	vpxor	ymm3,ymm13,ymm3
	vpslld	ymm15,ymm3,12
	vpsrld	ymm3,ymm3,20
	vpor	ymm3,ymm15,ymm3
	vpaddd	ymm10,ymm10,ymm2
	vpxor	ymm6,ymm10,ymm6
	vpshufb	ymm6,ymm6,ymm14
	vpaddd	ymm11,ymm11,ymm3
	vpxor	ymm7,ymm11,ymm7
	vpshufb	ymm7,ymm7,ymm14
	vpaddd	ymm12,ymm12,ymm6
	vpxor	ymm2,ymm12,ymm2
	vpslld	ymm15,ymm2,7
	vpsrld	ymm2,ymm2,25
	vpor	ymm2,ymm15,ymm2
	vbroadcasti128	ymm15,XMMWORD PTR[r9]
	vpaddd	ymm13,ymm13,ymm7
	vpxor	ymm3,ymm13,ymm3
	vpslld	ymm14,ymm3,7
	vpsrld	ymm3,ymm3,25
	vpor	ymm3,ymm14,ymm3
	vpaddd	ymm8,ymm8,ymm1
	vpxor	ymm7,ymm8,ymm7
	vpshufb	ymm7,ymm7,ymm15
	vpaddd	ymm9,ymm9,ymm2
	vpxor	ymm4,ymm9,ymm4
	vpshufb	ymm4,ymm4,ymm15
	vpaddd	ymm12,ymm12,ymm7
	vpxor	ymm1,ymm12,ymm1
	vpslld	ymm14,ymm1,12
	vpsrld	ymm1,ymm1,20
	vpor	ymm1,ymm14,ymm1
	vbroadcasti128	ymm14,XMMWORD PTR[r11]
	vpaddd	ymm13,ymm13,ymm4
	vpxor	ymm2,ymm13,ymm2
	vpslld	ymm15,ymm2,12
	vpsrld	ymm2,ymm2,20
	vpor	ymm2,ymm15,ymm2
	vpaddd	ymm8,ymm8,ymm1
	vpxor	ymm7,ymm8,ymm7
	vpshufb	ymm7,ymm7,ymm14
	vpaddd	ymm9,ymm9,ymm2
	vpxor	ymm4,ymm9,ymm4
	vpshufb	ymm4,ymm4,ymm14
	vpaddd	ymm12,ymm12,ymm7
	vpxor	ymm1,ymm12,ymm1
	vpslld	ymm15,ymm1,7
	vpsrld	ymm1,ymm1,25
	vpor	ymm1,ymm15,ymm1
	vbroadcasti128	ymm15,XMMWORD PTR[r9]
	vpaddd	ymm13,ymm13,ymm4
	vpxor	ymm2,ymm13,ymm2
	vpslld	ymm14,ymm2,7
	vpsrld	ymm2,ymm2,25
	vpor	ymm2,ymm14,ymm2
	vmovdqa	YMMWORD PTR[64+rsp],ymm12
	vmovdqa	YMMWORD PTR[96+rsp],ymm13
	vmovdqa	ymm12,YMMWORD PTR[rsp]
	vmovdqa	ymm13,YMMWORD PTR[32+rsp]
	vpaddd	ymm10,ymm10,ymm3
	vpxor	ymm5,ymm10,ymm5
	vpshufb	ymm5,ymm5,ymm15
	vpaddd	ymm11,ymm11,ymm0
	vpxor	ymm6,ymm11,ymm6
	vpshufb	ymm6,ymm6,ymm15
	vpaddd	ymm12,ymm12,ymm5
	vpxor	ymm3,ymm12,ymm3
	vpslld	ymm14,ymm3,12
	vpsrld	ymm3,ymm3,20
	vpor	ymm3,ymm14,ymm3
	vbroadcasti128	ymm14,XMMWORD PTR[r11]
	vpaddd	ymm13,ymm13,ymm6
	vpxor	ymm0,ymm13,ymm0
	vpslld	ymm15,ymm0,12
	vpsrld	ymm0,ymm0,20
	vpor	ymm0,ymm15,ymm0
	vpaddd	ymm10,ymm10,ymm3
	vpxor	ymm5,ymm10,ymm5
	vpshufb	ymm5,ymm5,ymm14
	vpaddd	ymm11,ymm11,ymm0
	vpxor	ymm6,ymm11,ymm6
	vpshufb	ymm6,ymm6,ymm14
	vpaddd	ymm12,ymm12,ymm5
	vpxor	ymm3,ymm12,ymm3
	vpslld	ymm15,ymm3,7
	vpsrld	ymm3,ymm3,25
	vpor	ymm3,ymm15,ymm3
	vbroadcasti128	ymm15,XMMWORD PTR[r9]
	vpaddd	ymm13,ymm13,ymm6
	vpxor	ymm0,ymm13,ymm0
	vpslld	ymm14,ymm0,7
	vpsrld	ymm0,ymm0,25
	vpor	ymm0,ymm14,ymm0
	dec	eax
	jnz	$L$chacha20_loop8x
	lea	rax,QWORD PTR[512+rsp]
	vpaddd	ymm8,ymm8,YMMWORD PTR[((128-256))+rcx]
	vpaddd	ymm9,ymm9,YMMWORD PTR[((160-256))+rcx]
	vpaddd	ymm10,ymm10,YMMWORD PTR[((192-256))+rcx]
	vpaddd	ymm11,ymm11,YMMWORD PTR[((224-256))+rcx]
	vpunpckldq	ymm14,ymm8,ymm9
	vpunpckldq	ymm15,ymm10,ymm11
	vpunpckhdq	ymm8,ymm8,ymm9
	vpunpckhdq	ymm10,ymm10,ymm11
	vpunpcklqdq	ymm9,ymm14,ymm15
	vpunpckhqdq	ymm14,ymm14,ymm15
	vpunpcklqdq	ymm11,ymm8,ymm10
	vpunpckhqdq	ymm8,ymm8,ymm10
	vpaddd	ymm0,ymm0,YMMWORD PTR[((256-256))+rcx]
	vpaddd	ymm1,ymm1,YMMWORD PTR[((288-256))+rcx]
	vpaddd	ymm2,ymm2,YMMWORD PTR[((320-256))+rcx]
	vpaddd	ymm3,ymm3,YMMWORD PTR[((352-256))+rcx]
	vpunpckldq	ymm10,ymm0,ymm1
	vpunpckldq	ymm15,ymm2,ymm3
	vpunpckhdq	ymm0,ymm0,ymm1
	vpunpckhdq	ymm2,ymm2,ymm3
	vpunpcklqdq	ymm1,ymm10,ymm15
	vpunpckhqdq	ymm10,ymm10,ymm15
	vpunpcklqdq	ymm3,ymm0,ymm2
	vpunpckhqdq	ymm0,ymm0,ymm2
	vperm2i128	ymm15,ymm9,ymm1,020h
	vperm2i128	ymm1,ymm9,ymm1,031h
	vperm2i128	ymm9,ymm14,ymm10,020h
	vperm2i128	ymm10,ymm14,ymm10,031h
	vperm2i128	ymm14,ymm11,ymm3,020h
	vperm2i128	ymm3,ymm11,ymm3,031h
	vperm2i128	ymm11,ymm8,ymm0,020h
	vperm2i128	ymm0,ymm8,ymm0,031h
	vmovdqa	YMMWORD PTR[rsp],ymm15
	vmovdqa	YMMWORD PTR[32+rsp],ymm9
	vmovdqa	ymm15,YMMWORD PTR[64+rsp]
	vmovdqa	ymm9,YMMWORD PTR[96+rsp]
	vpaddd	ymm12,ymm12,YMMWORD PTR[((384-512))+rax]
	vpaddd	ymm13,ymm13,YMMWORD PTR[((416-512))+rax]
	vpaddd	ymm15,ymm15,YMMWORD PTR[((448-512))+rax]
	vpaddd	ymm9,ymm9,YMMWORD PTR[((480-512))+rax]
	vpunpckldq	ymm2,ymm12,ymm13
	vpunpckldq	ymm8,ymm15,ymm9
	vpunpckhdq	ymm12,ymm12,ymm13
	vpunpckhdq	ymm15,ymm15,ymm9
	vpunpcklqdq	ymm13,ymm2,ymm8
	vpunpckhqdq	ymm2,ymm2,ymm8
	vpunpcklqdq	ymm9,ymm12,ymm15
	vpunpckhqdq	ymm12,ymm12,ymm15
	vpaddd	ymm4,ymm4,YMMWORD PTR[((512-512))+rax]
	vpaddd	ymm5,ymm5,YMMWORD PTR[((544-512))+rax]
	vpaddd	ymm6,ymm6,YMMWORD PTR[((576-512))+rax]
	vpaddd	ymm7,ymm7,YMMWORD PTR[((608-512))+rax]
	vpunpckldq	ymm15,ymm4,ymm5
	vpunpckldq	ymm8,ymm6,ymm7
	vpunpckhdq	ymm4,ymm4,ymm5
	vpunpckhdq	ymm6,ymm6,ymm7
	vpunpcklqdq	ymm5,ymm15,ymm8
	vpunpckhqdq	ymm15,ymm15,ymm8
	vpunpcklqdq	ymm7,ymm4,ymm6
	vpunpckhqdq	ymm4,ymm4,ymm6
	vperm2i128	ymm8,ymm13,ymm5,020h
	vperm2i128	ymm5,ymm13,ymm5,031h
	vperm2i128	ymm13,ymm2,ymm15,020h
	vperm2i128	ymm15,ymm2,ymm15,031h
	vperm2i128	ymm2,ymm9,ymm7,020h
	vperm2i128	ymm7,ymm9,ymm7,031h
	vperm2i128	ymm9,ymm12,ymm4,020h
	vperm2i128	ymm4,ymm12,ymm4,031h
	vmovdqa	ymm6,YMMWORD PTR[rsp]
	vmovdqa	ymm12,YMMWORD PTR[32+rsp]
	cmp	rdx,64*8
	jb	$L$tail8x
	vpxor	ymm6,ymm6,YMMWORD PTR[rsi]
	vpxor	ymm8,ymm8,YMMWORD PTR[32+rsi]
	vpxor	ymm1,ymm1,YMMWORD PTR[64+rsi]
	vpxor	ymm5,ymm5,YMMWORD PTR[96+rsi]
	lea	rsi,QWORD PTR[128+rsi]
	vmovdqu	YMMWORD PTR[rdi],ymm6
	vmovdqu	YMMWORD PTR[32+rdi],ymm8
	vmovdqu	YMMWORD PTR[64+rdi],ymm1
	vmovdqu	YMMWORD PTR[96+rdi],ymm5
	lea	rdi,QWORD PTR[128+rdi]
	vpxor	ymm12,ymm12,YMMWORD PTR[rsi]
	vpxor	ymm13,ymm13,YMMWORD PTR[32+rsi]
	vpxor	ymm10,ymm10,YMMWORD PTR[64+rsi]
	vpxor	ymm15,ymm15,YMMWORD PTR[96+rsi]
	lea	rsi,QWORD PTR[128+rsi]
	vmovdqu	YMMWORD PTR[rdi],ymm12
	vmovdqu	YMMWORD PTR[32+rdi],ymm13
	vmovdqu	YMMWORD PTR[64+rdi],ymm10
	vmovdqu	YMMWORD PTR[96+rdi],ymm15
	lea	rdi,QWORD PTR[128+rdi]
	vpxor	ymm14,ymm14,YMMWORD PTR[rsi]
	vpxor	ymm2,ymm2,YMMWORD PTR[32+rsi]
	vpxor	ymm3,ymm3,YMMWORD PTR[64+rsi]
	vpxor	ymm7,ymm7,YMMWORD PTR[96+rsi]
	lea	rsi,QWORD PTR[128+rsi]
	vmovdqu	YMMWORD PTR[rdi],ymm14
	vmovdqu	YMMWORD PTR[32+rdi],ymm2
	vmovdqu	YMMWORD PTR[64+rdi],ymm3
	vmovdqu	YMMWORD PTR[96+rdi],ymm7
	lea	rdi,QWORD PTR[128+rdi]
	vpxor	ymm11,ymm11,YMMWORD PTR[rsi]
	vpxor	ymm9,ymm9,YMMWORD PTR[32+rsi]
	vpxor	ymm0,ymm0,YMMWORD PTR[64+rsi]
	vpxor	ymm4,ymm4,YMMWORD PTR[96+rsi]
	lea	rsi,QWORD PTR[128+rsi]
	vmovdqu	YMMWORD PTR[rdi],ymm11
	vmovdqu	YMMWORD PTR[32+rdi],ymm9
	vmovdqu	YMMWORD PTR[64+rdi],ymm0
	vmovdqu	YMMWORD PTR[96+rdi],ymm4
	lea	rdi,QWORD PTR[128+rdi]
	sub	rdx,64*8
	jnz	$L$chacha20_loop_outer8x
	jmp	$L$done8x

$L$tail8x::
	cmp	rdx,448
	jae	$L$448_or_more8x
	cmp	rdx,384
	jae	$L$384_or_more8x
	cmp	rdx,320
	jae	$L$320_or_more8x
	cmp	rdx,256
	jae	$L$256_or_more8x
	cmp	rdx,192
	jae	$L$192_or_more8x
	cmp	rdx,128
	jae	$L$128_or_more8x
	cmp	rdx,64
	jae	$L$64_or_more8x
	xor	r9,r9
	vmovdqa	YMMWORD PTR[rsp],ymm6
	vmovdqa	YMMWORD PTR[32+rsp],ymm8
	jmp	$L$chacha20_loop_tail8x

ALIGN	32
$L$64_or_more8x::
	vpxor	ymm6,ymm6,YMMWORD PTR[rsi]
	vpxor	ymm8,ymm8,YMMWORD PTR[32+rsi]
	vmovdqu	YMMWORD PTR[rdi],ymm6
	vmovdqu	YMMWORD PTR[32+rdi],ymm8
	je	$L$done8x
	lea	rsi,QWORD PTR[64+rsi]
	xor	r9,r9
	vmovdqa	YMMWORD PTR[rsp],ymm1
	lea	rdi,QWORD PTR[64+rdi]
	sub	rdx,64
	vmovdqa	YMMWORD PTR[32+rsp],ymm5
	jmp	$L$chacha20_loop_tail8x

ALIGN	32
$L$128_or_more8x::
	vpxor	ymm6,ymm6,YMMWORD PTR[rsi]
	vpxor	ymm8,ymm8,YMMWORD PTR[32+rsi]
	vpxor	ymm1,ymm1,YMMWORD PTR[64+rsi]
	vpxor	ymm5,ymm5,YMMWORD PTR[96+rsi]
	vmovdqu	YMMWORD PTR[rdi],ymm6
	vmovdqu	YMMWORD PTR[32+rdi],ymm8
	vmovdqu	YMMWORD PTR[64+rdi],ymm1
	vmovdqu	YMMWORD PTR[96+rdi],ymm5
	je	$L$done8x
	lea	rsi,QWORD PTR[128+rsi]
	xor	r9,r9
	vmovdqa	YMMWORD PTR[rsp],ymm12
	lea	rdi,QWORD PTR[128+rdi]
	sub	rdx,128
	vmovdqa	YMMWORD PTR[32+rsp],ymm13
	jmp	$L$chacha20_loop_tail8x

ALIGN	32
$L$192_or_more8x::
	vpxor	ymm6,ymm6,YMMWORD PTR[rsi]
	vpxor	ymm8,ymm8,YMMWORD PTR[32+rsi]
	vpxor	ymm1,ymm1,YMMWORD PTR[64+rsi]
	vpxor	ymm5,ymm5,YMMWORD PTR[96+rsi]
	vpxor	ymm12,ymm12,YMMWORD PTR[128+rsi]
	vpxor	ymm13,ymm13,YMMWORD PTR[160+rsi]
	vmovdqu	YMMWORD PTR[rdi],ymm6
	vmovdqu	YMMWORD PTR[32+rdi],ymm8
	vmovdqu	YMMWORD PTR[64+rdi],ymm1
	vmovdqu	YMMWORD PTR[96+rdi],ymm5
	vmovdqu	YMMWORD PTR[128+rdi],ymm12
	vmovdqu	YMMWORD PTR[160+rdi],ymm13
	je	$L$done8x
	lea	rsi,QWORD PTR[192+rsi]
	xor	r9,r9
	vmovdqa	YMMWORD PTR[rsp],ymm10
	lea	rdi,QWORD PTR[192+rdi]
	sub	rdx,192
	vmovdqa	YMMWORD PTR[32+rsp],ymm15
	jmp	$L$chacha20_loop_tail8x

ALIGN	32
$L$256_or_more8x::
	vpxor	ymm6,ymm6,YMMWORD PTR[rsi]
	vpxor	ymm8,ymm8,YMMWORD PTR[32+rsi]
	vpxor	ymm1,ymm1,YMMWORD PTR[64+rsi]
	vpxor	ymm5,ymm5,YMMWORD PTR[96+rsi]
	vpxor	ymm12,ymm12,YMMWORD PTR[128+rsi]
	vpxor	ymm13,ymm13,YMMWORD PTR[160+rsi]
	vpxor	ymm10,ymm10,YMMWORD PTR[192+rsi]
	vpxor	ymm15,ymm15,YMMWORD PTR[224+rsi]
	vmovdqu	YMMWORD PTR[rdi],ymm6
	vmovdqu	YMMWORD PTR[32+rdi],ymm8
	vmovdqu	YMMWORD PTR[64+rdi],ymm1
	vmovdqu	YMMWORD PTR[96+rdi],ymm5
	vmovdqu	YMMWORD PTR[128+rdi],ymm12
	vmovdqu	YMMWORD PTR[160+rdi],ymm13
	vmovdqu	YMMWORD PTR[192+rdi],ymm10
	vmovdqu	YMMWORD PTR[224+rdi],ymm15
	je	$L$done8x
	lea	rsi,QWORD PTR[256+rsi]
	xor	r9,r9
	vmovdqa	YMMWORD PTR[rsp],ymm14
	lea	rdi,QWORD PTR[256+rdi]
	sub	rdx,256
	vmovdqa	YMMWORD PTR[32+rsp],ymm2
	jmp	$L$chacha20_loop_tail8x

ALIGN	32
$L$320_or_more8x::
	vpxor	ymm6,ymm6,YMMWORD PTR[rsi]
	vpxor	ymm8,ymm8,YMMWORD PTR[32+rsi]
	vpxor	ymm1,ymm1,YMMWORD PTR[64+rsi]
	vpxor	ymm5,ymm5,YMMWORD PTR[96+rsi]
	vpxor	ymm12,ymm12,YMMWORD PTR[128+rsi]
	vpxor	ymm13,ymm13,YMMWORD PTR[160+rsi]
	vpxor	ymm10,ymm10,YMMWORD PTR[192+rsi]
	vpxor	ymm15,ymm15,YMMWORD PTR[224+rsi]
	vpxor	ymm14,ymm14,YMMWORD PTR[256+rsi]
	vpxor	ymm2,ymm2,YMMWORD PTR[288+rsi]
	vmovdqu	YMMWORD PTR[rdi],ymm6
	vmovdqu	YMMWORD PTR[32+rdi],ymm8
	vmovdqu	YMMWORD PTR[64+rdi],ymm1
	vmovdqu	YMMWORD PTR[96+rdi],ymm5
	vmovdqu	YMMWORD PTR[128+rdi],ymm12
	vmovdqu	YMMWORD PTR[160+rdi],ymm13
	vmovdqu	YMMWORD PTR[192+rdi],ymm10
	vmovdqu	YMMWORD PTR[224+rdi],ymm15
	vmovdqu	YMMWORD PTR[256+rdi],ymm14
	vmovdqu	YMMWORD PTR[288+rdi],ymm2
	je	$L$done8x
	lea	rsi,QWORD PTR[320+rsi]
	xor	r9,r9
	vmovdqa	YMMWORD PTR[rsp],ymm3
	lea	rdi,QWORD PTR[320+rdi]
	sub	rdx,320
	vmovdqa	YMMWORD PTR[32+rsp],ymm7
	jmp	$L$chacha20_loop_tail8x

ALIGN	32
$L$384_or_more8x::
	vpxor	ymm6,ymm6,YMMWORD PTR[rsi]
	vpxor	ymm8,ymm8,YMMWORD PTR[32+rsi]
	vpxor	ymm1,ymm1,YMMWORD PTR[64+rsi]
	vpxor	ymm5,ymm5,YMMWORD PTR[96+rsi]
	vpxor	ymm12,ymm12,YMMWORD PTR[128+rsi]
	vpxor	ymm13,ymm13,YMMWORD PTR[160+rsi]
	vpxor	ymm10,ymm10,YMMWORD PTR[192+rsi]
	vpxor	ymm15,ymm15,YMMWORD PTR[224+rsi]
	vpxor	ymm14,ymm14,YMMWORD PTR[256+rsi]
	vpxor	ymm2,ymm2,YMMWORD PTR[288+rsi]
	vpxor	ymm3,ymm3,YMMWORD PTR[320+rsi]
	vpxor	ymm7,ymm7,YMMWORD PTR[352+rsi]
	vmovdqu	YMMWORD PTR[rdi],ymm6
	vmovdqu	YMMWORD PTR[32+rdi],ymm8
	vmovdqu	YMMWORD PTR[64+rdi],ymm1
	vmovdqu	YMMWORD PTR[96+rdi],ymm5
	vmovdqu	YMMWORD PTR[128+rdi],ymm12
	vmovdqu	YMMWORD PTR[160+rdi],ymm13
	vmovdqu	YMMWORD PTR[192+rdi],ymm10
	vmovdqu	YMMWORD PTR[224+rdi],ymm15
	vmovdqu	YMMWORD PTR[256+rdi],ymm14
	vmovdqu	YMMWORD PTR[288+rdi],ymm2
	vmovdqu	YMMWORD PTR[320+rdi],ymm3
	vmovdqu	YMMWORD PTR[352+rdi],ymm7
	je	$L$done8x
	lea	rsi,QWORD PTR[384+rsi]
	xor	r9,r9
	vmovdqa	YMMWORD PTR[rsp],ymm11
	lea	rdi,QWORD PTR[384+rdi]
	sub	rdx,384
	vmovdqa	YMMWORD PTR[32+rsp],ymm9
	jmp	$L$chacha20_loop_tail8x

ALIGN	32
$L$448_or_more8x::
	vpxor	ymm6,ymm6,YMMWORD PTR[rsi]
	vpxor	ymm8,ymm8,YMMWORD PTR[32+rsi]
	vpxor	ymm1,ymm1,YMMWORD PTR[64+rsi]
	vpxor	ymm5,ymm5,YMMWORD PTR[96+rsi]
	vpxor	ymm12,ymm12,YMMWORD PTR[128+rsi]
	vpxor	ymm13,ymm13,YMMWORD PTR[160+rsi]
	vpxor	ymm10,ymm10,YMMWORD PTR[192+rsi]
	vpxor	ymm15,ymm15,YMMWORD PTR[224+rsi]
	vpxor	ymm14,ymm14,YMMWORD PTR[256+rsi]
	vpxor	ymm2,ymm2,YMMWORD PTR[288+rsi]
	vpxor	ymm3,ymm3,YMMWORD PTR[320+rsi]
	vpxor	ymm7,ymm7,YMMWORD PTR[352+rsi]
	vpxor	ymm11,ymm11,YMMWORD PTR[384+rsi]
	vpxor	ymm9,ymm9,YMMWORD PTR[416+rsi]
	vmovdqu	YMMWORD PTR[rdi],ymm6
	vmovdqu	YMMWORD PTR[32+rdi],ymm8
	vmovdqu	YMMWORD PTR[64+rdi],ymm1
	vmovdqu	YMMWORD PTR[96+rdi],ymm5
	vmovdqu	YMMWORD PTR[128+rdi],ymm12
	vmovdqu	YMMWORD PTR[160+rdi],ymm13
	vmovdqu	YMMWORD PTR[192+rdi],ymm10
	vmovdqu	YMMWORD PTR[224+rdi],ymm15
	vmovdqu	YMMWORD PTR[256+rdi],ymm14
	vmovdqu	YMMWORD PTR[288+rdi],ymm2
	vmovdqu	YMMWORD PTR[320+rdi],ymm3
	vmovdqu	YMMWORD PTR[352+rdi],ymm7
	vmovdqu	YMMWORD PTR[384+rdi],ymm11
	vmovdqu	YMMWORD PTR[416+rdi],ymm9
	je	$L$done8x
	lea	rsi,QWORD PTR[448+rsi]
	xor	r9,r9
	vmovdqa	YMMWORD PTR[rsp],ymm0
	lea	rdi,QWORD PTR[448+rdi]
	sub	rdx,448
	vmovdqa	YMMWORD PTR[32+rsp],ymm4

$L$chacha20_loop_tail8x::
	movzx	eax,BYTE PTR[r9*1+rsi]
	movzx	ecx,BYTE PTR[r9*1+rsp]
	lea	r9,QWORD PTR[1+r9]
	xor	eax,ecx
	mov	BYTE PTR[((-1))+r9*1+rdi],al
	dec	rdx
	jnz	$L$chacha20_loop_tail8x

$L$done8x::
	vzeroall
	movaps	xmm6,XMMWORD PTR[((-168))+r10]
	movaps	xmm7,XMMWORD PTR[((-152))+r10]
	movaps	xmm8,XMMWORD PTR[((-136))+r10]
	movaps	xmm9,XMMWORD PTR[((-120))+r10]
	movaps	xmm10,XMMWORD PTR[((-104))+r10]
	movaps	xmm11,XMMWORD PTR[((-88))+r10]
	movaps	xmm12,XMMWORD PTR[((-72))+r10]
	movaps	xmm13,XMMWORD PTR[((-56))+r10]
	movaps	xmm14,XMMWORD PTR[((-40))+r10]
	movaps	xmm15,XMMWORD PTR[((-24))+r10]
	lea	rsp,QWORD PTR[r10]

$L$avx2_epilogue::
	mov	rdi,QWORD PTR[8+rsp]	;WIN64 epilogue
	mov	rsi,QWORD PTR[16+rsp]
	DB	0F3h,0C3h		;repret

$L$SEH_end_chacha20_avx2::
ChaCha20AVX2	ENDP
PUBLIC	ChaCha20AVX512

ALIGN	32
ChaCha20AVX512	PROC PUBLIC
	DB	243,15,30,250
	mov	QWORD PTR[8+rsp],rdi	;WIN64 prologue
	mov	QWORD PTR[16+rsp],rsi
	mov	rax,rsp
$L$SEH_begin_chacha20_avx512::
	mov	rdi,rcx
	mov	rsi,rdx
	mov	rdx,r8
	mov	rcx,r9
	mov	r8,QWORD PTR[40+rsp]

$L$chacha20_avx512::
	mov	r10,rsp
	cmp	rdx,512
	ja	$L$chacha20_16x
	sub	rsp,64+40
	and	rsp,-16
	movaps	XMMWORD PTR[(-40)+r10],xmm6
	movaps	XMMWORD PTR[(-24)+r10],xmm7
$L$avx512_body::
	vbroadcasti32x4	zmm0,XMMWORD PTR[$L$sigma]
	vbroadcasti32x4	zmm17,XMMWORD PTR[rcx]
	vbroadcasti32x4	zmm18,XMMWORD PTR[16+rcx]
	vbroadcasti32x4	zmm19,XMMWORD PTR[r8]
	vmovdqa32	zmm16,zmm0
	vmovdqa32	zmm20,ZMMWORD PTR[$L$fourz]
	vpaddd	zmm3,zmm19,ZMMWORD PTR[$L$zeroz]
	jmp	$L$chacha20_loop_outer_avx512

ALIGN	32
$L$chacha20_loop_outer_avx512::
	vmovdqa32	zmm1,zmm17
	vmovdqa32	zmm2,zmm18
	vmovdqa32	zmm19,zmm3
	mov	r8,10
	jmp	$L$chacha20_loop_avx512

ALIGN	32
$L$chacha20_loop_avx512::
	vpaddd	zmm0,zmm0,zmm1
	vpxord	zmm3,zmm3,zmm0
	vprold	zmm3,zmm3,16
	vpaddd	zmm2,zmm2,zmm3
	vpxord	zmm1,zmm1,zmm2
	vprold	zmm1,zmm1,12
	vpaddd	zmm0,zmm0,zmm1
	vpxord	zmm3,zmm3,zmm0
	vprold	zmm3,zmm3,8
	vpaddd	zmm2,zmm2,zmm3
	vpxord	zmm1,zmm1,zmm2
	vprold	zmm1,zmm1,7
	vpshufd	zmm2,zmm2,78
	vpshufd	zmm1,zmm1,57
	vpshufd	zmm3,zmm3,147
	vpaddd	zmm0,zmm0,zmm1
	vpxord	zmm3,zmm3,zmm0
	vprold	zmm3,zmm3,16
	vpaddd	zmm2,zmm2,zmm3
	vpxord	zmm1,zmm1,zmm2
	vprold	zmm1,zmm1,12
	vpaddd	zmm0,zmm0,zmm1
	vpxord	zmm3,zmm3,zmm0
	vprold	zmm3,zmm3,8
	vpaddd	zmm2,zmm2,zmm3
	vpxord	zmm1,zmm1,zmm2
	vprold	zmm1,zmm1,7
	vpshufd	zmm2,zmm2,78
	vpshufd	zmm1,zmm1,147
	vpshufd	zmm3,zmm3,57
	dec	r8
	jnz	$L$chacha20_loop_avx512
	vpaddd	zmm0,zmm0,zmm16
	vpaddd	zmm1,zmm1,zmm17
	vpaddd	zmm2,zmm2,zmm18
	vpaddd	zmm3,zmm3,zmm19
	sub	rdx,64
	jb	$L$tail64_avx512
	vpxor	xmm4,xmm0,XMMWORD PTR[rsi]
	vpxor	xmm5,xmm1,XMMWORD PTR[16+rsi]
	vpxor	xmm6,xmm2,XMMWORD PTR[32+rsi]
	vpxor	xmm7,xmm3,XMMWORD PTR[48+rsi]
	lea	rsi,QWORD PTR[64+rsi]
	vmovdqu	XMMWORD PTR[rdi],xmm4
	vmovdqu	XMMWORD PTR[16+rdi],xmm5
	vmovdqu	XMMWORD PTR[32+rdi],xmm6
	vmovdqu	XMMWORD PTR[48+rdi],xmm7
	lea	rdi,QWORD PTR[64+rdi]
	jz	$L$done_avx512
	vextracti32x4	xmm4,zmm0,1
	vextracti32x4	xmm5,zmm1,1
	vextracti32x4	xmm6,zmm2,1
	vextracti32x4	xmm7,zmm3,1
	sub	rdx,64
	jb	$L$tail_avx512
	vpxor	xmm4,xmm4,XMMWORD PTR[rsi]
	vpxor	xmm5,xmm5,XMMWORD PTR[16+rsi]
	vpxor	xmm6,xmm6,XMMWORD PTR[32+rsi]
	vpxor	xmm7,xmm7,XMMWORD PTR[48+rsi]
	lea	rsi,QWORD PTR[64+rsi]
	vmovdqu	XMMWORD PTR[rdi],xmm4
	vmovdqu	XMMWORD PTR[16+rdi],xmm5
	vmovdqu	XMMWORD PTR[32+rdi],xmm6
	vmovdqu	XMMWORD PTR[48+rdi],xmm7
	lea	rdi,QWORD PTR[64+rdi]
	jz	$L$done_avx512
	vextracti32x4	xmm4,zmm0,2
	vextracti32x4	xmm5,zmm1,2
	vextracti32x4	xmm6,zmm2,2
	vextracti32x4	xmm7,zmm3,2
	sub	rdx,64
	jb	$L$tail_avx512
	vpxor	xmm4,xmm4,XMMWORD PTR[rsi]
	vpxor	xmm5,xmm5,XMMWORD PTR[16+rsi]
	vpxor	xmm6,xmm6,XMMWORD PTR[32+rsi]
	vpxor	xmm7,xmm7,XMMWORD PTR[48+rsi]
	lea	rsi,QWORD PTR[64+rsi]
	vmovdqu	XMMWORD PTR[rdi],xmm4
	vmovdqu	XMMWORD PTR[16+rdi],xmm5
	vmovdqu	XMMWORD PTR[32+rdi],xmm6
	vmovdqu	XMMWORD PTR[48+rdi],xmm7
	lea	rdi,QWORD PTR[64+rdi]
	jz	$L$done_avx512
	vextracti32x4	xmm4,zmm0,3
	vextracti32x4	xmm5,zmm1,3
	vextracti32x4	xmm6,zmm2,3
	vextracti32x4	xmm7,zmm3,3
	sub	rdx,64
	jb	$L$tail_avx512
	vmovdqa32	zmm0,zmm16
	vpaddd	zmm3,zmm19,zmm20
	vpxor	xmm4,xmm4,XMMWORD PTR[rsi]
	vpxor	xmm5,xmm5,XMMWORD PTR[16+rsi]
	vpxor	xmm6,xmm6,XMMWORD PTR[32+rsi]
	vpxor	xmm7,xmm7,XMMWORD PTR[48+rsi]
	lea	rsi,QWORD PTR[64+rsi]
	vmovdqu	XMMWORD PTR[rdi],xmm4
	vmovdqu	XMMWORD PTR[16+rdi],xmm5
	vmovdqu	XMMWORD PTR[32+rdi],xmm6
	vmovdqu	XMMWORD PTR[48+rdi],xmm7
	lea	rdi,QWORD PTR[64+rdi]
	jnz	$L$chacha20_loop_outer_avx512
	jmp	$L$done_avx512

ALIGN	16
$L$tail64_avx512::
	vmovdqa	XMMWORD PTR[rsp],xmm0
	vmovdqa	XMMWORD PTR[16+rsp],xmm1
	vmovdqa	XMMWORD PTR[32+rsp],xmm2
	vmovdqa	XMMWORD PTR[48+rsp],xmm3
	add	rdx,64
	jmp	$L$chacha20_loop_tail_avx512

ALIGN	16
$L$tail_avx512::
	vmovdqa	XMMWORD PTR[rsp],xmm4
	vmovdqa	XMMWORD PTR[16+rsp],xmm5
	vmovdqa	XMMWORD PTR[32+rsp],xmm6
	vmovdqa	XMMWORD PTR[48+rsp],xmm7
	add	rdx,64

$L$chacha20_loop_tail_avx512::
	movzx	eax,BYTE PTR[r8*1+rsi]
	movzx	ecx,BYTE PTR[r8*1+rsp]
	lea	r8,QWORD PTR[1+r8]
	xor	eax,ecx
	mov	BYTE PTR[((-1))+r8*1+rdi],al
	dec	rdx
	jnz	$L$chacha20_loop_tail_avx512
	vmovdqu32	ZMMWORD PTR[rsp],zmm16

$L$done_avx512::
	vzeroall
	movaps	xmm6,XMMWORD PTR[((-40))+r10]
	movaps	xmm7,XMMWORD PTR[((-24))+r10]
	lea	rsp,QWORD PTR[r10]

$L$avx512_epilogue::
	mov	rdi,QWORD PTR[8+rsp]	;WIN64 epilogue
	mov	rsi,QWORD PTR[16+rsp]
	DB	0F3h,0C3h		;repret

$L$SEH_end_chacha20_avx512::
ChaCha20AVX512	ENDP
PUBLIC	ChaCha20AVX512VL

ALIGN	32
ChaCha20AVX512VL	PROC PUBLIC
	DB	243,15,30,250
	mov	QWORD PTR[8+rsp],rdi	;WIN64 prologue
	mov	QWORD PTR[16+rsp],rsi
	mov	rax,rsp
$L$SEH_begin_chacha20_avx512vl::
	mov	rdi,rcx
	mov	rsi,rdx
	mov	rdx,r8
	mov	rcx,r9
	mov	r8,QWORD PTR[40+rsp]

$L$chacha20_avx512vl::
	mov	r10,rsp
	cmp	rdx,128
	ja	$L$chacha20_8xvl
	sub	rsp,64+40
	movaps	XMMWORD PTR[(-40)+r10],xmm6
	movaps	XMMWORD PTR[(-24)+r10],xmm7
$L$avx512vl_body::
	vbroadcasti32x4	ymm0,XMMWORD PTR[$L$sigma]
	vbroadcasti32x4	ymm17,XMMWORD PTR[rcx]
	vbroadcasti32x4	ymm18,XMMWORD PTR[16+rcx]
	vbroadcasti32x4	ymm19,XMMWORD PTR[r8]
	vmovdqa32	ymm16,ymm0
	vmovdqa32	ymm20,YMMWORD PTR[$L$twoy]
	vpaddd	ymm3,ymm19,YMMWORD PTR[$L$zeroz]
	jmp	$L$chacha20_loop_outer_avx512vl

ALIGN	32
$L$chacha20_loop_outer_avx512vl::
	vmovdqa32	ymm1,ymm17
	vmovdqa32	ymm2,ymm18
	vmovdqa32	ymm19,ymm3
	mov	r8,10
	jmp	$L$chacha20_loop_avx512vl

ALIGN	32
$L$chacha20_loop_avx512vl::
	vpaddd	ymm0,ymm0,ymm1
	vpxor	ymm3,ymm3,ymm0
	vprold	ymm3,ymm3,16
	vpaddd	ymm2,ymm2,ymm3
	vpxor	ymm1,ymm1,ymm2
	vprold	ymm1,ymm1,12
	vpaddd	ymm0,ymm0,ymm1
	vpxor	ymm3,ymm3,ymm0
	vprold	ymm3,ymm3,8
	vpaddd	ymm2,ymm2,ymm3
	vpxor	ymm1,ymm1,ymm2
	vprold	ymm1,ymm1,7
	vpshufd	ymm2,ymm2,78
	vpshufd	ymm1,ymm1,57
	vpshufd	ymm3,ymm3,147
	vpaddd	ymm0,ymm0,ymm1
	vpxor	ymm3,ymm3,ymm0
	vprold	ymm3,ymm3,16
	vpaddd	ymm2,ymm2,ymm3
	vpxor	ymm1,ymm1,ymm2
	vprold	ymm1,ymm1,12
	vpaddd	ymm0,ymm0,ymm1
	vpxor	ymm3,ymm3,ymm0
	vprold	ymm3,ymm3,8
	vpaddd	ymm2,ymm2,ymm3
	vpxor	ymm1,ymm1,ymm2
	vprold	ymm1,ymm1,7
	vpshufd	ymm2,ymm2,78
	vpshufd	ymm1,ymm1,147
	vpshufd	ymm3,ymm3,57
	sub	r8,1
	jnz	$L$chacha20_loop_avx512vl
	vpaddd	ymm0,ymm0,ymm16
	vpaddd	ymm1,ymm1,ymm17
	vpaddd	ymm2,ymm2,ymm18
	vpaddd	ymm3,ymm3,ymm19
	sub	rdx,64
	jb	$L$tail64_avx512vl
	vpxor	xmm4,xmm0,XMMWORD PTR[rsi]
	vpxor	xmm5,xmm1,XMMWORD PTR[16+rsi]
	vpxor	xmm6,xmm2,XMMWORD PTR[32+rsi]
	vpxor	xmm7,xmm3,XMMWORD PTR[48+rsi]
	lea	rsi,QWORD PTR[64+rsi]
	vmovdqu	XMMWORD PTR[rdi],xmm4
	vmovdqu	XMMWORD PTR[16+rdi],xmm5
	vmovdqu	XMMWORD PTR[32+rdi],xmm6
	vmovdqu	XMMWORD PTR[48+rdi],xmm7
	lea	rdi,QWORD PTR[64+rdi]
	jz	$L$done_avx512vl
	vextracti128	xmm4,ymm0,1
	vextracti128	xmm5,ymm1,1
	vextracti128	xmm6,ymm2,1
	vextracti128	xmm7,ymm3,1
	sub	rdx,64
	jb	$L$tail_avx512vl
	vmovdqa32	ymm0,ymm16
	vpaddd	ymm3,ymm19,ymm20
	vpxor	xmm4,xmm4,XMMWORD PTR[rsi]
	vpxor	xmm5,xmm5,XMMWORD PTR[16+rsi]
	vpxor	xmm6,xmm6,XMMWORD PTR[32+rsi]
	vpxor	xmm7,xmm7,XMMWORD PTR[48+rsi]
	lea	rsi,QWORD PTR[64+rsi]
	vmovdqu	XMMWORD PTR[rdi],xmm4
	vmovdqu	XMMWORD PTR[16+rdi],xmm5
	vmovdqu	XMMWORD PTR[32+rdi],xmm6
	vmovdqu	XMMWORD PTR[48+rdi],xmm7
	lea	rdi,QWORD PTR[64+rdi]
	jnz	$L$chacha20_loop_outer_avx512vl
	jmp	$L$done_avx512vl

ALIGN	16
$L$tail64_avx512vl::
	vmovdqa	XMMWORD PTR[rsp],xmm0
	vmovdqa	XMMWORD PTR[16+rsp],xmm1
	vmovdqa	XMMWORD PTR[32+rsp],xmm2
	vmovdqa	XMMWORD PTR[48+rsp],xmm3
	add	rdx,64
	jmp	$L$chacha20_loop_tail_avx512vl

ALIGN	16
$L$tail_avx512vl::
	vmovdqa	XMMWORD PTR[rsp],xmm4
	vmovdqa	XMMWORD PTR[16+rsp],xmm5
	vmovdqa	XMMWORD PTR[32+rsp],xmm6
	vmovdqa	XMMWORD PTR[48+rsp],xmm7
	add	rdx,64

$L$chacha20_loop_tail_avx512vl::
	movzx	eax,BYTE PTR[r8*1+rsi]
	movzx	ecx,BYTE PTR[r8*1+rsp]
	lea	r8,QWORD PTR[1+r8]
	xor	eax,ecx
	mov	BYTE PTR[((-1))+r8*1+rdi],al
	dec	rdx
	jnz	$L$chacha20_loop_tail_avx512vl
	vmovdqu32	YMMWORD PTR[rsp],ymm16
	vmovdqu32	YMMWORD PTR[32+rsp],ymm16

$L$done_avx512vl::
	vzeroall
	movaps	xmm6,XMMWORD PTR[((-40))+r10]
	movaps	xmm7,XMMWORD PTR[((-24))+r10]
	lea	rsp,QWORD PTR[r10]

$L$avx512vl_epilogue::
	mov	rdi,QWORD PTR[8+rsp]	;WIN64 epilogue
	mov	rsi,QWORD PTR[16+rsp]
	DB	0F3h,0C3h		;repret

$L$SEH_end_chacha20_avx512vl::
ChaCha20AVX512VL	ENDP

ALIGN	32
chacha20_16x	PROC PRIVATE
	DB	243,15,30,250
	mov	QWORD PTR[8+rsp],rdi	;WIN64 prologue
	mov	QWORD PTR[16+rsp],rsi
	mov	rax,rsp
$L$SEH_begin_chacha20_16x::
	mov	rdi,rcx
	mov	rsi,rdx
	mov	rdx,r8
	mov	rcx,r9
	mov	r8,QWORD PTR[40+rsp]

$L$chacha20_16x::
	mov	r10,rsp
	sub	rsp,64+168
	and	rsp,-64
	movaps	XMMWORD PTR[(-168)+r10],xmm6
	movaps	XMMWORD PTR[(-152)+r10],xmm7
	movaps	XMMWORD PTR[(-136)+r10],xmm8
	movaps	XMMWORD PTR[(-120)+r10],xmm9
	movaps	XMMWORD PTR[(-104)+r10],xmm10
	movaps	XMMWORD PTR[(-88)+r10],xmm11
	movaps	XMMWORD PTR[(-72)+r10],xmm12
	movaps	XMMWORD PTR[(-56)+r10],xmm13
	movaps	XMMWORD PTR[(-40)+r10],xmm14
	movaps	XMMWORD PTR[(-24)+r10],xmm15
$L$16x_body::
	vzeroupper
	lea	r9,QWORD PTR[$L$sigma]
	vbroadcasti32x4	zmm3,XMMWORD PTR[r9]
	vbroadcasti32x4	zmm7,XMMWORD PTR[rcx]
	vbroadcasti32x4	zmm11,XMMWORD PTR[16+rcx]
	vbroadcasti32x4	zmm15,XMMWORD PTR[r8]
	vpshufd	zmm0,zmm3,000h
	vpshufd	zmm1,zmm3,055h
	vpshufd	zmm2,zmm3,0aah
	vpshufd	zmm3,zmm3,0ffh
	vmovdqa64	zmm16,zmm0
	vmovdqa64	zmm17,zmm1
	vmovdqa64	zmm18,zmm2
	vmovdqa64	zmm19,zmm3
	vpshufd	zmm4,zmm7,000h
	vpshufd	zmm5,zmm7,055h
	vpshufd	zmm6,zmm7,0aah
	vpshufd	zmm7,zmm7,0ffh
	vmovdqa64	zmm20,zmm4
	vmovdqa64	zmm21,zmm5
	vmovdqa64	zmm22,zmm6
	vmovdqa64	zmm23,zmm7
	vpshufd	zmm8,zmm11,000h
	vpshufd	zmm9,zmm11,055h
	vpshufd	zmm10,zmm11,0aah
	vpshufd	zmm11,zmm11,0ffh
	vmovdqa64	zmm24,zmm8
	vmovdqa64	zmm25,zmm9
	vmovdqa64	zmm26,zmm10
	vmovdqa64	zmm27,zmm11
	vpshufd	zmm12,zmm15,000h
	vpshufd	zmm13,zmm15,055h
	vpshufd	zmm14,zmm15,0aah
	vpshufd	zmm15,zmm15,0ffh
	vpaddd	zmm12,zmm12,ZMMWORD PTR[$L$incz]
	vmovdqa64	zmm28,zmm12
	vmovdqa64	zmm29,zmm13
	vmovdqa64	zmm30,zmm14
	vmovdqa64	zmm31,zmm15
	mov	eax,10
	jmp	$L$chacha20_loop16x

ALIGN	32
$L$chacha20_loop_outer16x::
	vpbroadcastd	zmm0,DWORD PTR[r9]
	vpbroadcastd	zmm1,DWORD PTR[4+r9]
	vpbroadcastd	zmm2,DWORD PTR[8+r9]
	vpbroadcastd	zmm3,DWORD PTR[12+r9]
	vpaddd	zmm28,zmm28,ZMMWORD PTR[$L$sixteen]
	vmovdqa64	zmm4,zmm20
	vmovdqa64	zmm5,zmm21
	vmovdqa64	zmm6,zmm22
	vmovdqa64	zmm7,zmm23
	vmovdqa64	zmm8,zmm24
	vmovdqa64	zmm9,zmm25
	vmovdqa64	zmm10,zmm26
	vmovdqa64	zmm11,zmm27
	vmovdqa64	zmm12,zmm28
	vmovdqa64	zmm13,zmm29
	vmovdqa64	zmm14,zmm30
	vmovdqa64	zmm15,zmm31
	vmovdqa64	zmm16,zmm0
	vmovdqa64	zmm17,zmm1
	vmovdqa64	zmm18,zmm2
	vmovdqa64	zmm19,zmm3
	mov	eax,10
	jmp	$L$chacha20_loop16x

ALIGN	32
$L$chacha20_loop16x::
	vpaddd	zmm0,zmm0,zmm4
	vpaddd	zmm1,zmm1,zmm5
	vpaddd	zmm2,zmm2,zmm6
	vpaddd	zmm3,zmm3,zmm7
	vpxord	zmm12,zmm12,zmm0
	vpxord	zmm13,zmm13,zmm1
	vpxord	zmm14,zmm14,zmm2
	vpxord	zmm15,zmm15,zmm3
	vprold	zmm12,zmm12,16
	vprold	zmm13,zmm13,16
	vprold	zmm14,zmm14,16
	vprold	zmm15,zmm15,16
	vpaddd	zmm8,zmm8,zmm12
	vpaddd	zmm9,zmm9,zmm13
	vpaddd	zmm10,zmm10,zmm14
	vpaddd	zmm11,zmm11,zmm15
	vpxord	zmm4,zmm4,zmm8
	vpxord	zmm5,zmm5,zmm9
	vpxord	zmm6,zmm6,zmm10
	vpxord	zmm7,zmm7,zmm11
	vprold	zmm4,zmm4,12
	vprold	zmm5,zmm5,12
	vprold	zmm6,zmm6,12
	vprold	zmm7,zmm7,12
	vpaddd	zmm0,zmm0,zmm4
	vpaddd	zmm1,zmm1,zmm5
	vpaddd	zmm2,zmm2,zmm6
	vpaddd	zmm3,zmm3,zmm7
	vpxord	zmm12,zmm12,zmm0
	vpxord	zmm13,zmm13,zmm1
	vpxord	zmm14,zmm14,zmm2
	vpxord	zmm15,zmm15,zmm3
	vprold	zmm12,zmm12,8
	vprold	zmm13,zmm13,8
	vprold	zmm14,zmm14,8
	vprold	zmm15,zmm15,8
	vpaddd	zmm8,zmm8,zmm12
	vpaddd	zmm9,zmm9,zmm13
	vpaddd	zmm10,zmm10,zmm14
	vpaddd	zmm11,zmm11,zmm15
	vpxord	zmm4,zmm4,zmm8
	vpxord	zmm5,zmm5,zmm9
	vpxord	zmm6,zmm6,zmm10
	vpxord	zmm7,zmm7,zmm11
	vprold	zmm4,zmm4,7
	vprold	zmm5,zmm5,7
	vprold	zmm6,zmm6,7
	vprold	zmm7,zmm7,7
	vpaddd	zmm0,zmm0,zmm5
	vpaddd	zmm1,zmm1,zmm6
	vpaddd	zmm2,zmm2,zmm7
	vpaddd	zmm3,zmm3,zmm4
	vpxord	zmm15,zmm15,zmm0
	vpxord	zmm12,zmm12,zmm1
	vpxord	zmm13,zmm13,zmm2
	vpxord	zmm14,zmm14,zmm3
	vprold	zmm15,zmm15,16
	vprold	zmm12,zmm12,16
	vprold	zmm13,zmm13,16
	vprold	zmm14,zmm14,16
	vpaddd	zmm10,zmm10,zmm15
	vpaddd	zmm11,zmm11,zmm12
	vpaddd	zmm8,zmm8,zmm13
	vpaddd	zmm9,zmm9,zmm14
	vpxord	zmm5,zmm5,zmm10
	vpxord	zmm6,zmm6,zmm11
	vpxord	zmm7,zmm7,zmm8
	vpxord	zmm4,zmm4,zmm9
	vprold	zmm5,zmm5,12
	vprold	zmm6,zmm6,12
	vprold	zmm7,zmm7,12
	vprold	zmm4,zmm4,12
	vpaddd	zmm0,zmm0,zmm5
	vpaddd	zmm1,zmm1,zmm6
	vpaddd	zmm2,zmm2,zmm7
	vpaddd	zmm3,zmm3,zmm4
	vpxord	zmm15,zmm15,zmm0
	vpxord	zmm12,zmm12,zmm1
	vpxord	zmm13,zmm13,zmm2
	vpxord	zmm14,zmm14,zmm3
	vprold	zmm15,zmm15,8
	vprold	zmm12,zmm12,8
	vprold	zmm13,zmm13,8
	vprold	zmm14,zmm14,8
	vpaddd	zmm10,zmm10,zmm15
	vpaddd	zmm11,zmm11,zmm12
	vpaddd	zmm8,zmm8,zmm13
	vpaddd	zmm9,zmm9,zmm14
	vpxord	zmm5,zmm5,zmm10
	vpxord	zmm6,zmm6,zmm11
	vpxord	zmm7,zmm7,zmm8
	vpxord	zmm4,zmm4,zmm9
	vprold	zmm5,zmm5,7
	vprold	zmm6,zmm6,7
	vprold	zmm7,zmm7,7
	vprold	zmm4,zmm4,7
	dec	eax
	jnz	$L$chacha20_loop16x
	vpaddd	zmm0,zmm0,zmm16
	vpaddd	zmm1,zmm1,zmm17
	vpaddd	zmm2,zmm2,zmm18
	vpaddd	zmm3,zmm3,zmm19
	vpunpckldq	zmm18,zmm0,zmm1
	vpunpckldq	zmm19,zmm2,zmm3
	vpunpckhdq	zmm0,zmm0,zmm1
	vpunpckhdq	zmm2,zmm2,zmm3
	vpunpcklqdq	zmm1,zmm18,zmm19
	vpunpckhqdq	zmm18,zmm18,zmm19
	vpunpcklqdq	zmm3,zmm0,zmm2
	vpunpckhqdq	zmm0,zmm0,zmm2
	vpaddd	zmm4,zmm4,zmm20
	vpaddd	zmm5,zmm5,zmm21
	vpaddd	zmm6,zmm6,zmm22
	vpaddd	zmm7,zmm7,zmm23
	vpunpckldq	zmm2,zmm4,zmm5
	vpunpckldq	zmm19,zmm6,zmm7
	vpunpckhdq	zmm4,zmm4,zmm5
	vpunpckhdq	zmm6,zmm6,zmm7
	vpunpcklqdq	zmm5,zmm2,zmm19
	vpunpckhqdq	zmm2,zmm2,zmm19
	vpunpcklqdq	zmm7,zmm4,zmm6
	vpunpckhqdq	zmm4,zmm4,zmm6
	vshufi32x4	zmm19,zmm1,zmm5,044h
	vshufi32x4	zmm5,zmm1,zmm5,0eeh
	vshufi32x4	zmm1,zmm18,zmm2,044h
	vshufi32x4	zmm2,zmm18,zmm2,0eeh
	vshufi32x4	zmm18,zmm3,zmm7,044h
	vshufi32x4	zmm7,zmm3,zmm7,0eeh
	vshufi32x4	zmm3,zmm0,zmm4,044h
	vshufi32x4	zmm4,zmm0,zmm4,0eeh
	vpaddd	zmm8,zmm8,zmm24
	vpaddd	zmm9,zmm9,zmm25
	vpaddd	zmm10,zmm10,zmm26
	vpaddd	zmm11,zmm11,zmm27
	vpunpckldq	zmm6,zmm8,zmm9
	vpunpckldq	zmm0,zmm10,zmm11
	vpunpckhdq	zmm8,zmm8,zmm9
	vpunpckhdq	zmm10,zmm10,zmm11
	vpunpcklqdq	zmm9,zmm6,zmm0
	vpunpckhqdq	zmm6,zmm6,zmm0
	vpunpcklqdq	zmm11,zmm8,zmm10
	vpunpckhqdq	zmm8,zmm8,zmm10
	vpaddd	zmm12,zmm12,zmm28
	vpaddd	zmm13,zmm13,zmm29
	vpaddd	zmm14,zmm14,zmm30
	vpaddd	zmm15,zmm15,zmm31
	vpunpckldq	zmm10,zmm12,zmm13
	vpunpckldq	zmm0,zmm14,zmm15
	vpunpckhdq	zmm12,zmm12,zmm13
	vpunpckhdq	zmm14,zmm14,zmm15
	vpunpcklqdq	zmm13,zmm10,zmm0
	vpunpckhqdq	zmm10,zmm10,zmm0
	vpunpcklqdq	zmm15,zmm12,zmm14
	vpunpckhqdq	zmm12,zmm12,zmm14
	vshufi32x4	zmm0,zmm9,zmm13,044h
	vshufi32x4	zmm13,zmm9,zmm13,0eeh
	vshufi32x4	zmm9,zmm6,zmm10,044h
	vshufi32x4	zmm10,zmm6,zmm10,0eeh
	vshufi32x4	zmm6,zmm11,zmm15,044h
	vshufi32x4	zmm15,zmm11,zmm15,0eeh
	vshufi32x4	zmm11,zmm8,zmm12,044h
	vshufi32x4	zmm12,zmm8,zmm12,0eeh
	vshufi32x4	zmm16,zmm19,zmm0,088h
	vshufi32x4	zmm19,zmm19,zmm0,0ddh
	vshufi32x4	zmm0,zmm5,zmm13,088h
	vshufi32x4	zmm13,zmm5,zmm13,0ddh
	vshufi32x4	zmm17,zmm1,zmm9,088h
	vshufi32x4	zmm1,zmm1,zmm9,0ddh
	vshufi32x4	zmm9,zmm2,zmm10,088h
	vshufi32x4	zmm10,zmm2,zmm10,0ddh
	vshufi32x4	zmm14,zmm18,zmm6,088h
	vshufi32x4	zmm18,zmm18,zmm6,0ddh
	vshufi32x4	zmm6,zmm7,zmm15,088h
	vshufi32x4	zmm15,zmm7,zmm15,0ddh
	vshufi32x4	zmm8,zmm3,zmm11,088h
	vshufi32x4	zmm3,zmm3,zmm11,0ddh
	vshufi32x4	zmm11,zmm4,zmm12,088h
	vshufi32x4	zmm12,zmm4,zmm12,0ddh
	cmp	rdx,64*16
	jb	$L$tail16x
	vpxord	zmm16,zmm16,ZMMWORD PTR[rsi]
	vpxord	zmm17,zmm17,ZMMWORD PTR[64+rsi]
	vpxord	zmm14,zmm14,ZMMWORD PTR[128+rsi]
	vpxord	zmm8,zmm8,ZMMWORD PTR[192+rsi]
	vmovdqu32	ZMMWORD PTR[rdi],zmm16
	vmovdqu32	ZMMWORD PTR[64+rdi],zmm17
	vmovdqu32	ZMMWORD PTR[128+rdi],zmm14
	vmovdqu32	ZMMWORD PTR[192+rdi],zmm8
	vpxord	zmm19,zmm19,ZMMWORD PTR[256+rsi]
	vpxord	zmm1,zmm1,ZMMWORD PTR[320+rsi]
	vpxord	zmm18,zmm18,ZMMWORD PTR[384+rsi]
	vpxord	zmm3,zmm3,ZMMWORD PTR[448+rsi]
	vmovdqu32	ZMMWORD PTR[256+rdi],zmm19
	vmovdqu32	ZMMWORD PTR[320+rdi],zmm1
	vmovdqu32	ZMMWORD PTR[384+rdi],zmm18
	vmovdqu32	ZMMWORD PTR[448+rdi],zmm3
	vpxord	zmm0,zmm0,ZMMWORD PTR[512+rsi]
	vpxord	zmm9,zmm9,ZMMWORD PTR[576+rsi]
	vpxord	zmm6,zmm6,ZMMWORD PTR[640+rsi]
	vpxord	zmm11,zmm11,ZMMWORD PTR[704+rsi]
	vmovdqu32	ZMMWORD PTR[512+rdi],zmm0
	vmovdqu32	ZMMWORD PTR[576+rdi],zmm9
	vmovdqu32	ZMMWORD PTR[640+rdi],zmm6
	vmovdqu32	ZMMWORD PTR[704+rdi],zmm11
	vpxord	zmm13,zmm13,ZMMWORD PTR[768+rsi]
	vpxord	zmm10,zmm10,ZMMWORD PTR[832+rsi]
	vpxord	zmm15,zmm15,ZMMWORD PTR[896+rsi]
	vpxord	zmm12,zmm12,ZMMWORD PTR[960+rsi]
	lea	rsi,QWORD PTR[1024+rsi]
	vmovdqu32	ZMMWORD PTR[768+rdi],zmm13
	vmovdqu32	ZMMWORD PTR[832+rdi],zmm10
	vmovdqu32	ZMMWORD PTR[896+rdi],zmm15
	vmovdqu32	ZMMWORD PTR[960+rdi],zmm12
	lea	rdi,QWORD PTR[1024+rdi]
	sub	rdx,64*16
	jnz	$L$chacha20_loop_outer16x
	jmp	$L$done16x

ALIGN	32
$L$tail16x::
	xor	r9,r9
	sub	rdi,rsi
	cmp	rdx,64*1
	jb	$L$ess_than_64_16x
	vpxord	zmm16,zmm16,ZMMWORD PTR[rsi]
	vmovdqu32	ZMMWORD PTR[rsi*1+rdi],zmm16
	je	$L$done16x
	vmovdqa32	zmm16,zmm17
	lea	rsi,QWORD PTR[64+rsi]
	cmp	rdx,64*2
	jb	$L$ess_than_64_16x
	vpxord	zmm17,zmm17,ZMMWORD PTR[rsi]
	vmovdqu32	ZMMWORD PTR[rsi*1+rdi],zmm17
	je	$L$done16x
	vmovdqa32	zmm16,zmm14
	lea	rsi,QWORD PTR[64+rsi]
	cmp	rdx,64*3
	jb	$L$ess_than_64_16x
	vpxord	zmm14,zmm14,ZMMWORD PTR[rsi]
	vmovdqu32	ZMMWORD PTR[rsi*1+rdi],zmm14
	je	$L$done16x
	vmovdqa32	zmm16,zmm8
	lea	rsi,QWORD PTR[64+rsi]
	cmp	rdx,64*4
	jb	$L$ess_than_64_16x
	vpxord	zmm8,zmm8,ZMMWORD PTR[rsi]
	vmovdqu32	ZMMWORD PTR[rsi*1+rdi],zmm8
	je	$L$done16x
	vmovdqa32	zmm16,zmm19
	lea	rsi,QWORD PTR[64+rsi]
	cmp	rdx,64*5
	jb	$L$ess_than_64_16x
	vpxord	zmm19,zmm19,ZMMWORD PTR[rsi]
	vmovdqu32	ZMMWORD PTR[rsi*1+rdi],zmm19
	je	$L$done16x
	vmovdqa32	zmm16,zmm1
	lea	rsi,QWORD PTR[64+rsi]
	cmp	rdx,64*6
	jb	$L$ess_than_64_16x
	vpxord	zmm1,zmm1,ZMMWORD PTR[rsi]
	vmovdqu32	ZMMWORD PTR[rsi*1+rdi],zmm1
	je	$L$done16x
	vmovdqa32	zmm16,zmm18
	lea	rsi,QWORD PTR[64+rsi]
	cmp	rdx,64*7
	jb	$L$ess_than_64_16x
	vpxord	zmm18,zmm18,ZMMWORD PTR[rsi]
	vmovdqu32	ZMMWORD PTR[rsi*1+rdi],zmm18
	je	$L$done16x
	vmovdqa32	zmm16,zmm3
	lea	rsi,QWORD PTR[64+rsi]
	cmp	rdx,64*8
	jb	$L$ess_than_64_16x
	vpxord	zmm3,zmm3,ZMMWORD PTR[rsi]
	vmovdqu32	ZMMWORD PTR[rsi*1+rdi],zmm3
	je	$L$done16x
	vmovdqa32	zmm16,zmm0
	lea	rsi,QWORD PTR[64+rsi]
	cmp	rdx,64*9
	jb	$L$ess_than_64_16x
	vpxord	zmm0,zmm0,ZMMWORD PTR[rsi]
	vmovdqu32	ZMMWORD PTR[rsi*1+rdi],zmm0
	je	$L$done16x
	vmovdqa32	zmm16,zmm9
	lea	rsi,QWORD PTR[64+rsi]
	cmp	rdx,64*10
	jb	$L$ess_than_64_16x
	vpxord	zmm9,zmm9,ZMMWORD PTR[rsi]
	vmovdqu32	ZMMWORD PTR[rsi*1+rdi],zmm9
	je	$L$done16x
	vmovdqa32	zmm16,zmm6
	lea	rsi,QWORD PTR[64+rsi]
	cmp	rdx,64*11
	jb	$L$ess_than_64_16x
	vpxord	zmm6,zmm6,ZMMWORD PTR[rsi]
	vmovdqu32	ZMMWORD PTR[rsi*1+rdi],zmm6
	je	$L$done16x
	vmovdqa32	zmm16,zmm11
	lea	rsi,QWORD PTR[64+rsi]
	cmp	rdx,64*12
	jb	$L$ess_than_64_16x
	vpxord	zmm11,zmm11,ZMMWORD PTR[rsi]
	vmovdqu32	ZMMWORD PTR[rsi*1+rdi],zmm11
	je	$L$done16x
	vmovdqa32	zmm16,zmm13
	lea	rsi,QWORD PTR[64+rsi]
	cmp	rdx,64*13
	jb	$L$ess_than_64_16x
	vpxord	zmm13,zmm13,ZMMWORD PTR[rsi]
	vmovdqu32	ZMMWORD PTR[rsi*1+rdi],zmm13
	je	$L$done16x
	vmovdqa32	zmm16,zmm10
	lea	rsi,QWORD PTR[64+rsi]
	cmp	rdx,64*14
	jb	$L$ess_than_64_16x
	vpxord	zmm10,zmm10,ZMMWORD PTR[rsi]
	vmovdqu32	ZMMWORD PTR[rsi*1+rdi],zmm10
	je	$L$done16x
	vmovdqa32	zmm16,zmm15
	lea	rsi,QWORD PTR[64+rsi]
	cmp	rdx,64*15
	jb	$L$ess_than_64_16x
	vpxord	zmm15,zmm15,ZMMWORD PTR[rsi]
	vmovdqu32	ZMMWORD PTR[rsi*1+rdi],zmm15
	je	$L$done16x
	vmovdqa32	zmm16,zmm12
	lea	rsi,QWORD PTR[64+rsi]

$L$ess_than_64_16x::
	vmovdqa32	ZMMWORD PTR[rsp],zmm16
	lea	rdi,QWORD PTR[rsi*1+rdi]
	and	rdx,63

$L$chacha20_loop_tail16x::
	movzx	eax,BYTE PTR[r9*1+rsi]
	movzx	ecx,BYTE PTR[r9*1+rsp]
	lea	r9,QWORD PTR[1+r9]
	xor	eax,ecx
	mov	BYTE PTR[((-1))+r9*1+rdi],al
	dec	rdx
	jnz	$L$chacha20_loop_tail16x
	vpxord	zmm16,zmm16,zmm16
	vmovdqa32	ZMMWORD PTR[rsp],zmm16

$L$done16x::
	vzeroall
	movaps	xmm6,XMMWORD PTR[((-168))+r10]
	movaps	xmm7,XMMWORD PTR[((-152))+r10]
	movaps	xmm8,XMMWORD PTR[((-136))+r10]
	movaps	xmm9,XMMWORD PTR[((-120))+r10]
	movaps	xmm10,XMMWORD PTR[((-104))+r10]
	movaps	xmm11,XMMWORD PTR[((-88))+r10]
	movaps	xmm12,XMMWORD PTR[((-72))+r10]
	movaps	xmm13,XMMWORD PTR[((-56))+r10]
	movaps	xmm14,XMMWORD PTR[((-40))+r10]
	movaps	xmm15,XMMWORD PTR[((-24))+r10]
	lea	rsp,QWORD PTR[r10]

$L$16x_epilogue::
	mov	rdi,QWORD PTR[8+rsp]	;WIN64 epilogue
	mov	rsi,QWORD PTR[16+rsp]
	DB	0F3h,0C3h		;repret

$L$SEH_end_chacha20_16x::
chacha20_16x	ENDP

ALIGN	32
chacha20_8xvl	PROC PRIVATE
	DB	243,15,30,250
	mov	QWORD PTR[8+rsp],rdi	;WIN64 prologue
	mov	QWORD PTR[16+rsp],rsi
	mov	rax,rsp
$L$SEH_begin_chacha20_8xvl::
	mov	rdi,rcx
	mov	rsi,rdx
	mov	rdx,r8
	mov	rcx,r9
	mov	r8,QWORD PTR[40+rsp]

$L$chacha20_8xvl::
	mov	r10,rsp
	sub	rsp,64+168
	and	rsp,-64
	movaps	XMMWORD PTR[(-168)+r10],xmm6
	movaps	XMMWORD PTR[(-152)+r10],xmm7
	movaps	XMMWORD PTR[(-136)+r10],xmm8
	movaps	XMMWORD PTR[(-120)+r10],xmm9
	movaps	XMMWORD PTR[(-104)+r10],xmm10
	movaps	XMMWORD PTR[(-88)+r10],xmm11
	movaps	XMMWORD PTR[(-72)+r10],xmm12
	movaps	XMMWORD PTR[(-56)+r10],xmm13
	movaps	XMMWORD PTR[(-40)+r10],xmm14
	movaps	XMMWORD PTR[(-24)+r10],xmm15
$L$8xvl_body::
	vzeroupper
	lea	r9,QWORD PTR[$L$sigma]
	vbroadcasti128	ymm3,XMMWORD PTR[r9]
	vbroadcasti128	ymm7,XMMWORD PTR[rcx]
	vbroadcasti128	ymm11,XMMWORD PTR[16+rcx]
	vbroadcasti128	ymm15,XMMWORD PTR[r8]
	vpshufd	ymm0,ymm3,000h
	vpshufd	ymm1,ymm3,055h
	vpshufd	ymm2,ymm3,0aah
	vpshufd	ymm3,ymm3,0ffh
	vmovdqa64	ymm16,ymm0
	vmovdqa64	ymm17,ymm1
	vmovdqa64	ymm18,ymm2
	vmovdqa64	ymm19,ymm3
	vpshufd	ymm4,ymm7,000h
	vpshufd	ymm5,ymm7,055h
	vpshufd	ymm6,ymm7,0aah
	vpshufd	ymm7,ymm7,0ffh
	vmovdqa64	ymm20,ymm4
	vmovdqa64	ymm21,ymm5
	vmovdqa64	ymm22,ymm6
	vmovdqa64	ymm23,ymm7
	vpshufd	ymm8,ymm11,000h
	vpshufd	ymm9,ymm11,055h
	vpshufd	ymm10,ymm11,0aah
	vpshufd	ymm11,ymm11,0ffh
	vmovdqa64	ymm24,ymm8
	vmovdqa64	ymm25,ymm9
	vmovdqa64	ymm26,ymm10
	vmovdqa64	ymm27,ymm11
	vpshufd	ymm12,ymm15,000h
	vpshufd	ymm13,ymm15,055h
	vpshufd	ymm14,ymm15,0aah
	vpshufd	ymm15,ymm15,0ffh
	vpaddd	ymm12,ymm12,YMMWORD PTR[$L$incy]
	vmovdqa64	ymm28,ymm12
	vmovdqa64	ymm29,ymm13
	vmovdqa64	ymm30,ymm14
	vmovdqa64	ymm31,ymm15
	mov	eax,10
	jmp	$L$chacha20_loop8xvl

ALIGN	32
$L$chacha20_loop_outer8xvl::
	vpbroadcastd	ymm2,DWORD PTR[8+r9]
	vpbroadcastd	ymm3,DWORD PTR[12+r9]
	vpaddd	ymm28,ymm28,YMMWORD PTR[$L$eight]
	vmovdqa64	ymm4,ymm20
	vmovdqa64	ymm5,ymm21
	vmovdqa64	ymm6,ymm22
	vmovdqa64	ymm7,ymm23
	vmovdqa64	ymm8,ymm24
	vmovdqa64	ymm9,ymm25
	vmovdqa64	ymm10,ymm26
	vmovdqa64	ymm11,ymm27
	vmovdqa64	ymm12,ymm28
	vmovdqa64	ymm13,ymm29
	vmovdqa64	ymm14,ymm30
	vmovdqa64	ymm15,ymm31
	vmovdqa64	ymm16,ymm0
	vmovdqa64	ymm17,ymm1
	vmovdqa64	ymm18,ymm2
	vmovdqa64	ymm19,ymm3
	mov	eax,10
	jmp	$L$chacha20_loop8xvl

ALIGN	32
$L$chacha20_loop8xvl::
	vpaddd	ymm0,ymm0,ymm4
	vpaddd	ymm1,ymm1,ymm5
	vpaddd	ymm2,ymm2,ymm6
	vpaddd	ymm3,ymm3,ymm7
	vpxor	ymm12,ymm12,ymm0
	vpxor	ymm13,ymm13,ymm1
	vpxor	ymm14,ymm14,ymm2
	vpxor	ymm15,ymm15,ymm3
	vprold	ymm12,ymm12,16
	vprold	ymm13,ymm13,16
	vprold	ymm14,ymm14,16
	vprold	ymm15,ymm15,16
	vpaddd	ymm8,ymm8,ymm12
	vpaddd	ymm9,ymm9,ymm13
	vpaddd	ymm10,ymm10,ymm14
	vpaddd	ymm11,ymm11,ymm15
	vpxor	ymm4,ymm4,ymm8
	vpxor	ymm5,ymm5,ymm9
	vpxor	ymm6,ymm6,ymm10
	vpxor	ymm7,ymm7,ymm11
	vprold	ymm4,ymm4,12
	vprold	ymm5,ymm5,12
	vprold	ymm6,ymm6,12
	vprold	ymm7,ymm7,12
	vpaddd	ymm0,ymm0,ymm4
	vpaddd	ymm1,ymm1,ymm5
	vpaddd	ymm2,ymm2,ymm6
	vpaddd	ymm3,ymm3,ymm7
	vpxor	ymm12,ymm12,ymm0
	vpxor	ymm13,ymm13,ymm1
	vpxor	ymm14,ymm14,ymm2
	vpxor	ymm15,ymm15,ymm3
	vprold	ymm12,ymm12,8
	vprold	ymm13,ymm13,8
	vprold	ymm14,ymm14,8
	vprold	ymm15,ymm15,8
	vpaddd	ymm8,ymm8,ymm12
	vpaddd	ymm9,ymm9,ymm13
	vpaddd	ymm10,ymm10,ymm14
	vpaddd	ymm11,ymm11,ymm15
	vpxor	ymm4,ymm4,ymm8
	vpxor	ymm5,ymm5,ymm9
	vpxor	ymm6,ymm6,ymm10
	vpxor	ymm7,ymm7,ymm11
	vprold	ymm4,ymm4,7
	vprold	ymm5,ymm5,7
	vprold	ymm6,ymm6,7
	vprold	ymm7,ymm7,7
	vpaddd	ymm0,ymm0,ymm5
	vpaddd	ymm1,ymm1,ymm6
	vpaddd	ymm2,ymm2,ymm7
	vpaddd	ymm3,ymm3,ymm4
	vpxor	ymm15,ymm15,ymm0
	vpxor	ymm12,ymm12,ymm1
	vpxor	ymm13,ymm13,ymm2
	vpxor	ymm14,ymm14,ymm3
	vprold	ymm15,ymm15,16
	vprold	ymm12,ymm12,16
	vprold	ymm13,ymm13,16
	vprold	ymm14,ymm14,16
	vpaddd	ymm10,ymm10,ymm15
	vpaddd	ymm11,ymm11,ymm12
	vpaddd	ymm8,ymm8,ymm13
	vpaddd	ymm9,ymm9,ymm14
	vpxor	ymm5,ymm5,ymm10
	vpxor	ymm6,ymm6,ymm11
	vpxor	ymm7,ymm7,ymm8
	vpxor	ymm4,ymm4,ymm9
	vprold	ymm5,ymm5,12
	vprold	ymm6,ymm6,12
	vprold	ymm7,ymm7,12
	vprold	ymm4,ymm4,12
	vpaddd	ymm0,ymm0,ymm5
	vpaddd	ymm1,ymm1,ymm6
	vpaddd	ymm2,ymm2,ymm7
	vpaddd	ymm3,ymm3,ymm4
	vpxor	ymm15,ymm15,ymm0
	vpxor	ymm12,ymm12,ymm1
	vpxor	ymm13,ymm13,ymm2
	vpxor	ymm14,ymm14,ymm3
	vprold	ymm15,ymm15,8
	vprold	ymm12,ymm12,8
	vprold	ymm13,ymm13,8
	vprold	ymm14,ymm14,8
	vpaddd	ymm10,ymm10,ymm15
	vpaddd	ymm11,ymm11,ymm12
	vpaddd	ymm8,ymm8,ymm13
	vpaddd	ymm9,ymm9,ymm14
	vpxor	ymm5,ymm5,ymm10
	vpxor	ymm6,ymm6,ymm11
	vpxor	ymm7,ymm7,ymm8
	vpxor	ymm4,ymm4,ymm9
	vprold	ymm5,ymm5,7
	vprold	ymm6,ymm6,7
	vprold	ymm7,ymm7,7
	vprold	ymm4,ymm4,7
	dec	eax
	jnz	$L$chacha20_loop8xvl
	vpaddd	ymm0,ymm0,ymm16
	vpaddd	ymm1,ymm1,ymm17
	vpaddd	ymm2,ymm2,ymm18
	vpaddd	ymm3,ymm3,ymm19
	vpunpckldq	ymm18,ymm0,ymm1
	vpunpckldq	ymm19,ymm2,ymm3
	vpunpckhdq	ymm0,ymm0,ymm1
	vpunpckhdq	ymm2,ymm2,ymm3
	vpunpcklqdq	ymm1,ymm18,ymm19
	vpunpckhqdq	ymm18,ymm18,ymm19
	vpunpcklqdq	ymm3,ymm0,ymm2
	vpunpckhqdq	ymm0,ymm0,ymm2
	vpaddd	ymm4,ymm4,ymm20
	vpaddd	ymm5,ymm5,ymm21
	vpaddd	ymm6,ymm6,ymm22
	vpaddd	ymm7,ymm7,ymm23
	vpunpckldq	ymm2,ymm4,ymm5
	vpunpckldq	ymm19,ymm6,ymm7
	vpunpckhdq	ymm4,ymm4,ymm5
	vpunpckhdq	ymm6,ymm6,ymm7
	vpunpcklqdq	ymm5,ymm2,ymm19
	vpunpckhqdq	ymm2,ymm2,ymm19
	vpunpcklqdq	ymm7,ymm4,ymm6
	vpunpckhqdq	ymm4,ymm4,ymm6
	vshufi32x4	ymm19,ymm1,ymm5,0
	vshufi32x4	ymm5,ymm1,ymm5,3
	vshufi32x4	ymm1,ymm18,ymm2,0
	vshufi32x4	ymm2,ymm18,ymm2,3
	vshufi32x4	ymm18,ymm3,ymm7,0
	vshufi32x4	ymm7,ymm3,ymm7,3
	vshufi32x4	ymm3,ymm0,ymm4,0
	vshufi32x4	ymm4,ymm0,ymm4,3
	vpaddd	ymm8,ymm8,ymm24
	vpaddd	ymm9,ymm9,ymm25
	vpaddd	ymm10,ymm10,ymm26
	vpaddd	ymm11,ymm11,ymm27
	vpunpckldq	ymm6,ymm8,ymm9
	vpunpckldq	ymm0,ymm10,ymm11
	vpunpckhdq	ymm8,ymm8,ymm9
	vpunpckhdq	ymm10,ymm10,ymm11
	vpunpcklqdq	ymm9,ymm6,ymm0
	vpunpckhqdq	ymm6,ymm6,ymm0
	vpunpcklqdq	ymm11,ymm8,ymm10
	vpunpckhqdq	ymm8,ymm8,ymm10
	vpaddd	ymm12,ymm12,ymm28
	vpaddd	ymm13,ymm13,ymm29
	vpaddd	ymm14,ymm14,ymm30
	vpaddd	ymm15,ymm15,ymm31
	vpunpckldq	ymm10,ymm12,ymm13
	vpunpckldq	ymm0,ymm14,ymm15
	vpunpckhdq	ymm12,ymm12,ymm13
	vpunpckhdq	ymm14,ymm14,ymm15
	vpunpcklqdq	ymm13,ymm10,ymm0
	vpunpckhqdq	ymm10,ymm10,ymm0
	vpunpcklqdq	ymm15,ymm12,ymm14
	vpunpckhqdq	ymm12,ymm12,ymm14
	vperm2i128	ymm0,ymm9,ymm13,020h
	vperm2i128	ymm13,ymm9,ymm13,031h
	vperm2i128	ymm9,ymm6,ymm10,020h
	vperm2i128	ymm10,ymm6,ymm10,031h
	vperm2i128	ymm6,ymm11,ymm15,020h
	vperm2i128	ymm15,ymm11,ymm15,031h
	vperm2i128	ymm11,ymm8,ymm12,020h
	vperm2i128	ymm12,ymm8,ymm12,031h
	cmp	rdx,64*8
	jb	$L$tail8xvl
	mov	eax,080h
	vpxord	ymm19,ymm19,YMMWORD PTR[rsi]
	vpxor	ymm0,ymm0,YMMWORD PTR[32+rsi]
	vpxor	ymm5,ymm5,YMMWORD PTR[64+rsi]
	vpxor	ymm13,ymm13,YMMWORD PTR[96+rsi]
	lea	rsi,QWORD PTR[rax*1+rsi]
	vmovdqu32	YMMWORD PTR[rdi],ymm19
	vmovdqu	YMMWORD PTR[32+rdi],ymm0
	vmovdqu	YMMWORD PTR[64+rdi],ymm5
	vmovdqu	YMMWORD PTR[96+rdi],ymm13
	lea	rdi,QWORD PTR[rax*1+rdi]
	vpxor	ymm1,ymm1,YMMWORD PTR[rsi]
	vpxor	ymm9,ymm9,YMMWORD PTR[32+rsi]
	vpxor	ymm2,ymm2,YMMWORD PTR[64+rsi]
	vpxor	ymm10,ymm10,YMMWORD PTR[96+rsi]
	lea	rsi,QWORD PTR[rax*1+rsi]
	vmovdqu	YMMWORD PTR[rdi],ymm1
	vmovdqu	YMMWORD PTR[32+rdi],ymm9
	vmovdqu	YMMWORD PTR[64+rdi],ymm2
	vmovdqu	YMMWORD PTR[96+rdi],ymm10
	lea	rdi,QWORD PTR[rax*1+rdi]
	vpxord	ymm18,ymm18,YMMWORD PTR[rsi]
	vpxor	ymm6,ymm6,YMMWORD PTR[32+rsi]
	vpxor	ymm7,ymm7,YMMWORD PTR[64+rsi]
	vpxor	ymm15,ymm15,YMMWORD PTR[96+rsi]
	lea	rsi,QWORD PTR[rax*1+rsi]
	vmovdqu32	YMMWORD PTR[rdi],ymm18
	vmovdqu	YMMWORD PTR[32+rdi],ymm6
	vmovdqu	YMMWORD PTR[64+rdi],ymm7
	vmovdqu	YMMWORD PTR[96+rdi],ymm15
	lea	rdi,QWORD PTR[rax*1+rdi]
	vpxor	ymm3,ymm3,YMMWORD PTR[rsi]
	vpxor	ymm11,ymm11,YMMWORD PTR[32+rsi]
	vpxor	ymm4,ymm4,YMMWORD PTR[64+rsi]
	vpxor	ymm12,ymm12,YMMWORD PTR[96+rsi]
	lea	rsi,QWORD PTR[rax*1+rsi]
	vmovdqu	YMMWORD PTR[rdi],ymm3
	vmovdqu	YMMWORD PTR[32+rdi],ymm11
	vmovdqu	YMMWORD PTR[64+rdi],ymm4
	vmovdqu	YMMWORD PTR[96+rdi],ymm12
	lea	rdi,QWORD PTR[rax*1+rdi]
	vpbroadcastd	ymm0,DWORD PTR[r9]
	vpbroadcastd	ymm1,DWORD PTR[4+r9]
	sub	rdx,64*8
	jnz	$L$chacha20_loop_outer8xvl
	jmp	$L$done8xvl

ALIGN	32
$L$tail8xvl::
	vmovdqa64	ymm8,ymm19
	xor	r9,r9
	sub	rdi,rsi
	cmp	rdx,64*1
	jb	$L$ess_than_64_8xvl
	vpxor	ymm8,ymm8,YMMWORD PTR[rsi]
	vpxor	ymm0,ymm0,YMMWORD PTR[32+rsi]
	vmovdqu	YMMWORD PTR[rsi*1+rdi],ymm8
	vmovdqu	YMMWORD PTR[32+rsi*1+rdi],ymm0
	je	$L$done8xvl
	vmovdqa	ymm8,ymm5
	vmovdqa	ymm0,ymm13
	lea	rsi,QWORD PTR[64+rsi]
	cmp	rdx,64*2
	jb	$L$ess_than_64_8xvl
	vpxor	ymm5,ymm5,YMMWORD PTR[rsi]
	vpxor	ymm13,ymm13,YMMWORD PTR[32+rsi]
	vmovdqu	YMMWORD PTR[rsi*1+rdi],ymm5
	vmovdqu	YMMWORD PTR[32+rsi*1+rdi],ymm13
	je	$L$done8xvl
	vmovdqa	ymm8,ymm1
	vmovdqa	ymm0,ymm9
	lea	rsi,QWORD PTR[64+rsi]
	cmp	rdx,64*3
	jb	$L$ess_than_64_8xvl
	vpxor	ymm1,ymm1,YMMWORD PTR[rsi]
	vpxor	ymm9,ymm9,YMMWORD PTR[32+rsi]
	vmovdqu	YMMWORD PTR[rsi*1+rdi],ymm1
	vmovdqu	YMMWORD PTR[32+rsi*1+rdi],ymm9
	je	$L$done8xvl
	vmovdqa	ymm8,ymm2
	vmovdqa	ymm0,ymm10
	lea	rsi,QWORD PTR[64+rsi]
	cmp	rdx,64*4
	jb	$L$ess_than_64_8xvl
	vpxor	ymm2,ymm2,YMMWORD PTR[rsi]
	vpxor	ymm10,ymm10,YMMWORD PTR[32+rsi]
	vmovdqu	YMMWORD PTR[rsi*1+rdi],ymm2
	vmovdqu	YMMWORD PTR[32+rsi*1+rdi],ymm10
	je	$L$done8xvl
	vmovdqa32	ymm8,ymm18
	vmovdqa	ymm0,ymm6
	lea	rsi,QWORD PTR[64+rsi]
	cmp	rdx,64*5
	jb	$L$ess_than_64_8xvl
	vpxord	ymm18,ymm18,YMMWORD PTR[rsi]
	vpxor	ymm6,ymm6,YMMWORD PTR[32+rsi]
	vmovdqu32	YMMWORD PTR[rsi*1+rdi],ymm18
	vmovdqu	YMMWORD PTR[32+rsi*1+rdi],ymm6
	je	$L$done8xvl
	vmovdqa	ymm8,ymm7
	vmovdqa	ymm0,ymm15
	lea	rsi,QWORD PTR[64+rsi]
	cmp	rdx,64*6
	jb	$L$ess_than_64_8xvl
	vpxor	ymm7,ymm7,YMMWORD PTR[rsi]
	vpxor	ymm15,ymm15,YMMWORD PTR[32+rsi]
	vmovdqu	YMMWORD PTR[rsi*1+rdi],ymm7
	vmovdqu	YMMWORD PTR[32+rsi*1+rdi],ymm15
	je	$L$done8xvl
	vmovdqa	ymm8,ymm3
	vmovdqa	ymm0,ymm11
	lea	rsi,QWORD PTR[64+rsi]
	cmp	rdx,64*7
	jb	$L$ess_than_64_8xvl
	vpxor	ymm3,ymm3,YMMWORD PTR[rsi]
	vpxor	ymm11,ymm11,YMMWORD PTR[32+rsi]
	vmovdqu	YMMWORD PTR[rsi*1+rdi],ymm3
	vmovdqu	YMMWORD PTR[32+rsi*1+rdi],ymm11
	je	$L$done8xvl
	vmovdqa	ymm8,ymm4
	vmovdqa	ymm0,ymm12
	lea	rsi,QWORD PTR[64+rsi]

$L$ess_than_64_8xvl::
	vmovdqa	YMMWORD PTR[rsp],ymm8
	vmovdqa	YMMWORD PTR[32+rsp],ymm0
	lea	rdi,QWORD PTR[rsi*1+rdi]
	and	rdx,63

$L$chacha20_loop_tail8xvl::
	movzx	eax,BYTE PTR[r9*1+rsi]
	movzx	ecx,BYTE PTR[r9*1+rsp]
	lea	r9,QWORD PTR[1+r9]
	xor	eax,ecx
	mov	BYTE PTR[((-1))+r9*1+rdi],al
	dec	rdx
	jnz	$L$chacha20_loop_tail8xvl
	vpxor	ymm8,ymm8,ymm8
	vmovdqa	YMMWORD PTR[rsp],ymm8
	vmovdqa	YMMWORD PTR[32+rsp],ymm8

$L$done8xvl::
	vzeroall
	movaps	xmm6,XMMWORD PTR[((-168))+r10]
	movaps	xmm7,XMMWORD PTR[((-152))+r10]
	movaps	xmm8,XMMWORD PTR[((-136))+r10]
	movaps	xmm9,XMMWORD PTR[((-120))+r10]
	movaps	xmm10,XMMWORD PTR[((-104))+r10]
	movaps	xmm11,XMMWORD PTR[((-88))+r10]
	movaps	xmm12,XMMWORD PTR[((-72))+r10]
	movaps	xmm13,XMMWORD PTR[((-56))+r10]
	movaps	xmm14,XMMWORD PTR[((-40))+r10]
	movaps	xmm15,XMMWORD PTR[((-24))+r10]
	lea	rsp,QWORD PTR[r10]

$L$8xvl_epilogue::
	mov	rdi,QWORD PTR[8+rsp]	;WIN64 epilogue
	mov	rsi,QWORD PTR[16+rsp]
	DB	0F3h,0C3h		;repret

$L$SEH_end_chacha20_8xvl::
chacha20_8xvl	ENDP

ALIGN	16
chacha20_se_handler	PROC PRIVATE
	DB	243,15,30,250
	push	rsi
	push	rdi
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	pushfq
	sub	rsp,64
	mov	rax,QWORD PTR[120+r8]
	mov	rbx,QWORD PTR[248+r8]
	mov	rsi,QWORD PTR[8+r9]
	mov	r11,QWORD PTR[56+r9]
	lea	r10,QWORD PTR[$L$ctr32_body]
	cmp	rbx,r10
	jb	$L$chacha20_common_seh_tail
	mov	rax,QWORD PTR[152+r8]
	lea	r10,QWORD PTR[$L$chacha20_no_data]
	cmp	rbx,r10
	jae	$L$chacha20_common_seh_tail
	lea	rax,QWORD PTR[((64+24+48))+rax]
	mov	rbx,QWORD PTR[((-8))+rax]
	mov	rbp,QWORD PTR[((-16))+rax]
	mov	r12,QWORD PTR[((-24))+rax]
	mov	r13,QWORD PTR[((-32))+rax]
	mov	r14,QWORD PTR[((-40))+rax]
	mov	r15,QWORD PTR[((-48))+rax]
	mov	QWORD PTR[144+r8],rbx
	mov	QWORD PTR[160+r8],rbp
	mov	QWORD PTR[216+r8],r12
	mov	QWORD PTR[224+r8],r13
	mov	QWORD PTR[232+r8],r14
	mov	QWORD PTR[240+r8],r15

$L$chacha20_common_seh_tail::
	mov	rdi,QWORD PTR[8+rax]
	mov	rsi,QWORD PTR[16+rax]
	mov	QWORD PTR[152+r8],rax
	mov	QWORD PTR[168+r8],rsi
	mov	QWORD PTR[176+r8],rdi
	mov	rdi,QWORD PTR[40+r9]
	mov	rsi,r8
	mov	ecx,154
	DD	0a548f3fch
	mov	rsi,r9
	xor	rcx,rcx
	mov	rdx,QWORD PTR[8+rsi]
	mov	r8,QWORD PTR[rsi]
	mov	r9,QWORD PTR[16+rsi]
	mov	r10,QWORD PTR[40+rsi]
	lea	r11,QWORD PTR[56+rsi]
	lea	r12,QWORD PTR[24+rsi]
	mov	QWORD PTR[32+rsp],r10
	mov	QWORD PTR[40+rsp],r11
	mov	QWORD PTR[48+rsp],r12
	mov	QWORD PTR[56+rsp],rcx
	call	QWORD PTR[__imp_RtlVirtualUnwind]
	mov	eax,1
	add	rsp,64
	popfq
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	pop	rdi
	pop	rsi
	DB	0F3h,0C3h		;repret
chacha20_se_handler	ENDP

ALIGN	16
chacha20_simd_handler	PROC PRIVATE
	DB	243,15,30,250
	push	rsi
	push	rdi
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	pushfq
	sub	rsp,64
	mov	rax,QWORD PTR[120+r8]
	mov	rbx,QWORD PTR[248+r8]
	mov	rsi,QWORD PTR[8+r9]
	mov	r11,QWORD PTR[56+r9]
	mov	r10d,DWORD PTR[r11]
	lea	r10,QWORD PTR[r10*1+rsi]
	cmp	rbx,r10
	jb	$L$chacha20_common_seh_tail
	mov	rax,QWORD PTR[200+r8]
	mov	r10d,DWORD PTR[4+r11]
	mov	ecx,DWORD PTR[8+r11]
	lea	r10,QWORD PTR[r10*1+rsi]
	cmp	rbx,r10
	jae	$L$chacha20_common_seh_tail
	neg	rcx
	lea	rsi,QWORD PTR[((-8))+rcx*1+rax]
	lea	rdi,QWORD PTR[512+r8]
	neg	ecx
	shr	ecx,3
	DD	0a548f3fch
	jmp	$L$chacha20_common_seh_tail
chacha20_simd_handler	ENDP

PUBLIC	Poly1305InitALU
PUBLIC	Poly1305InitAVX512IFMA
PUBLIC	Poly1305BlocksALU
PUBLIC	Poly1305BlocksAVX
PUBLIC	Poly1305BlocksAVX2
PUBLIC	Poly1305BlocksAVX512IFMA
PUBLIC	Poly1305EmitALU
PUBLIC	Poly1305EmitAVX512IFMA

ALIGN	32
Poly1305InitALU	PROC PUBLIC
	DB	243,15,30,250
	mov	QWORD PTR[8+rsp],rdi	;WIN64 prologue
	mov	QWORD PTR[16+rsp],rsi
	mov	rax,rsp
$L$SEH_begin_poly1305_init::
	mov	rdi,rcx
	mov	rsi,rdx
	mov	rdx,r8
	xor	rax,rax
	mov	QWORD PTR[rdi],rax
	mov	QWORD PTR[8+rdi],rax
	mov	QWORD PTR[16+rdi],rax
	mov	rax,00ffffffc0fffffffh
	lea	rcx,QWORD PTR[((-3))+rax]
	and	rax,QWORD PTR[rsi]
	and	rcx,QWORD PTR[8+rsi]
	mov	QWORD PTR[24+rdi],rax
	mov	QWORD PTR[32+rdi],rcx
	mov	DWORD PTR[48+rdi],-1
	mov	rdi,QWORD PTR[8+rsp]	;WIN64 epilogue
	mov	rsi,QWORD PTR[16+rsp]
	DB	0F3h,0C3h		;repret
$L$SEH_end_poly1305_init::
Poly1305InitALU	ENDP

ALIGN	32
Poly1305BlocksALU	PROC PUBLIC
	DB	243,15,30,250
	mov	QWORD PTR[8+rsp],rdi	;WIN64 prologue
	mov	QWORD PTR[16+rsp],rsi
	mov	rax,rsp
$L$SEH_begin_poly1305_blocks::
	mov	rdi,rcx
	mov	rsi,rdx
	mov	rdx,r8
	mov	rcx,r9

$L$blocks::
	shr	rdx,4
	jz	$L$poly1305_no_data
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	lea	rsp,QWORD PTR[((-8))+rsp]

$L$blocks_body::
	mov	r15,rdx
	mov	r11,QWORD PTR[24+rdi]
	mov	r13,QWORD PTR[32+rdi]
	mov	r14,QWORD PTR[rdi]
	mov	rbx,QWORD PTR[8+rdi]
	mov	rbp,QWORD PTR[16+rdi]
	mov	eax,r14d
	mov	edx,DWORD PTR[4+rdi]
	mov	r8d,ebx
	mov	r10d,DWORD PTR[12+rdi]
	mov	r12d,ebp
	shl	rdx,26
	mov	r9,r8
	shl	r8,52
	add	rax,rdx
	shr	r9,12
	add	r8,rax
	adc	r9,0
	shl	r10,14
	mov	rax,r12
	shr	r12,24
	add	r9,r10
	shl	rax,40
	add	r9,rax
	adc	r12,0
	cmp	rbp,4
	cmova	r14,r8
	cmova	rbx,r9
	cmova	rbp,r12
	mov	r12,r13
	shr	r13,2
	mov	rax,r12
	add	r13,r12
	jmp	$L$poly1305_loop

ALIGN	32
$L$poly1305_loop::
	add	r14,QWORD PTR[rsi]
	adc	rbx,QWORD PTR[8+rsi]
	lea	rsi,QWORD PTR[16+rsi]
	adc	rbp,rcx
	mul	r14
	mov	r9,rax
	mov	rax,r11
	mov	r10,rdx
	mul	r14
	mov	r14,rax
	mov	rax,r11
	mov	r8,rdx
	mul	rbx
	add	r9,rax
	mov	rax,r13
	adc	r10,rdx
	mul	rbx
	mov	rbx,rbp
	add	r14,rax
	adc	r8,rdx
	imul	rbx,r13
	add	r9,rbx
	mov	rbx,r8
	adc	r10,0
	imul	rbp,r11
	add	rbx,r9
	mov	rax,-4
	adc	r10,rbp
	and	rax,r10
	mov	rbp,r10
	shr	r10,2
	and	rbp,3
	add	rax,r10
	add	r14,rax
	adc	rbx,0
	adc	rbp,0
	mov	rax,r12
	dec	r15
	jnz	$L$poly1305_loop
	mov	QWORD PTR[rdi],r14
	mov	QWORD PTR[8+rdi],rbx
	mov	QWORD PTR[16+rdi],rbp
	mov	r15,QWORD PTR[8+rsp]
	mov	r14,QWORD PTR[16+rsp]
	mov	r13,QWORD PTR[24+rsp]
	mov	r12,QWORD PTR[32+rsp]
	mov	rbp,QWORD PTR[40+rsp]
	mov	rbx,QWORD PTR[48+rsp]
	lea	rsp,QWORD PTR[56+rsp]

$L$poly1305_no_data::
$L$blocks_epilogue::
	mov	rdi,QWORD PTR[8+rsp]	;WIN64 epilogue
	mov	rsi,QWORD PTR[16+rsp]
	DB	0F3h,0C3h		;repret

$L$SEH_end_poly1305_blocks::
Poly1305BlocksALU	ENDP

ALIGN	32
Poly1305EmitALU	PROC PUBLIC
	DB	243,15,30,250
	mov	QWORD PTR[8+rsp],rdi	;WIN64 prologue
	mov	QWORD PTR[16+rsp],rsi
	mov	rax,rsp
$L$SEH_begin_poly1305_emit::
	mov	rdi,rcx
	mov	rsi,rdx
	mov	rdx,r8
	mov	eax,DWORD PTR[rdi]
	mov	ecx,DWORD PTR[4+rdi]
	mov	r8d,DWORD PTR[8+rdi]
	mov	r11d,DWORD PTR[12+rdi]
	mov	r10d,DWORD PTR[16+rdi]
	shl	rcx,26
	mov	r9,r8
	shl	r8,52
	add	rax,rcx
	shr	r9,12
	add	r8,rax
	adc	r9,0
	shl	r11,14
	mov	rax,r10
	shr	r10,24
	add	r9,r11
	mov	rcx,QWORD PTR[rdi]
	shl	rax,40
	mov	r11,QWORD PTR[8+rdi]
	add	r9,rax
	mov	rax,QWORD PTR[16+rdi]
	adc	r10,0
	cmp	rax,4
	cmovbe	r8,rcx
	cmovbe	r9,r11
	cmovbe	r10,rax
	mov	rax,r8
	add	r8,5
	mov	rcx,r9
	adc	r9,0
	adc	r10,0
	shr	r10,2
	cmovnz	rax,r8
	cmovnz	rcx,r9
	add	rax,QWORD PTR[rdx]
	adc	rcx,QWORD PTR[8+rdx]
	mov	QWORD PTR[rsi],rax
	mov	QWORD PTR[8+rsi],rcx
	mov	rdi,QWORD PTR[8+rsp]	;WIN64 epilogue
	mov	rsi,QWORD PTR[16+rsp]
	DB	0F3h,0C3h		;repret
$L$SEH_end_poly1305_emit::
Poly1305EmitALU	ENDP

ALIGN	32
__poly1305_block	PROC PRIVATE
	DB	243,15,30,250
	mul	r14
	mov	r9,rax
	mov	rax,r11
	mov	r10,rdx
	mul	r14
	mov	r14,rax
	mov	rax,r11
	mov	r8,rdx
	mul	rbx
	add	r9,rax
	mov	rax,r13
	adc	r10,rdx
	mul	rbx
	mov	rbx,rbp
	add	r14,rax
	adc	r8,rdx
	imul	rbx,r13
	add	r9,rbx
	mov	rbx,r8
	adc	r10,0
	imul	rbp,r11
	add	rbx,r9
	mov	rax,-4
	adc	r10,rbp
	and	rax,r10
	mov	rbp,r10
	shr	r10,2
	and	rbp,3
	add	rax,r10
	add	r14,rax
	adc	rbx,0
	adc	rbp,0
	DB	0F3h,0C3h		;repret
__poly1305_block	ENDP

ALIGN	32
__poly1305_init_avx	PROC PRIVATE
	DB	243,15,30,250
	cmp	DWORD PTR[48+rdi],-1
	jne	$L$done_init_avx
	mov	r14,r11
	mov	rbx,r12
	xor	rbp,rbp
	lea	rdi,QWORD PTR[((48+64))+rdi]
	mov	rax,r12
	call	__poly1305_block
	mov	eax,03ffffffh
	mov	edx,03ffffffh
	mov	r8,r14
	and	eax,r14d
	mov	r9,r11
	and	edx,r11d
	mov	DWORD PTR[((-64))+rdi],eax
	shr	r8,26
	mov	DWORD PTR[((-60))+rdi],edx
	shr	r9,26
	mov	eax,03ffffffh
	mov	edx,03ffffffh
	and	eax,r8d
	and	edx,r9d
	mov	DWORD PTR[((-48))+rdi],eax
	lea	eax,DWORD PTR[rax*4+rax]
	mov	DWORD PTR[((-44))+rdi],edx
	lea	edx,DWORD PTR[rdx*4+rdx]
	mov	DWORD PTR[((-32))+rdi],eax
	shr	r8,26
	mov	DWORD PTR[((-28))+rdi],edx
	shr	r9,26
	mov	rax,rbx
	mov	rdx,r12
	shl	rax,12
	shl	rdx,12
	or	rax,r8
	or	rdx,r9
	and	eax,03ffffffh
	and	edx,03ffffffh
	mov	DWORD PTR[((-16))+rdi],eax
	lea	eax,DWORD PTR[rax*4+rax]
	mov	DWORD PTR[((-12))+rdi],edx
	lea	edx,DWORD PTR[rdx*4+rdx]
	mov	DWORD PTR[rdi],eax
	mov	r8,rbx
	mov	DWORD PTR[4+rdi],edx
	mov	r9,r12
	mov	eax,03ffffffh
	mov	edx,03ffffffh
	shr	r8,14
	shr	r9,14
	and	eax,r8d
	and	edx,r9d
	mov	DWORD PTR[16+rdi],eax
	lea	eax,DWORD PTR[rax*4+rax]
	mov	DWORD PTR[20+rdi],edx
	lea	edx,DWORD PTR[rdx*4+rdx]
	mov	DWORD PTR[32+rdi],eax
	shr	r8,26
	mov	DWORD PTR[36+rdi],edx
	shr	r9,26
	mov	rax,rbp
	shl	rax,24
	or	r8,rax
	mov	DWORD PTR[48+rdi],r8d
	lea	r8,QWORD PTR[r8*4+r8]
	mov	DWORD PTR[52+rdi],r9d
	lea	r9,QWORD PTR[r9*4+r9]
	mov	DWORD PTR[64+rdi],r8d
	mov	DWORD PTR[68+rdi],r9d
	mov	rax,r12
	call	__poly1305_block
	mov	eax,03ffffffh
	mov	r8,r14
	and	eax,r14d
	shr	r8,26
	mov	DWORD PTR[((-52))+rdi],eax
	mov	edx,03ffffffh
	and	edx,r8d
	mov	DWORD PTR[((-36))+rdi],edx
	lea	edx,DWORD PTR[rdx*4+rdx]
	shr	r8,26
	mov	DWORD PTR[((-20))+rdi],edx
	mov	rax,rbx
	shl	rax,12
	or	rax,r8
	and	eax,03ffffffh
	mov	DWORD PTR[((-4))+rdi],eax
	lea	eax,DWORD PTR[rax*4+rax]
	mov	r8,rbx
	mov	DWORD PTR[12+rdi],eax
	mov	edx,03ffffffh
	shr	r8,14
	and	edx,r8d
	mov	DWORD PTR[28+rdi],edx
	lea	edx,DWORD PTR[rdx*4+rdx]
	shr	r8,26
	mov	DWORD PTR[44+rdi],edx
	mov	rax,rbp
	shl	rax,24
	or	r8,rax
	mov	DWORD PTR[60+rdi],r8d
	lea	r8,QWORD PTR[r8*4+r8]
	mov	DWORD PTR[76+rdi],r8d
	mov	rax,r12
	call	__poly1305_block
	mov	eax,03ffffffh
	mov	r8,r14
	and	eax,r14d
	shr	r8,26
	mov	DWORD PTR[((-56))+rdi],eax
	mov	edx,03ffffffh
	and	edx,r8d
	mov	DWORD PTR[((-40))+rdi],edx
	lea	edx,DWORD PTR[rdx*4+rdx]
	shr	r8,26
	mov	DWORD PTR[((-24))+rdi],edx
	mov	rax,rbx
	shl	rax,12
	or	rax,r8
	and	eax,03ffffffh
	mov	DWORD PTR[((-8))+rdi],eax
	lea	eax,DWORD PTR[rax*4+rax]
	mov	r8,rbx
	mov	DWORD PTR[8+rdi],eax
	mov	edx,03ffffffh
	shr	r8,14
	and	edx,r8d
	mov	DWORD PTR[24+rdi],edx
	lea	edx,DWORD PTR[rdx*4+rdx]
	shr	r8,26
	mov	DWORD PTR[40+rdi],edx
	mov	rax,rbp
	shl	rax,24
	or	r8,rax
	mov	DWORD PTR[56+rdi],r8d
	lea	r8,QWORD PTR[r8*4+r8]
	mov	DWORD PTR[72+rdi],r8d
	lea	rdi,QWORD PTR[((-48-64))+rdi]
$L$done_init_avx::
	DB	0F3h,0C3h		;repret
__poly1305_init_avx	ENDP

ALIGN	32
Poly1305BlocksAVX	PROC PUBLIC
	DB	243,15,30,250
	mov	QWORD PTR[8+rsp],rdi	;WIN64 prologue
	mov	QWORD PTR[16+rsp],rsi
	mov	rax,rsp
$L$SEH_begin_poly1305_blocks_avx::
	mov	rdi,rcx
	mov	rsi,rdx
	mov	rdx,r8
	mov	rcx,r9
	mov	r8d,DWORD PTR[20+rdi]
	cmp	rdx,128
	jb	$L$blocks
	and	rdx,-16
	vzeroupper
	test	r8d,r8d
	jz	$L$base2_64_avx
	test	rdx,31
	jz	$L$even_avx
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	lea	rsp,QWORD PTR[((-8))+rsp]

$L$blocks_avx_body::
	mov	r15,rdx
	mov	r8,QWORD PTR[rdi]
	mov	r9,QWORD PTR[8+rdi]
	mov	ebp,DWORD PTR[16+rdi]
	mov	r11,QWORD PTR[24+rdi]
	mov	r13,QWORD PTR[32+rdi]
	mov	r14d,r8d
	and	r8,-2147483648
	mov	r12,r9
	mov	ebx,r9d
	and	r9,-2147483648
	shr	r8,6
	shl	r12,52
	add	r14,r8
	shr	rbx,12
	shr	r9,18
	add	r14,r12
	adc	rbx,r9
	mov	r8,rbp
	shl	r8,40
	shr	rbp,24
	add	rbx,r8
	adc	rbp,0
	mov	r12,r13
	mov	rax,r13
	shr	r13,2
	add	r13,r12
	add	r14,QWORD PTR[rsi]
	adc	rbx,QWORD PTR[8+rsi]
	lea	rsi,QWORD PTR[16+rsi]
	adc	rbp,rcx
	call	__poly1305_block
	mov	rax,r14
	mov	rdx,r14
	shr	r14,52
	mov	r11,rbx
	mov	r12,rbx
	shr	rdx,26
	and	rax,03ffffffh
	shl	r11,12
	and	rdx,03ffffffh
	shr	rbx,14
	or	r14,r11
	shl	rbp,24
	and	r14,03ffffffh
	shr	r12,40
	and	rbx,03ffffffh
	or	rbp,r12
	vmovd	xmm0,eax
	vmovd	xmm1,edx
	vmovd	xmm2,r14d
	vmovd	xmm3,ebx
	vmovd	xmm4,ebp
	lea	rdx,QWORD PTR[((-16))+r15]
	mov	r15,QWORD PTR[8+rsp]
	mov	r14,QWORD PTR[16+rsp]
	mov	r13,QWORD PTR[24+rsp]
	mov	r12,QWORD PTR[32+rsp]
	mov	rbp,QWORD PTR[40+rsp]
	mov	rbx,QWORD PTR[48+rsp]
	lea	rax,QWORD PTR[56+rsp]
	lea	rsp,QWORD PTR[56+rsp]

$L$blocks_avx_epilogue::
	jmp	$L$do_avx

ALIGN	32
$L$base2_64_avx::
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	lea	rsp,QWORD PTR[((-8))+rsp]

$L$base2_64_avx_body::
	mov	r15,rdx
	mov	r11,QWORD PTR[24+rdi]
	mov	r13,QWORD PTR[32+rdi]
	mov	r14,QWORD PTR[rdi]
	mov	rbx,QWORD PTR[8+rdi]
	mov	ebp,DWORD PTR[16+rdi]
	mov	r12,r13
	mov	rax,r13
	shr	r13,2
	add	r13,r12
	test	rdx,31
	jz	$L$init_avx
	add	r14,QWORD PTR[rsi]
	adc	rbx,QWORD PTR[8+rsi]
	lea	rsi,QWORD PTR[16+rsi]
	adc	rbp,rcx
	sub	r15,16
	call	__poly1305_block

$L$init_avx::
	mov	rax,r14
	mov	rdx,r14
	shr	r14,52
	mov	r8,rbx
	mov	r9,rbx
	shr	rdx,26
	and	rax,03ffffffh
	shl	r8,12
	and	rdx,03ffffffh
	shr	rbx,14
	or	r14,r8
	shl	rbp,24
	and	r14,03ffffffh
	shr	r9,40
	and	rbx,03ffffffh
	or	rbp,r9
	vmovd	xmm0,eax
	vmovd	xmm1,edx
	vmovd	xmm2,r14d
	vmovd	xmm3,ebx
	vmovd	xmm4,ebp
	mov	DWORD PTR[20+rdi],1
	call	__poly1305_init_avx
	mov	rdx,r15
	mov	r15,QWORD PTR[8+rsp]
	mov	r14,QWORD PTR[16+rsp]
	mov	r13,QWORD PTR[24+rsp]
	mov	r12,QWORD PTR[32+rsp]
	mov	rbp,QWORD PTR[40+rsp]
	mov	rbx,QWORD PTR[48+rsp]
	lea	rax,QWORD PTR[56+rsp]
	lea	rsp,QWORD PTR[56+rsp]

$L$base2_64_avx_epilogue::
	jmp	$L$do_avx

ALIGN	32
$L$even_avx::
	vmovd	xmm0,DWORD PTR[rdi]
	vmovd	xmm1,DWORD PTR[4+rdi]
	vmovd	xmm2,DWORD PTR[8+rdi]
	vmovd	xmm3,DWORD PTR[12+rdi]
	vmovd	xmm4,DWORD PTR[16+rdi]

$L$do_avx::
	lea	r11,QWORD PTR[((-248))+rsp]
	sub	rsp,0218h
	vmovdqa	XMMWORD PTR[80+r11],xmm6
	vmovdqa	XMMWORD PTR[96+r11],xmm7
	vmovdqa	XMMWORD PTR[112+r11],xmm8
	vmovdqa	XMMWORD PTR[128+r11],xmm9
	vmovdqa	XMMWORD PTR[144+r11],xmm10
	vmovdqa	XMMWORD PTR[160+r11],xmm11
	vmovdqa	XMMWORD PTR[176+r11],xmm12
	vmovdqa	XMMWORD PTR[192+r11],xmm13
	vmovdqa	XMMWORD PTR[208+r11],xmm14
	vmovdqa	XMMWORD PTR[224+r11],xmm15
$L$do_avx_body::
	sub	rdx,64
	lea	rax,QWORD PTR[((-32))+rsi]
	cmovc	rsi,rax
	vmovdqu	xmm14,XMMWORD PTR[48+rdi]
	lea	rdi,QWORD PTR[112+rdi]
	lea	rcx,QWORD PTR[$L$const]
	vmovdqu	xmm5,XMMWORD PTR[32+rsi]
	vmovdqu	xmm6,XMMWORD PTR[48+rsi]
	vmovdqa	xmm15,XMMWORD PTR[64+rcx]
	vpsrldq	xmm7,xmm5,6
	vpsrldq	xmm8,xmm6,6
	vpunpckhqdq	xmm9,xmm5,xmm6
	vpunpcklqdq	xmm5,xmm5,xmm6
	vpunpcklqdq	xmm8,xmm7,xmm8
	vpsrlq	xmm9,xmm9,40
	vpsrlq	xmm6,xmm5,26
	vpand	xmm5,xmm5,xmm15
	vpsrlq	xmm7,xmm8,4
	vpand	xmm6,xmm6,xmm15
	vpsrlq	xmm8,xmm8,30
	vpand	xmm7,xmm7,xmm15
	vpand	xmm8,xmm8,xmm15
	vpor	xmm9,xmm9,XMMWORD PTR[32+rcx]
	jbe	$L$skip_loop_avx
	vmovdqu	xmm11,XMMWORD PTR[((-48))+rdi]
	vmovdqu	xmm12,XMMWORD PTR[((-32))+rdi]
	vpshufd	xmm13,xmm14,0EEh
	vpshufd	xmm10,xmm14,044h
	vmovdqa	XMMWORD PTR[(-144)+r11],xmm13
	vmovdqa	XMMWORD PTR[rsp],xmm10
	vpshufd	xmm14,xmm11,0EEh
	vmovdqu	xmm10,XMMWORD PTR[((-16))+rdi]
	vpshufd	xmm11,xmm11,044h
	vmovdqa	XMMWORD PTR[(-128)+r11],xmm14
	vmovdqa	XMMWORD PTR[16+rsp],xmm11
	vpshufd	xmm13,xmm12,0EEh
	vmovdqu	xmm11,XMMWORD PTR[rdi]
	vpshufd	xmm12,xmm12,044h
	vmovdqa	XMMWORD PTR[(-112)+r11],xmm13
	vmovdqa	XMMWORD PTR[32+rsp],xmm12
	vpshufd	xmm14,xmm10,0EEh
	vmovdqu	xmm12,XMMWORD PTR[16+rdi]
	vpshufd	xmm10,xmm10,044h
	vmovdqa	XMMWORD PTR[(-96)+r11],xmm14
	vmovdqa	XMMWORD PTR[48+rsp],xmm10
	vpshufd	xmm13,xmm11,0EEh
	vmovdqu	xmm10,XMMWORD PTR[32+rdi]
	vpshufd	xmm11,xmm11,044h
	vmovdqa	XMMWORD PTR[(-80)+r11],xmm13
	vmovdqa	XMMWORD PTR[64+rsp],xmm11
	vpshufd	xmm14,xmm12,0EEh
	vmovdqu	xmm11,XMMWORD PTR[48+rdi]
	vpshufd	xmm12,xmm12,044h
	vmovdqa	XMMWORD PTR[(-64)+r11],xmm14
	vmovdqa	XMMWORD PTR[80+rsp],xmm12
	vpshufd	xmm13,xmm10,0EEh
	vmovdqu	xmm12,XMMWORD PTR[64+rdi]
	vpshufd	xmm10,xmm10,044h
	vmovdqa	XMMWORD PTR[(-48)+r11],xmm13
	vmovdqa	XMMWORD PTR[96+rsp],xmm10
	vpshufd	xmm14,xmm11,0EEh
	vpshufd	xmm11,xmm11,044h
	vmovdqa	XMMWORD PTR[(-32)+r11],xmm14
	vmovdqa	XMMWORD PTR[112+rsp],xmm11
	vpshufd	xmm13,xmm12,0EEh
	vmovdqa	xmm14,XMMWORD PTR[rsp]
	vpshufd	xmm12,xmm12,044h
	vmovdqa	XMMWORD PTR[(-16)+r11],xmm13
	vmovdqa	XMMWORD PTR[128+rsp],xmm12
	jmp	$L$poly1305_loop_avx

ALIGN	32
$L$poly1305_loop_avx::
	vpmuludq	xmm10,xmm14,xmm5
	vpmuludq	xmm11,xmm14,xmm6
	vmovdqa	XMMWORD PTR[32+r11],xmm2
	vpmuludq	xmm12,xmm14,xmm7
	vmovdqa	xmm2,XMMWORD PTR[16+rsp]
	vpmuludq	xmm13,xmm14,xmm8
	vpmuludq	xmm14,xmm14,xmm9
	vmovdqa	XMMWORD PTR[r11],xmm0
	vpmuludq	xmm0,xmm9,XMMWORD PTR[32+rsp]
	vmovdqa	XMMWORD PTR[16+r11],xmm1
	vpmuludq	xmm1,xmm2,xmm8
	vpaddq	xmm10,xmm10,xmm0
	vpaddq	xmm14,xmm14,xmm1
	vmovdqa	XMMWORD PTR[48+r11],xmm3
	vpmuludq	xmm0,xmm2,xmm7
	vpmuludq	xmm1,xmm2,xmm6
	vpaddq	xmm13,xmm13,xmm0
	vmovdqa	xmm3,XMMWORD PTR[48+rsp]
	vpaddq	xmm12,xmm12,xmm1
	vmovdqa	XMMWORD PTR[64+r11],xmm4
	vpmuludq	xmm2,xmm2,xmm5
	vpmuludq	xmm0,xmm3,xmm7
	vpaddq	xmm11,xmm11,xmm2
	vmovdqa	xmm4,XMMWORD PTR[64+rsp]
	vpaddq	xmm14,xmm14,xmm0
	vpmuludq	xmm1,xmm3,xmm6
	vpmuludq	xmm3,xmm3,xmm5
	vpaddq	xmm13,xmm13,xmm1
	vmovdqa	xmm2,XMMWORD PTR[80+rsp]
	vpaddq	xmm12,xmm12,xmm3
	vpmuludq	xmm0,xmm4,xmm9
	vpmuludq	xmm4,xmm4,xmm8
	vpaddq	xmm11,xmm11,xmm0
	vmovdqa	xmm3,XMMWORD PTR[96+rsp]
	vpaddq	xmm10,xmm10,xmm4
	vmovdqa	xmm4,XMMWORD PTR[128+rsp]
	vpmuludq	xmm1,xmm2,xmm6
	vpmuludq	xmm2,xmm2,xmm5
	vpaddq	xmm14,xmm14,xmm1
	vpaddq	xmm13,xmm13,xmm2
	vpmuludq	xmm0,xmm3,xmm9
	vpmuludq	xmm1,xmm3,xmm8
	vpaddq	xmm12,xmm12,xmm0
	vmovdqu	xmm0,XMMWORD PTR[rsi]
	vpaddq	xmm11,xmm11,xmm1
	vpmuludq	xmm3,xmm3,xmm7
	vpmuludq	xmm7,xmm4,xmm7
	vpaddq	xmm10,xmm10,xmm3
	vmovdqu	xmm1,XMMWORD PTR[16+rsi]
	vpaddq	xmm11,xmm11,xmm7
	vpmuludq	xmm8,xmm4,xmm8
	vpmuludq	xmm9,xmm4,xmm9
	vpsrldq	xmm2,xmm0,6
	vpaddq	xmm12,xmm12,xmm8
	vpaddq	xmm13,xmm13,xmm9
	vpsrldq	xmm3,xmm1,6
	vpmuludq	xmm9,xmm5,XMMWORD PTR[112+rsp]
	vpmuludq	xmm5,xmm4,xmm6
	vpunpckhqdq	xmm4,xmm0,xmm1
	vpaddq	xmm14,xmm14,xmm9
	vmovdqa	xmm9,XMMWORD PTR[((-144))+r11]
	vpaddq	xmm10,xmm10,xmm5
	vpunpcklqdq	xmm0,xmm0,xmm1
	vpunpcklqdq	xmm3,xmm2,xmm3
	vpsrldq	xmm4,xmm4,5
	vpsrlq	xmm1,xmm0,26
	vpand	xmm0,xmm0,xmm15
	vpsrlq	xmm2,xmm3,4
	vpand	xmm1,xmm1,xmm15
	vpand	xmm4,xmm4,XMMWORD PTR[rcx]
	vpsrlq	xmm3,xmm3,30
	vpand	xmm2,xmm2,xmm15
	vpand	xmm3,xmm3,xmm15
	vpor	xmm4,xmm4,XMMWORD PTR[32+rcx]
	vpaddq	xmm0,xmm0,XMMWORD PTR[r11]
	vpaddq	xmm1,xmm1,XMMWORD PTR[16+r11]
	vpaddq	xmm2,xmm2,XMMWORD PTR[32+r11]
	vpaddq	xmm3,xmm3,XMMWORD PTR[48+r11]
	vpaddq	xmm4,xmm4,XMMWORD PTR[64+r11]
	lea	rax,QWORD PTR[32+rsi]
	lea	rsi,QWORD PTR[64+rsi]
	sub	rdx,64
	cmovc	rsi,rax
	vpmuludq	xmm5,xmm9,xmm0
	vpmuludq	xmm6,xmm9,xmm1
	vpaddq	xmm10,xmm10,xmm5
	vpaddq	xmm11,xmm11,xmm6
	vmovdqa	xmm7,XMMWORD PTR[((-128))+r11]
	vpmuludq	xmm5,xmm9,xmm2
	vpmuludq	xmm6,xmm9,xmm3
	vpaddq	xmm12,xmm12,xmm5
	vpaddq	xmm13,xmm13,xmm6
	vpmuludq	xmm9,xmm9,xmm4
	vpmuludq	xmm5,xmm4,XMMWORD PTR[((-112))+r11]
	vpaddq	xmm14,xmm14,xmm9
	vpaddq	xmm10,xmm10,xmm5
	vpmuludq	xmm6,xmm7,xmm2
	vpmuludq	xmm5,xmm7,xmm3
	vpaddq	xmm13,xmm13,xmm6
	vmovdqa	xmm8,XMMWORD PTR[((-96))+r11]
	vpaddq	xmm14,xmm14,xmm5
	vpmuludq	xmm6,xmm7,xmm1
	vpmuludq	xmm7,xmm7,xmm0
	vpaddq	xmm12,xmm12,xmm6
	vpaddq	xmm11,xmm11,xmm7
	vmovdqa	xmm9,XMMWORD PTR[((-80))+r11]
	vpmuludq	xmm5,xmm8,xmm2
	vpmuludq	xmm6,xmm8,xmm1
	vpaddq	xmm14,xmm14,xmm5
	vpaddq	xmm13,xmm13,xmm6
	vmovdqa	xmm7,XMMWORD PTR[((-64))+r11]
	vpmuludq	xmm8,xmm8,xmm0
	vpmuludq	xmm5,xmm9,xmm4
	vpaddq	xmm12,xmm12,xmm8
	vpaddq	xmm11,xmm11,xmm5
	vmovdqa	xmm8,XMMWORD PTR[((-48))+r11]
	vpmuludq	xmm9,xmm9,xmm3
	vpmuludq	xmm6,xmm7,xmm1
	vpaddq	xmm10,xmm10,xmm9
	vmovdqa	xmm9,XMMWORD PTR[((-16))+r11]
	vpaddq	xmm14,xmm14,xmm6
	vpmuludq	xmm7,xmm7,xmm0
	vpmuludq	xmm5,xmm8,xmm4
	vpaddq	xmm13,xmm13,xmm7
	vpaddq	xmm12,xmm12,xmm5
	vmovdqu	xmm5,XMMWORD PTR[32+rsi]
	vpmuludq	xmm7,xmm8,xmm3
	vpmuludq	xmm8,xmm8,xmm2
	vpaddq	xmm11,xmm11,xmm7
	vmovdqu	xmm6,XMMWORD PTR[48+rsi]
	vpaddq	xmm10,xmm10,xmm8
	vpmuludq	xmm2,xmm9,xmm2
	vpmuludq	xmm3,xmm9,xmm3
	vpsrldq	xmm7,xmm5,6
	vpaddq	xmm11,xmm11,xmm2
	vpmuludq	xmm4,xmm9,xmm4
	vpsrldq	xmm8,xmm6,6
	vpaddq	xmm2,xmm12,xmm3
	vpaddq	xmm3,xmm13,xmm4
	vpmuludq	xmm4,xmm0,XMMWORD PTR[((-32))+r11]
	vpmuludq	xmm0,xmm9,xmm1
	vpunpckhqdq	xmm9,xmm5,xmm6
	vpaddq	xmm4,xmm14,xmm4
	vpaddq	xmm0,xmm10,xmm0
	vpunpcklqdq	xmm5,xmm5,xmm6
	vpunpcklqdq	xmm8,xmm7,xmm8
	vpsrldq	xmm9,xmm9,5
	vpsrlq	xmm6,xmm5,26
	vmovdqa	xmm14,XMMWORD PTR[rsp]
	vpand	xmm5,xmm5,xmm15
	vpsrlq	xmm7,xmm8,4
	vpand	xmm6,xmm6,xmm15
	vpand	xmm9,xmm9,XMMWORD PTR[rcx]
	vpsrlq	xmm8,xmm8,30
	vpand	xmm7,xmm7,xmm15
	vpand	xmm8,xmm8,xmm15
	vpor	xmm9,xmm9,XMMWORD PTR[32+rcx]
	vpsrlq	xmm13,xmm3,26
	vpand	xmm3,xmm3,xmm15
	vpaddq	xmm4,xmm4,xmm13
	vpsrlq	xmm10,xmm0,26
	vpand	xmm0,xmm0,xmm15
	vpaddq	xmm1,xmm11,xmm10
	vpsrlq	xmm10,xmm4,26
	vpand	xmm4,xmm4,xmm15
	vpsrlq	xmm11,xmm1,26
	vpand	xmm1,xmm1,xmm15
	vpaddq	xmm2,xmm2,xmm11
	vpaddq	xmm0,xmm0,xmm10
	vpsllq	xmm10,xmm10,2
	vpaddq	xmm0,xmm0,xmm10
	vpsrlq	xmm12,xmm2,26
	vpand	xmm2,xmm2,xmm15
	vpaddq	xmm3,xmm3,xmm12
	vpsrlq	xmm10,xmm0,26
	vpand	xmm0,xmm0,xmm15
	vpaddq	xmm1,xmm1,xmm10
	vpsrlq	xmm13,xmm3,26
	vpand	xmm3,xmm3,xmm15
	vpaddq	xmm4,xmm4,xmm13
	ja	$L$poly1305_loop_avx

$L$skip_loop_avx::
	vpshufd	xmm14,xmm14,010h
	add	rdx,32
	jnz	$L$ong_tail_avx
	vpaddq	xmm7,xmm7,xmm2
	vpaddq	xmm5,xmm5,xmm0
	vpaddq	xmm6,xmm6,xmm1
	vpaddq	xmm8,xmm8,xmm3
	vpaddq	xmm9,xmm9,xmm4

$L$ong_tail_avx::
	vmovdqa	XMMWORD PTR[32+r11],xmm2
	vmovdqa	XMMWORD PTR[r11],xmm0
	vmovdqa	XMMWORD PTR[16+r11],xmm1
	vmovdqa	XMMWORD PTR[48+r11],xmm3
	vmovdqa	XMMWORD PTR[64+r11],xmm4
	vpmuludq	xmm12,xmm14,xmm7
	vpmuludq	xmm10,xmm14,xmm5
	vpshufd	xmm2,XMMWORD PTR[((-48))+rdi],010h
	vpmuludq	xmm11,xmm14,xmm6
	vpmuludq	xmm13,xmm14,xmm8
	vpmuludq	xmm14,xmm14,xmm9
	vpmuludq	xmm0,xmm2,xmm8
	vpaddq	xmm14,xmm14,xmm0
	vpshufd	xmm3,XMMWORD PTR[((-32))+rdi],010h
	vpmuludq	xmm1,xmm2,xmm7
	vpaddq	xmm13,xmm13,xmm1
	vpshufd	xmm4,XMMWORD PTR[((-16))+rdi],010h
	vpmuludq	xmm0,xmm2,xmm6
	vpaddq	xmm12,xmm12,xmm0
	vpmuludq	xmm2,xmm2,xmm5
	vpaddq	xmm11,xmm11,xmm2
	vpmuludq	xmm3,xmm3,xmm9
	vpaddq	xmm10,xmm10,xmm3
	vpshufd	xmm2,XMMWORD PTR[rdi],010h
	vpmuludq	xmm1,xmm4,xmm7
	vpaddq	xmm14,xmm14,xmm1
	vpmuludq	xmm0,xmm4,xmm6
	vpaddq	xmm13,xmm13,xmm0
	vpshufd	xmm3,XMMWORD PTR[16+rdi],010h
	vpmuludq	xmm4,xmm4,xmm5
	vpaddq	xmm12,xmm12,xmm4
	vpmuludq	xmm1,xmm2,xmm9
	vpaddq	xmm11,xmm11,xmm1
	vpshufd	xmm4,XMMWORD PTR[32+rdi],010h
	vpmuludq	xmm2,xmm2,xmm8
	vpaddq	xmm10,xmm10,xmm2
	vpmuludq	xmm0,xmm3,xmm6
	vpaddq	xmm14,xmm14,xmm0
	vpmuludq	xmm3,xmm3,xmm5
	vpaddq	xmm13,xmm13,xmm3
	vpshufd	xmm2,XMMWORD PTR[48+rdi],010h
	vpmuludq	xmm1,xmm4,xmm9
	vpaddq	xmm12,xmm12,xmm1
	vpshufd	xmm3,XMMWORD PTR[64+rdi],010h
	vpmuludq	xmm0,xmm4,xmm8
	vpaddq	xmm11,xmm11,xmm0
	vpmuludq	xmm4,xmm4,xmm7
	vpaddq	xmm10,xmm10,xmm4
	vpmuludq	xmm2,xmm2,xmm5
	vpaddq	xmm14,xmm14,xmm2
	vpmuludq	xmm1,xmm3,xmm9
	vpaddq	xmm13,xmm13,xmm1
	vpmuludq	xmm0,xmm3,xmm8
	vpaddq	xmm12,xmm12,xmm0
	vpmuludq	xmm1,xmm3,xmm7
	vpaddq	xmm11,xmm11,xmm1
	vpmuludq	xmm3,xmm3,xmm6
	vpaddq	xmm10,xmm10,xmm3
	jz	$L$short_tail_avx
	vmovdqu	xmm0,XMMWORD PTR[rsi]
	vmovdqu	xmm1,XMMWORD PTR[16+rsi]
	vpsrldq	xmm2,xmm0,6
	vpsrldq	xmm3,xmm1,6
	vpunpckhqdq	xmm4,xmm0,xmm1
	vpunpcklqdq	xmm0,xmm0,xmm1
	vpunpcklqdq	xmm3,xmm2,xmm3
	vpsrlq	xmm4,xmm4,40
	vpsrlq	xmm1,xmm0,26
	vpand	xmm0,xmm0,xmm15
	vpsrlq	xmm2,xmm3,4
	vpand	xmm1,xmm1,xmm15
	vpsrlq	xmm3,xmm3,30
	vpand	xmm2,xmm2,xmm15
	vpand	xmm3,xmm3,xmm15
	vpor	xmm4,xmm4,XMMWORD PTR[32+rcx]
	vpshufd	xmm9,XMMWORD PTR[((-64))+rdi],032h
	vpaddq	xmm0,xmm0,XMMWORD PTR[r11]
	vpaddq	xmm1,xmm1,XMMWORD PTR[16+r11]
	vpaddq	xmm2,xmm2,XMMWORD PTR[32+r11]
	vpaddq	xmm3,xmm3,XMMWORD PTR[48+r11]
	vpaddq	xmm4,xmm4,XMMWORD PTR[64+r11]
	vpmuludq	xmm5,xmm9,xmm0
	vpaddq	xmm10,xmm10,xmm5
	vpmuludq	xmm6,xmm9,xmm1
	vpaddq	xmm11,xmm11,xmm6
	vpmuludq	xmm5,xmm9,xmm2
	vpaddq	xmm12,xmm12,xmm5
	vpshufd	xmm7,XMMWORD PTR[((-48))+rdi],032h
	vpmuludq	xmm6,xmm9,xmm3
	vpaddq	xmm13,xmm13,xmm6
	vpmuludq	xmm9,xmm9,xmm4
	vpaddq	xmm14,xmm14,xmm9
	vpmuludq	xmm5,xmm7,xmm3
	vpaddq	xmm14,xmm14,xmm5
	vpshufd	xmm8,XMMWORD PTR[((-32))+rdi],032h
	vpmuludq	xmm6,xmm7,xmm2
	vpaddq	xmm13,xmm13,xmm6
	vpshufd	xmm9,XMMWORD PTR[((-16))+rdi],032h
	vpmuludq	xmm5,xmm7,xmm1
	vpaddq	xmm12,xmm12,xmm5
	vpmuludq	xmm7,xmm7,xmm0
	vpaddq	xmm11,xmm11,xmm7
	vpmuludq	xmm8,xmm8,xmm4
	vpaddq	xmm10,xmm10,xmm8
	vpshufd	xmm7,XMMWORD PTR[rdi],032h
	vpmuludq	xmm6,xmm9,xmm2
	vpaddq	xmm14,xmm14,xmm6
	vpmuludq	xmm5,xmm9,xmm1
	vpaddq	xmm13,xmm13,xmm5
	vpshufd	xmm8,XMMWORD PTR[16+rdi],032h
	vpmuludq	xmm9,xmm9,xmm0
	vpaddq	xmm12,xmm12,xmm9
	vpmuludq	xmm6,xmm7,xmm4
	vpaddq	xmm11,xmm11,xmm6
	vpshufd	xmm9,XMMWORD PTR[32+rdi],032h
	vpmuludq	xmm7,xmm7,xmm3
	vpaddq	xmm10,xmm10,xmm7
	vpmuludq	xmm5,xmm8,xmm1
	vpaddq	xmm14,xmm14,xmm5
	vpmuludq	xmm8,xmm8,xmm0
	vpaddq	xmm13,xmm13,xmm8
	vpshufd	xmm7,XMMWORD PTR[48+rdi],032h
	vpmuludq	xmm6,xmm9,xmm4
	vpaddq	xmm12,xmm12,xmm6
	vpshufd	xmm8,XMMWORD PTR[64+rdi],032h
	vpmuludq	xmm5,xmm9,xmm3
	vpaddq	xmm11,xmm11,xmm5
	vpmuludq	xmm9,xmm9,xmm2
	vpaddq	xmm10,xmm10,xmm9
	vpmuludq	xmm7,xmm7,xmm0
	vpaddq	xmm14,xmm14,xmm7
	vpmuludq	xmm6,xmm8,xmm4
	vpaddq	xmm13,xmm13,xmm6
	vpmuludq	xmm5,xmm8,xmm3
	vpaddq	xmm12,xmm12,xmm5
	vpmuludq	xmm6,xmm8,xmm2
	vpaddq	xmm11,xmm11,xmm6
	vpmuludq	xmm8,xmm8,xmm1
	vpaddq	xmm10,xmm10,xmm8

$L$short_tail_avx::
	vpsrldq	xmm9,xmm14,8
	vpsrldq	xmm8,xmm13,8
	vpsrldq	xmm6,xmm11,8
	vpsrldq	xmm5,xmm10,8
	vpsrldq	xmm7,xmm12,8
	vpaddq	xmm13,xmm13,xmm8
	vpaddq	xmm14,xmm14,xmm9
	vpaddq	xmm10,xmm10,xmm5
	vpaddq	xmm11,xmm11,xmm6
	vpaddq	xmm12,xmm12,xmm7
	vpsrlq	xmm3,xmm13,26
	vpand	xmm13,xmm13,xmm15
	vpaddq	xmm14,xmm14,xmm3
	vpsrlq	xmm0,xmm10,26
	vpand	xmm10,xmm10,xmm15
	vpaddq	xmm11,xmm11,xmm0
	vpsrlq	xmm4,xmm14,26
	vpand	xmm14,xmm14,xmm15
	vpsrlq	xmm1,xmm11,26
	vpand	xmm11,xmm11,xmm15
	vpaddq	xmm12,xmm12,xmm1
	vpaddq	xmm10,xmm10,xmm4
	vpsllq	xmm4,xmm4,2
	vpaddq	xmm10,xmm10,xmm4
	vpsrlq	xmm2,xmm12,26
	vpand	xmm12,xmm12,xmm15
	vpaddq	xmm13,xmm13,xmm2
	vpsrlq	xmm0,xmm10,26
	vpand	xmm10,xmm10,xmm15
	vpaddq	xmm11,xmm11,xmm0
	vpsrlq	xmm3,xmm13,26
	vpand	xmm13,xmm13,xmm15
	vpaddq	xmm14,xmm14,xmm3
	vmovd	DWORD PTR[(-112)+rdi],xmm10
	vmovd	DWORD PTR[(-108)+rdi],xmm11
	vmovd	DWORD PTR[(-104)+rdi],xmm12
	vmovd	DWORD PTR[(-100)+rdi],xmm13
	vmovd	DWORD PTR[(-96)+rdi],xmm14
	vmovdqa	xmm6,XMMWORD PTR[80+r11]
	vmovdqa	xmm7,XMMWORD PTR[96+r11]
	vmovdqa	xmm8,XMMWORD PTR[112+r11]
	vmovdqa	xmm9,XMMWORD PTR[128+r11]
	vmovdqa	xmm10,XMMWORD PTR[144+r11]
	vmovdqa	xmm11,XMMWORD PTR[160+r11]
	vmovdqa	xmm12,XMMWORD PTR[176+r11]
	vmovdqa	xmm13,XMMWORD PTR[192+r11]
	vmovdqa	xmm14,XMMWORD PTR[208+r11]
	vmovdqa	xmm15,XMMWORD PTR[224+r11]
	lea	rsp,QWORD PTR[248+r11]
$L$do_avx_epilogue::
	vzeroupper
	mov	rdi,QWORD PTR[8+rsp]	;WIN64 epilogue
	mov	rsi,QWORD PTR[16+rsp]
	DB	0F3h,0C3h		;repret

$L$SEH_end_poly1305_blocks_avx::
Poly1305BlocksAVX	ENDP

ALIGN	32
Poly1305BlocksAVX2	PROC PUBLIC
	DB	243,15,30,250
	mov	QWORD PTR[8+rsp],rdi	;WIN64 prologue
	mov	QWORD PTR[16+rsp],rsi
	mov	rax,rsp
$L$SEH_begin_poly1305_blocks_avx2::
	mov	rdi,rcx
	mov	rsi,rdx
	mov	rdx,r8
	mov	rcx,r9
	mov	r8d,DWORD PTR[20+rdi]
	cmp	rdx,128
	jb	$L$blocks
	and	rdx,-16
	vzeroupper
	test	r8d,r8d
	jz	$L$base2_64_avx2
	test	rdx,63
	jz	$L$even_avx2
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	lea	rsp,QWORD PTR[((-8))+rsp]

$L$blocks_avx2_body::
	mov	r15,rdx
	mov	r8,QWORD PTR[rdi]
	mov	r9,QWORD PTR[8+rdi]
	mov	ebp,DWORD PTR[16+rdi]
	mov	r11,QWORD PTR[24+rdi]
	mov	r13,QWORD PTR[32+rdi]
	mov	r14d,r8d
	and	r8,-2147483648
	mov	r12,r9
	mov	ebx,r9d
	and	r9,-2147483648
	shr	r8,6
	shl	r12,52
	add	r14,r8
	shr	rbx,12
	shr	r9,18
	add	r14,r12
	adc	rbx,r9
	mov	r8,rbp
	shl	r8,40
	shr	rbp,24
	add	rbx,r8
	adc	rbp,0
	mov	r12,r13
	mov	rax,r13
	shr	r13,2
	add	r13,r12

$L$base2_26_pre_avx2::
	add	r14,QWORD PTR[rsi]
	adc	rbx,QWORD PTR[8+rsi]
	lea	rsi,QWORD PTR[16+rsi]
	adc	rbp,rcx
	sub	r15,16
	call	__poly1305_block
	mov	rax,r12
	test	r15,63
	jnz	$L$base2_26_pre_avx2
	mov	rax,r14
	mov	rdx,r14
	shr	r14,52
	mov	r11,rbx
	mov	r12,rbx
	shr	rdx,26
	and	rax,03ffffffh
	shl	r11,12
	and	rdx,03ffffffh
	shr	rbx,14
	or	r14,r11
	shl	rbp,24
	and	r14,03ffffffh
	shr	r12,40
	and	rbx,03ffffffh
	or	rbp,r12
	vmovd	xmm0,eax
	vmovd	xmm1,edx
	vmovd	xmm2,r14d
	vmovd	xmm3,ebx
	vmovd	xmm4,ebp
	mov	rdx,r15
	mov	r15,QWORD PTR[8+rsp]
	mov	r14,QWORD PTR[16+rsp]
	mov	r13,QWORD PTR[24+rsp]
	mov	r12,QWORD PTR[32+rsp]
	mov	rbp,QWORD PTR[40+rsp]
	mov	rbx,QWORD PTR[48+rsp]
	lea	rax,QWORD PTR[56+rsp]
	lea	rsp,QWORD PTR[56+rsp]

$L$blocks_avx2_epilogue::
	jmp	$L$do_avx2

ALIGN	32
$L$base2_64_avx2::
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	lea	rsp,QWORD PTR[((-8))+rsp]

$L$base2_64_avx2_body::
	mov	r15,rdx
	mov	r11,QWORD PTR[24+rdi]
	mov	r13,QWORD PTR[32+rdi]
	mov	r14,QWORD PTR[rdi]
	mov	rbx,QWORD PTR[8+rdi]
	mov	ebp,DWORD PTR[16+rdi]
	mov	r12,r13
	mov	rax,r13
	shr	r13,2
	add	r13,r12
	test	rdx,63
	jz	$L$init_avx2

$L$base2_64_pre_avx2::
	add	r14,QWORD PTR[rsi]
	adc	rbx,QWORD PTR[8+rsi]
	lea	rsi,QWORD PTR[16+rsi]
	adc	rbp,rcx
	sub	r15,16
	call	__poly1305_block
	mov	rax,r12
	test	r15,63
	jnz	$L$base2_64_pre_avx2

$L$init_avx2::
	mov	rax,r14
	mov	rdx,r14
	shr	r14,52
	mov	r8,rbx
	mov	r9,rbx
	shr	rdx,26
	and	rax,03ffffffh
	shl	r8,12
	and	rdx,03ffffffh
	shr	rbx,14
	or	r14,r8
	shl	rbp,24
	and	r14,03ffffffh
	shr	r9,40
	and	rbx,03ffffffh
	or	rbp,r9
	vmovd	xmm0,eax
	vmovd	xmm1,edx
	vmovd	xmm2,r14d
	vmovd	xmm3,ebx
	vmovd	xmm4,ebp
	mov	DWORD PTR[20+rdi],1
	call	__poly1305_init_avx
	mov	rdx,r15
	mov	r15,QWORD PTR[8+rsp]
	mov	r14,QWORD PTR[16+rsp]
	mov	r13,QWORD PTR[24+rsp]
	mov	r12,QWORD PTR[32+rsp]
	mov	rbp,QWORD PTR[40+rsp]
	mov	rbx,QWORD PTR[48+rsp]
	lea	rax,QWORD PTR[56+rsp]
	lea	rsp,QWORD PTR[56+rsp]

$L$base2_64_avx2_epilogue::
	jmp	$L$do_avx2

ALIGN	32
$L$even_avx2::
	vmovd	xmm0,DWORD PTR[rdi]
	vmovd	xmm1,DWORD PTR[4+rdi]
	vmovd	xmm2,DWORD PTR[8+rdi]
	vmovd	xmm3,DWORD PTR[12+rdi]
	vmovd	xmm4,DWORD PTR[16+rdi]

$L$do_avx2::
	lea	r11,QWORD PTR[((-248))+rsp]
	sub	rsp,01c8h
	vmovdqa	XMMWORD PTR[80+r11],xmm6
	vmovdqa	XMMWORD PTR[96+r11],xmm7
	vmovdqa	XMMWORD PTR[112+r11],xmm8
	vmovdqa	XMMWORD PTR[128+r11],xmm9
	vmovdqa	XMMWORD PTR[144+r11],xmm10
	vmovdqa	XMMWORD PTR[160+r11],xmm11
	vmovdqa	XMMWORD PTR[176+r11],xmm12
	vmovdqa	XMMWORD PTR[192+r11],xmm13
	vmovdqa	XMMWORD PTR[208+r11],xmm14
	vmovdqa	XMMWORD PTR[224+r11],xmm15
$L$do_avx2_body::
	lea	rcx,QWORD PTR[$L$const]
	lea	rdi,QWORD PTR[((48+64))+rdi]
	vmovdqa	ymm7,YMMWORD PTR[96+rcx]
	vmovdqu	xmm9,XMMWORD PTR[((-64))+rdi]
	and	rsp,-512
	vmovdqu	xmm10,XMMWORD PTR[((-48))+rdi]
	vmovdqu	xmm6,XMMWORD PTR[((-32))+rdi]
	vmovdqu	xmm11,XMMWORD PTR[((-16))+rdi]
	vmovdqu	xmm12,XMMWORD PTR[rdi]
	vmovdqu	xmm13,XMMWORD PTR[16+rdi]
	lea	rax,QWORD PTR[144+rsp]
	vmovdqu	xmm14,XMMWORD PTR[32+rdi]
	vpermd	ymm9,ymm7,ymm9
	vmovdqu	xmm15,XMMWORD PTR[48+rdi]
	vpermd	ymm10,ymm7,ymm10
	vmovdqu	xmm5,XMMWORD PTR[64+rdi]
	vpermd	ymm6,ymm7,ymm6
	vmovdqa	YMMWORD PTR[rsp],ymm9
	vpermd	ymm11,ymm7,ymm11
	vmovdqa	YMMWORD PTR[(32-144)+rax],ymm10
	vpermd	ymm12,ymm7,ymm12
	vmovdqa	YMMWORD PTR[(64-144)+rax],ymm6
	vpermd	ymm13,ymm7,ymm13
	vmovdqa	YMMWORD PTR[(96-144)+rax],ymm11
	vpermd	ymm14,ymm7,ymm14
	vmovdqa	YMMWORD PTR[(128-144)+rax],ymm12
	vpermd	ymm15,ymm7,ymm15
	vmovdqa	YMMWORD PTR[(160-144)+rax],ymm13
	vpermd	ymm5,ymm7,ymm5
	vmovdqa	YMMWORD PTR[(192-144)+rax],ymm14
	vmovdqa	YMMWORD PTR[(224-144)+rax],ymm15
	vmovdqa	YMMWORD PTR[(256-144)+rax],ymm5
	vmovdqa	ymm5,YMMWORD PTR[64+rcx]
	vmovdqu	xmm7,XMMWORD PTR[rsi]
	vmovdqu	xmm8,XMMWORD PTR[16+rsi]
	vinserti128	ymm7,ymm7,XMMWORD PTR[32+rsi],1
	vinserti128	ymm8,ymm8,XMMWORD PTR[48+rsi],1
	lea	rsi,QWORD PTR[64+rsi]
	vpsrldq	ymm9,ymm7,6
	vpsrldq	ymm10,ymm8,6
	vpunpckhqdq	ymm6,ymm7,ymm8
	vpunpcklqdq	ymm9,ymm9,ymm10
	vpunpcklqdq	ymm7,ymm7,ymm8
	vpsrlq	ymm10,ymm9,30
	vpsrlq	ymm9,ymm9,4
	vpsrlq	ymm8,ymm7,26
	vpsrlq	ymm6,ymm6,40
	vpand	ymm9,ymm9,ymm5
	vpand	ymm7,ymm7,ymm5
	vpand	ymm8,ymm8,ymm5
	vpand	ymm10,ymm10,ymm5
	vpor	ymm6,ymm6,YMMWORD PTR[32+rcx]
	vpaddq	ymm2,ymm9,ymm2
	sub	rdx,64
	jz	$L$tail_avx2
	jmp	$L$poly1305_loop_avx2

ALIGN	32
$L$poly1305_loop_avx2::
	vpaddq	ymm0,ymm7,ymm0
	vmovdqa	ymm7,YMMWORD PTR[rsp]
	vpaddq	ymm1,ymm8,ymm1
	vmovdqa	ymm8,YMMWORD PTR[32+rsp]
	vpaddq	ymm3,ymm10,ymm3
	vmovdqa	ymm9,YMMWORD PTR[96+rsp]
	vpaddq	ymm4,ymm6,ymm4
	vmovdqa	ymm10,YMMWORD PTR[48+rax]
	vmovdqa	ymm5,YMMWORD PTR[112+rax]
	vpmuludq	ymm13,ymm7,ymm2
	vpmuludq	ymm14,ymm8,ymm2
	vpmuludq	ymm15,ymm9,ymm2
	vpmuludq	ymm11,ymm10,ymm2
	vpmuludq	ymm12,ymm5,ymm2
	vpmuludq	ymm6,ymm8,ymm0
	vpmuludq	ymm2,ymm8,ymm1
	vpaddq	ymm12,ymm12,ymm6
	vpaddq	ymm13,ymm13,ymm2
	vpmuludq	ymm6,ymm8,ymm3
	vpmuludq	ymm2,ymm4,YMMWORD PTR[64+rsp]
	vpaddq	ymm15,ymm15,ymm6
	vpaddq	ymm11,ymm11,ymm2
	vmovdqa	ymm8,YMMWORD PTR[((-16))+rax]
	vpmuludq	ymm6,ymm7,ymm0
	vpmuludq	ymm2,ymm7,ymm1
	vpaddq	ymm11,ymm11,ymm6
	vpaddq	ymm12,ymm12,ymm2
	vpmuludq	ymm6,ymm7,ymm3
	vpmuludq	ymm2,ymm7,ymm4
	vmovdqu	xmm7,XMMWORD PTR[rsi]
	vpaddq	ymm14,ymm14,ymm6
	vpaddq	ymm15,ymm15,ymm2
	vinserti128	ymm7,ymm7,XMMWORD PTR[32+rsi],1
	vpmuludq	ymm6,ymm8,ymm3
	vpmuludq	ymm2,ymm8,ymm4
	vmovdqu	xmm8,XMMWORD PTR[16+rsi]
	vpaddq	ymm11,ymm11,ymm6
	vpaddq	ymm12,ymm12,ymm2
	vmovdqa	ymm2,YMMWORD PTR[16+rax]
	vpmuludq	ymm6,ymm9,ymm1
	vpmuludq	ymm9,ymm9,ymm0
	vpaddq	ymm14,ymm14,ymm6
	vpaddq	ymm13,ymm13,ymm9
	vinserti128	ymm8,ymm8,XMMWORD PTR[48+rsi],1
	lea	rsi,QWORD PTR[64+rsi]
	vpmuludq	ymm6,ymm2,ymm1
	vpmuludq	ymm2,ymm2,ymm0
	vpsrldq	ymm9,ymm7,6
	vpaddq	ymm15,ymm15,ymm6
	vpaddq	ymm14,ymm14,ymm2
	vpmuludq	ymm6,ymm10,ymm3
	vpmuludq	ymm2,ymm10,ymm4
	vpsrldq	ymm10,ymm8,6
	vpaddq	ymm12,ymm12,ymm6
	vpaddq	ymm13,ymm13,ymm2
	vpunpckhqdq	ymm6,ymm7,ymm8
	vpmuludq	ymm3,ymm5,ymm3
	vpmuludq	ymm4,ymm5,ymm4
	vpunpcklqdq	ymm7,ymm7,ymm8
	vpaddq	ymm2,ymm13,ymm3
	vpaddq	ymm3,ymm14,ymm4
	vpunpcklqdq	ymm10,ymm9,ymm10
	vpmuludq	ymm4,ymm0,YMMWORD PTR[80+rax]
	vpmuludq	ymm0,ymm5,ymm1
	vmovdqa	ymm5,YMMWORD PTR[64+rcx]
	vpaddq	ymm4,ymm15,ymm4
	vpaddq	ymm0,ymm11,ymm0
	vpsrlq	ymm14,ymm3,26
	vpand	ymm3,ymm3,ymm5
	vpaddq	ymm4,ymm4,ymm14
	vpsrlq	ymm11,ymm0,26
	vpand	ymm0,ymm0,ymm5
	vpaddq	ymm1,ymm12,ymm11
	vpsrlq	ymm15,ymm4,26
	vpand	ymm4,ymm4,ymm5
	vpsrlq	ymm9,ymm10,4
	vpsrlq	ymm12,ymm1,26
	vpand	ymm1,ymm1,ymm5
	vpaddq	ymm2,ymm2,ymm12
	vpaddq	ymm0,ymm0,ymm15
	vpsllq	ymm15,ymm15,2
	vpaddq	ymm0,ymm0,ymm15
	vpand	ymm9,ymm9,ymm5
	vpsrlq	ymm8,ymm7,26
	vpsrlq	ymm13,ymm2,26
	vpand	ymm2,ymm2,ymm5
	vpaddq	ymm3,ymm3,ymm13
	vpaddq	ymm2,ymm2,ymm9
	vpsrlq	ymm10,ymm10,30
	vpsrlq	ymm11,ymm0,26
	vpand	ymm0,ymm0,ymm5
	vpaddq	ymm1,ymm1,ymm11
	vpsrlq	ymm6,ymm6,40
	vpsrlq	ymm14,ymm3,26
	vpand	ymm3,ymm3,ymm5
	vpaddq	ymm4,ymm4,ymm14
	vpand	ymm7,ymm7,ymm5
	vpand	ymm8,ymm8,ymm5
	vpand	ymm10,ymm10,ymm5
	vpor	ymm6,ymm6,YMMWORD PTR[32+rcx]
	sub	rdx,64
	jnz	$L$poly1305_loop_avx2

DB	066h,090h
$L$tail_avx2::
	vpaddq	ymm0,ymm7,ymm0
	vmovdqu	ymm7,YMMWORD PTR[4+rsp]
	vpaddq	ymm1,ymm8,ymm1
	vmovdqu	ymm8,YMMWORD PTR[36+rsp]
	vpaddq	ymm3,ymm10,ymm3
	vmovdqu	ymm9,YMMWORD PTR[100+rsp]
	vpaddq	ymm4,ymm6,ymm4
	vmovdqu	ymm10,YMMWORD PTR[52+rax]
	vmovdqu	ymm5,YMMWORD PTR[116+rax]
	vpmuludq	ymm13,ymm7,ymm2
	vpmuludq	ymm14,ymm8,ymm2
	vpmuludq	ymm15,ymm9,ymm2
	vpmuludq	ymm11,ymm10,ymm2
	vpmuludq	ymm12,ymm5,ymm2
	vpmuludq	ymm6,ymm8,ymm0
	vpmuludq	ymm2,ymm8,ymm1
	vpaddq	ymm12,ymm12,ymm6
	vpaddq	ymm13,ymm13,ymm2
	vpmuludq	ymm6,ymm8,ymm3
	vpmuludq	ymm2,ymm4,YMMWORD PTR[68+rsp]
	vpaddq	ymm15,ymm15,ymm6
	vpaddq	ymm11,ymm11,ymm2
	vpmuludq	ymm6,ymm7,ymm0
	vpmuludq	ymm2,ymm7,ymm1
	vpaddq	ymm11,ymm11,ymm6
	vmovdqu	ymm8,YMMWORD PTR[((-12))+rax]
	vpaddq	ymm12,ymm12,ymm2
	vpmuludq	ymm6,ymm7,ymm3
	vpmuludq	ymm2,ymm7,ymm4
	vpaddq	ymm14,ymm14,ymm6
	vpaddq	ymm15,ymm15,ymm2
	vpmuludq	ymm6,ymm8,ymm3
	vpmuludq	ymm2,ymm8,ymm4
	vpaddq	ymm11,ymm11,ymm6
	vpaddq	ymm12,ymm12,ymm2
	vmovdqu	ymm2,YMMWORD PTR[20+rax]
	vpmuludq	ymm6,ymm9,ymm1
	vpmuludq	ymm9,ymm9,ymm0
	vpaddq	ymm14,ymm14,ymm6
	vpaddq	ymm13,ymm13,ymm9
	vpmuludq	ymm6,ymm2,ymm1
	vpmuludq	ymm2,ymm2,ymm0
	vpaddq	ymm15,ymm15,ymm6
	vpaddq	ymm14,ymm14,ymm2
	vpmuludq	ymm6,ymm10,ymm3
	vpmuludq	ymm2,ymm10,ymm4
	vpaddq	ymm12,ymm12,ymm6
	vpaddq	ymm13,ymm13,ymm2
	vpmuludq	ymm3,ymm5,ymm3
	vpmuludq	ymm4,ymm5,ymm4
	vpaddq	ymm2,ymm13,ymm3
	vpaddq	ymm3,ymm14,ymm4
	vpmuludq	ymm4,ymm0,YMMWORD PTR[84+rax]
	vpmuludq	ymm0,ymm5,ymm1
	vmovdqa	ymm5,YMMWORD PTR[64+rcx]
	vpaddq	ymm4,ymm15,ymm4
	vpaddq	ymm0,ymm11,ymm0
	vpsrldq	ymm8,ymm12,8
	vpsrldq	ymm9,ymm2,8
	vpsrldq	ymm10,ymm3,8
	vpsrldq	ymm6,ymm4,8
	vpsrldq	ymm7,ymm0,8
	vpaddq	ymm12,ymm12,ymm8
	vpaddq	ymm2,ymm2,ymm9
	vpaddq	ymm3,ymm3,ymm10
	vpaddq	ymm4,ymm4,ymm6
	vpaddq	ymm0,ymm0,ymm7
	vpermq	ymm10,ymm3,02h
	vpermq	ymm6,ymm4,02h
	vpermq	ymm7,ymm0,02h
	vpermq	ymm8,ymm12,02h
	vpermq	ymm9,ymm2,02h
	vpaddq	ymm3,ymm3,ymm10
	vpaddq	ymm4,ymm4,ymm6
	vpaddq	ymm0,ymm0,ymm7
	vpaddq	ymm12,ymm12,ymm8
	vpaddq	ymm2,ymm2,ymm9
	vpsrlq	ymm14,ymm3,26
	vpand	ymm3,ymm3,ymm5
	vpaddq	ymm4,ymm4,ymm14
	vpsrlq	ymm11,ymm0,26
	vpand	ymm0,ymm0,ymm5
	vpaddq	ymm1,ymm12,ymm11
	vpsrlq	ymm15,ymm4,26
	vpand	ymm4,ymm4,ymm5
	vpsrlq	ymm12,ymm1,26
	vpand	ymm1,ymm1,ymm5
	vpaddq	ymm2,ymm2,ymm12
	vpaddq	ymm0,ymm0,ymm15
	vpsllq	ymm15,ymm15,2
	vpaddq	ymm0,ymm0,ymm15
	vpsrlq	ymm13,ymm2,26
	vpand	ymm2,ymm2,ymm5
	vpaddq	ymm3,ymm3,ymm13
	vpsrlq	ymm11,ymm0,26
	vpand	ymm0,ymm0,ymm5
	vpaddq	ymm1,ymm1,ymm11
	vpsrlq	ymm14,ymm3,26
	vpand	ymm3,ymm3,ymm5
	vpaddq	ymm4,ymm4,ymm14
	vmovd	DWORD PTR[(-112)+rdi],xmm0
	vmovd	DWORD PTR[(-108)+rdi],xmm1
	vmovd	DWORD PTR[(-104)+rdi],xmm2
	vmovd	DWORD PTR[(-100)+rdi],xmm3
	vmovd	DWORD PTR[(-96)+rdi],xmm4
	vmovdqa	xmm6,XMMWORD PTR[80+r11]
	vmovdqa	xmm7,XMMWORD PTR[96+r11]
	vmovdqa	xmm8,XMMWORD PTR[112+r11]
	vmovdqa	xmm9,XMMWORD PTR[128+r11]
	vmovdqa	xmm10,XMMWORD PTR[144+r11]
	vmovdqa	xmm11,XMMWORD PTR[160+r11]
	vmovdqa	xmm12,XMMWORD PTR[176+r11]
	vmovdqa	xmm13,XMMWORD PTR[192+r11]
	vmovdqa	xmm14,XMMWORD PTR[208+r11]
	vmovdqa	xmm15,XMMWORD PTR[224+r11]
	lea	rsp,QWORD PTR[248+r11]
$L$do_avx2_epilogue::
	vzeroupper
	mov	rdi,QWORD PTR[8+rsp]	;WIN64 epilogue
	mov	rsi,QWORD PTR[16+rsp]
	DB	0F3h,0C3h		;repret

$L$SEH_end_poly1305_blocks_avx2::
Poly1305BlocksAVX2	ENDP

ALIGN	32
Poly1305InitAVX512IFMA	PROC PUBLIC
	DB	243,15,30,250
	mov	QWORD PTR[8+rsp],rdi	;WIN64 prologue
	mov	QWORD PTR[16+rsp],rsi
	mov	rax,rsp
$L$SEH_begin_poly1305_init_base2_44::
	mov	rdi,rcx
	mov	rsi,rdx
	mov	rdx,r8
	xor	rax,rax
	mov	QWORD PTR[rdi],rax
	mov	QWORD PTR[8+rdi],rax
	mov	QWORD PTR[16+rdi],rax

$L$init_base2_44::
	mov	rax,00ffffffc0fffffffh
	mov	rcx,00ffffffc0ffffffch
	and	rax,QWORD PTR[rsi]
	mov	r8,000000fffffffffffh
	and	rcx,QWORD PTR[8+rsi]
	mov	r9,000000fffffffffffh
	and	r8,rax
	shrd	rax,rcx,44
	mov	QWORD PTR[40+rdi],r8
	and	rax,r9
	shr	rcx,24
	mov	QWORD PTR[48+rdi],rax
	lea	rax,QWORD PTR[rax*4+rax]
	mov	QWORD PTR[56+rdi],rcx
	shl	rax,2
	lea	rcx,QWORD PTR[rcx*4+rcx]
	shl	rcx,2
	mov	QWORD PTR[24+rdi],rax
	mov	QWORD PTR[32+rdi],rcx
	mov	QWORD PTR[64+rdi],-1
$L$no_key_base2_44::
	mov	rdi,QWORD PTR[8+rsp]	;WIN64 epilogue
	mov	rsi,QWORD PTR[16+rsp]
	DB	0F3h,0C3h		;repret
$L$SEH_end_poly1305_init_base2_44::
Poly1305InitAVX512IFMA	ENDP

ALIGN	32
poly1305_blocks_base2_44	PROC PRIVATE
	DB	243,15,30,250
	mov	QWORD PTR[8+rsp],rdi	;WIN64 prologue
	mov	QWORD PTR[16+rsp],rsi
	mov	rax,rsp
$L$SEH_begin_poly1305_blocks_base2_44::
	mov	rdi,rcx
	mov	rsi,rdx
	mov	rdx,r8
	mov	rcx,r9

$L$blocks_base2_44::
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	and	rdx,-16
	add	rdx,rsi
	shl	rcx,40
	push	rdx

$L$blocks_base2_44_body::
	mov	rdx,QWORD PTR[rdi]
	mov	r8,QWORD PTR[8+rdi]
	mov	r9,QWORD PTR[16+rdi]
	mov	r13,QWORD PTR[40+rdi]
	mov	r14,QWORD PTR[48+rdi]
	mov	r15,QWORD PTR[32+rdi]
	mov	rax,0fffff00000000000h
	jmp	$L$poly1305_loop_base2_44
	ud2

ALIGN	32
$L$poly1305_loop_base2_44::
	mov	r11,QWORD PTR[rsi]
	mov	r12,QWORD PTR[8+rsi]
	lea	rsi,QWORD PTR[16+rsi]
	andn	r10,rax,r11
	shrd	r11,r12,44
	add	rdx,r10
	shr	r12,24
	andn	r11,rax,r11
	add	r9,rcx
	add	r8,r11
	add	r9,r12
	mulx	rbx,r10,r13
	mulx	rcx,r11,r14
	mulx	rbp,r12,QWORD PTR[56+rdi]
	mov	rdx,r8
	mulx	r8,rax,r15
	add	r10,rax
	adc	r8,rbx
	mulx	rbx,rax,r13
	add	r11,rax
	adc	rcx,rbx
	mulx	rbx,rax,r14
	mov	rdx,r9
	add	r12,rax
	adc	rbp,rbx
	mulx	rbx,rax,QWORD PTR[24+rdi]
	add	r10,rax
	adc	r8,rbx
	mulx	r9,rax,r15
	add	r11,rax
	adc	r9,rcx
	mulx	rbx,rax,r13
	add	r12,rax
	adc	rbp,rbx
	mov	rax,0fffff00000000000h
	andn	rdx,rax,r10
	shrd	r10,r8,44
	add	r11,r10
	adc	r9,0
	andn	r8,rax,r11
	shrd	r11,r9,44
	mov	r9,003ffffffffffh
	add	r12,r11
	adc	rbp,0
	and	r9,r12
	shrd	r12,rbp,42
	mov	rcx,010000000000h
	lea	r12,QWORD PTR[r12*4+r12]
	add	rdx,r12
	cmp	rsi,QWORD PTR[rsp]
	jb	$L$poly1305_loop_base2_44
	mov	QWORD PTR[rdi],rdx
	mov	QWORD PTR[8+rdi],r8
	mov	QWORD PTR[16+rdi],r9
	mov	r15,QWORD PTR[8+rsp]
	mov	r14,QWORD PTR[16+rsp]
	mov	r13,QWORD PTR[24+rsp]
	mov	r12,QWORD PTR[32+rsp]
	mov	rbp,QWORD PTR[40+rsp]
	mov	rbx,QWORD PTR[48+rsp]
	lea	rsp,QWORD PTR[56+rsp]

$L$blocks_base2_44_epilogue::
	mov	rdi,QWORD PTR[8+rsp]	;WIN64 epilogue
	mov	rsi,QWORD PTR[16+rsp]
	DB	0F3h,0C3h		;repret

$L$SEH_end_poly1305_blocks_base2_44::
poly1305_blocks_base2_44	ENDP

ALIGN	32
Poly1305BlocksAVX512IFMA	PROC PUBLIC
	DB	243,15,30,250
	mov	QWORD PTR[8+rsp],rdi	;WIN64 prologue
	mov	QWORD PTR[16+rsp],rsi
	mov	rax,rsp
$L$SEH_begin_poly1305_blocks_vpmadd52::
	mov	rdi,rcx
	mov	rsi,rdx
	mov	rdx,r8
	mov	rcx,r9
	and	rdx,-16
	jz	$L$poly1305_no_data_vpmadd52
	mov	r8,QWORD PTR[64+rdi]
	mov	r9,030h
	mov	r10,010h
	cmp	rdx,040h
	cmovae	r9,r10
	test	r8,r8
	cmovns	r9,r10
	and	r9,rdx
	jz	$L$blocks_vpmadd52_4x
	sub	rdx,r9
	cmovz	rdx,r9
	jz	$L$blocks_base2_44
	mov	r10d,7
	mov	r11d,1
	shl	rcx,40
	kmovw	k7,r10d
	lea	r10,QWORD PTR[$L$2_44_inp_permd]
	kmovw	k1,r11d
	vmovq	xmm21,rcx
	shr	rcx,40
	vmovdqa64	ymm19,YMMWORD PTR[r10]
	vmovdqa64	ymm20,YMMWORD PTR[32+r10]
	vpermq	ymm21,ymm21,0cfh
	vmovdqa64	ymm22,YMMWORD PTR[64+r10]
	vmovdqu64	ymm16{k7}{z},[rdi]
	vmovdqu64	ymm3{k7}{z},[40+rdi]
	vmovdqu64	ymm4{k7}{z},[32+rdi]
	vmovdqu64	ymm5{k7}{z},[24+rdi]
	vmovdqa64	ymm23,YMMWORD PTR[96+r10]
	vmovdqa64	ymm24,YMMWORD PTR[128+r10]
	vmovdqu32	xmm18,XMMWORD PTR[rsi]
	lea	rsi,QWORD PTR[16+rsi]
	vpermd	ymm18,ymm19,ymm18
	vpsrlvq	ymm18,ymm18,ymm20
	vpandq	ymm18,ymm18,ymm22
	vporq	ymm18,ymm18,ymm21
	vpaddq	ymm16,ymm16,ymm18
	vpxord	ymm27,ymm27,ymm27
	vpxord	ymm28,ymm28,ymm28
	vpermq	ymm0{k7}{z},ymm16,0
	vpermq	ymm1{k7}{z},ymm16,85
	vpermq	ymm2{k7}{z},ymm16,170
	vpxord	ymm18,ymm18,ymm18
	vpxord	ymm26,ymm26,ymm26
	vpmadd52luq	ymm27,ymm0,ymm3
	vpmadd52huq	ymm28,ymm0,ymm3
	vpxord	ymm16,ymm16,ymm16
	vpxord	ymm17,ymm17,ymm17
	vpmadd52luq	ymm18,ymm1,ymm4
	vpmadd52huq	ymm26,ymm1,ymm4
	vpmadd52luq	ymm16,ymm2,ymm5
	vpmadd52huq	ymm17,ymm2,ymm5
	vpaddq	ymm27,ymm27,ymm18
	vpaddq	ymm28,ymm28,ymm26
	vpaddq	ymm16,ymm16,ymm27
	vpaddq	ymm17,ymm17,ymm28
	vpsrlvq	ymm18,ymm16,ymm23
	vpsllvq	ymm17,ymm17,ymm24
	vpandq	ymm16,ymm16,ymm22
	vpaddq	ymm17,ymm17,ymm18
	vpermq	ymm17,ymm17,147
	vpaddq	ymm16,ymm16,ymm17
	vpsrlvq	ymm18,ymm16,ymm23
	vpandq	ymm16,ymm16,ymm22
	vpermq	ymm18,ymm18,147
	vpaddq	ymm16,ymm16,ymm18
	vpermq	ymm18{k1}{z},ymm16,147
	vpaddq	ymm16,ymm16,ymm18
	vpsllq	ymm18,ymm18,2
	vpaddq	ymm16,ymm16,ymm18
	vmovdqu64	YMMWORD PTR[rdi]{k7},ymm16
	jmp	$L$blocks_vpmadd52_4x

$L$poly1305_no_data_vpmadd52::
	mov	rdi,QWORD PTR[8+rsp]	;WIN64 epilogue
	mov	rsi,QWORD PTR[16+rsp]
	DB	0F3h,0C3h		;repret
$L$SEH_end_poly1305_blocks_vpmadd52::
Poly1305BlocksAVX512IFMA	ENDP

ALIGN	32
poly1305_blocks_vpmadd52_4x	PROC PRIVATE
	DB	243,15,30,250
	mov	QWORD PTR[8+rsp],rdi	;WIN64 prologue
	mov	QWORD PTR[16+rsp],rsi
	mov	rax,rsp
$L$SEH_begin_poly1305_blocks_vpmadd52_4x::
	mov	rdi,rcx
	mov	rsi,rdx
	mov	rdx,r8
	mov	rcx,r9
	and	rdx,-16
	jz	$L$poly1305_no_data_vpmadd52_4x
	mov	r8,QWORD PTR[64+rdi]

$L$blocks_vpmadd52_4x::
	shl	rcx,40
	shr	rdx,4
	vpbroadcastq	ymm31,rcx
	vmovdqa64	ymm30,YMMWORD PTR[$L$x_mask44]
	mov	eax,5
	kmovw	k1,eax
	test	r8,r8
	js	$L$init_vpmadd52
	vmovq	xmm0,QWORD PTR[rdi]
	vmovq	xmm1,QWORD PTR[8+rdi]
	vmovq	xmm2,QWORD PTR[16+rdi]
	test	rdx,3
	jnz	$L$blocks_vpmadd52_2x_do

$L$blocks_vpmadd52_4x_do::
	vpbroadcastq	ymm3,QWORD PTR[64+rdi]
	vpbroadcastq	ymm4,QWORD PTR[96+rdi]
	vpbroadcastq	ymm5,QWORD PTR[128+rdi]
	vpbroadcastq	ymm16,QWORD PTR[160+rdi]

$L$blocks_vpmadd52_4x_key_loaded::
	vpsllq	ymm17,ymm5,2
	vpaddq	ymm17,ymm17,ymm5
	vpsllq	ymm17,ymm17,2
	vmovdqu64	ymm26,YMMWORD PTR[rsi]
	vmovdqu64	ymm27,YMMWORD PTR[32+rsi]
	lea	rsi,QWORD PTR[64+rsi]
	vpunpcklqdq	ymm25,ymm26,ymm27
	vpunpckhqdq	ymm27,ymm26,ymm27
	vpsrlq	ymm26,ymm27,24
	vporq	ymm26,ymm26,ymm31
	vpaddq	ymm2,ymm2,ymm26
	vpandq	ymm24,ymm25,ymm30
	vpsrlq	ymm25,ymm25,44
	vpsllq	ymm27,ymm27,20
	vporq	ymm25,ymm25,ymm27
	vpandq	ymm25,ymm25,ymm30
	sub	rdx,4
	jz	$L$tail_vpmadd52_4x
	jmp	$L$poly1305_loop_vpmadd52_4x
	ud2

ALIGN	32
$L$init_vpmadd52::
	vmovq	xmm16,QWORD PTR[24+rdi]
	vmovq	xmm2,QWORD PTR[56+rdi]
	vmovq	xmm17,QWORD PTR[32+rdi]
	vmovq	xmm3,QWORD PTR[40+rdi]
	vmovq	xmm4,QWORD PTR[48+rdi]
	vmovdqa	ymm0,ymm3
	vmovdqa	ymm1,ymm4
	vmovdqa	ymm5,ymm2
	mov	eax,2

$L$mul_init_vpmadd52::
	vpxorq	ymm18,ymm18,ymm18
	vpxorq	ymm19,ymm19,ymm19
	vpxorq	ymm20,ymm20,ymm20
	vpxorq	ymm21,ymm21,ymm21
	vpxorq	ymm22,ymm22,ymm22
	vpxorq	ymm23,ymm23,ymm23
	vpmadd52luq	ymm18,ymm16,ymm2
	vpxorq	ymm24,ymm24,ymm24
	vpxorq	ymm25,ymm25,ymm25
	vpmadd52huq	ymm19,ymm16,ymm2
	vpxorq	ymm26,ymm26,ymm26
	vpxorq	ymm27,ymm27,ymm27
	vpmadd52luq	ymm20,ymm17,ymm2
	vpxorq	ymm28,ymm28,ymm28
	vpxorq	ymm29,ymm29,ymm29
	vpmadd52huq	ymm21,ymm17,ymm2
	vpmadd52luq	ymm22,ymm3,ymm2
	vpmadd52huq	ymm23,ymm3,ymm2
	vpmadd52luq	ymm24,ymm3,ymm0
	vpmadd52huq	ymm25,ymm3,ymm0
	vpmadd52luq	ymm26,ymm4,ymm0
	vpmadd52huq	ymm27,ymm4,ymm0
	vpmadd52luq	ymm28,ymm5,ymm0
	vpmadd52huq	ymm29,ymm5,ymm0
	vpmadd52luq	ymm18,ymm17,ymm1
	vpmadd52huq	ymm19,ymm17,ymm1
	vpmadd52luq	ymm20,ymm3,ymm1
	vpmadd52huq	ymm21,ymm3,ymm1
	vpaddq	ymm18,ymm18,ymm24
	vpaddq	ymm19,ymm19,ymm25
	vpmadd52luq	ymm22,ymm4,ymm1
	vpaddq	ymm20,ymm20,ymm26
	vpaddq	ymm21,ymm21,ymm27
	vpmadd52huq	ymm23,ymm4,ymm1
	vpaddq	ymm22,ymm22,ymm28
	vpaddq	ymm23,ymm23,ymm29
	vpsrlq	ymm29,ymm18,44
	vpsllq	ymm19,ymm19,8
	vpandq	ymm0,ymm18,ymm30
	vpaddq	ymm19,ymm19,ymm29
	vpaddq	ymm20,ymm20,ymm19
	vpsrlq	ymm29,ymm20,44
	vpsllq	ymm21,ymm21,8
	vpandq	ymm1,ymm20,ymm30
	vpaddq	ymm21,ymm21,ymm29
	vpaddq	ymm22,ymm22,ymm21
	vpsrlq	ymm29,ymm22,42
	vpsllq	ymm23,ymm23,10
	vpandq	ymm2,ymm22,YMMWORD PTR[$L$x_mask42]
	vpaddq	ymm23,ymm23,ymm29
	vpaddq	ymm0,ymm0,ymm23
	vpsllq	ymm23,ymm23,2
	vpaddq	ymm0,ymm0,ymm23
	vpsrlq	ymm29,ymm0,44
	vpandq	ymm0,ymm0,ymm30
	vpaddq	ymm1,ymm1,ymm29
	dec	eax
	jz	$L$done_init_vpmadd52
	vpunpcklqdq	ymm4,ymm1,ymm4
	vpbroadcastq	xmm1,xmm1
	vpunpcklqdq	ymm5,ymm2,ymm5
	vpbroadcastq	xmm2,xmm2
	vpunpcklqdq	ymm3,ymm0,ymm3
	vpbroadcastq	xmm0,xmm0
	vpsllq	ymm16,ymm4,2
	vpsllq	ymm17,ymm5,2
	vpaddq	ymm16,ymm16,ymm4
	vpaddq	ymm17,ymm17,ymm5
	vpsllq	ymm16,ymm16,2
	vpsllq	ymm17,ymm17,2
	jmp	$L$mul_init_vpmadd52
	ud2

ALIGN	32
$L$done_init_vpmadd52::
	vinserti128	ymm4,ymm1,xmm4,1
	vinserti128	ymm5,ymm2,xmm5,1
	vinserti128	ymm3,ymm0,xmm3,1
	vpermq	ymm4,ymm4,216
	vpermq	ymm5,ymm5,216
	vpermq	ymm3,ymm3,216
	vpsllq	ymm16,ymm4,2
	vpaddq	ymm16,ymm16,ymm4
	vpsllq	ymm16,ymm16,2
	vmovq	xmm0,QWORD PTR[rdi]
	vmovq	xmm1,QWORD PTR[8+rdi]
	vmovq	xmm2,QWORD PTR[16+rdi]
	test	rdx,3
	jnz	$L$done_init_vpmadd52_2x
	vmovdqu64	YMMWORD PTR[64+rdi],ymm3
	vpbroadcastq	ymm3,xmm3
	vmovdqu64	YMMWORD PTR[96+rdi],ymm4
	vpbroadcastq	ymm4,xmm4
	vmovdqu64	YMMWORD PTR[128+rdi],ymm5
	vpbroadcastq	ymm5,xmm5
	vmovdqu64	YMMWORD PTR[160+rdi],ymm16
	vpbroadcastq	ymm16,xmm16
	jmp	$L$blocks_vpmadd52_4x_key_loaded
	ud2

ALIGN	32
$L$done_init_vpmadd52_2x::
	vmovdqu64	YMMWORD PTR[64+rdi],ymm3
	vpsrldq	ymm3,ymm3,8
	vmovdqu64	YMMWORD PTR[96+rdi],ymm4
	vpsrldq	ymm4,ymm4,8
	vmovdqu64	YMMWORD PTR[128+rdi],ymm5
	vpsrldq	ymm5,ymm5,8
	vmovdqu64	YMMWORD PTR[160+rdi],ymm16
	vpsrldq	ymm16,ymm16,8
	jmp	$L$blocks_vpmadd52_2x_key_loaded
	ud2

ALIGN	32
$L$blocks_vpmadd52_2x_do::
	vmovdqu64	ymm5{k1}{z},[((128+8))+rdi]
	vmovdqu64	ymm16{k1}{z},[((160+8))+rdi]
	vmovdqu64	ymm3{k1}{z},[((64+8))+rdi]
	vmovdqu64	ymm4{k1}{z},[((96+8))+rdi]

$L$blocks_vpmadd52_2x_key_loaded::
	vmovdqu64	ymm26,YMMWORD PTR[rsi]
	vpxorq	ymm27,ymm27,ymm27
	lea	rsi,QWORD PTR[32+rsi]
	vpunpcklqdq	ymm25,ymm26,ymm27
	vpunpckhqdq	ymm27,ymm26,ymm27
	vpsrlq	ymm26,ymm27,24
	vporq	ymm26,ymm26,ymm31
	vpaddq	ymm2,ymm2,ymm26
	vpandq	ymm24,ymm25,ymm30
	vpsrlq	ymm25,ymm25,44
	vpsllq	ymm27,ymm27,20
	vporq	ymm25,ymm25,ymm27
	vpandq	ymm25,ymm25,ymm30
	jmp	$L$tail_vpmadd52_2x
	ud2

ALIGN	32
$L$poly1305_loop_vpmadd52_4x::
	vpaddq	ymm0,ymm0,ymm24
	vpaddq	ymm1,ymm1,ymm25
	vpxorq	ymm18,ymm18,ymm18
	vpxorq	ymm19,ymm19,ymm19
	vpxorq	ymm20,ymm20,ymm20
	vpxorq	ymm21,ymm21,ymm21
	vpxorq	ymm22,ymm22,ymm22
	vpxorq	ymm23,ymm23,ymm23
	vpmadd52luq	ymm18,ymm16,ymm2
	vpxorq	ymm24,ymm24,ymm24
	vpxorq	ymm25,ymm25,ymm25
	vpmadd52huq	ymm19,ymm16,ymm2
	vpxorq	ymm26,ymm26,ymm26
	vpxorq	ymm27,ymm27,ymm27
	vpmadd52luq	ymm20,ymm17,ymm2
	vpxorq	ymm28,ymm28,ymm28
	vpxorq	ymm29,ymm29,ymm29
	vpmadd52huq	ymm21,ymm17,ymm2
	vpmadd52luq	ymm22,ymm3,ymm2
	vpmadd52huq	ymm23,ymm3,ymm2
	vpmadd52luq	ymm24,ymm3,ymm0
	vpmadd52huq	ymm25,ymm3,ymm0
	vpmadd52luq	ymm26,ymm4,ymm0
	vpmadd52huq	ymm27,ymm4,ymm0
	vpmadd52luq	ymm28,ymm5,ymm0
	vpmadd52huq	ymm29,ymm5,ymm0
	vpmadd52luq	ymm18,ymm17,ymm1
	vpmadd52huq	ymm19,ymm17,ymm1
	vpmadd52luq	ymm20,ymm3,ymm1
	vpmadd52huq	ymm21,ymm3,ymm1
	vpaddq	ymm18,ymm18,ymm24
	vpaddq	ymm19,ymm19,ymm25
	vpmadd52luq	ymm22,ymm4,ymm1
	vpaddq	ymm20,ymm20,ymm26
	vpaddq	ymm21,ymm21,ymm27
	vpmadd52huq	ymm23,ymm4,ymm1
	vpaddq	ymm22,ymm22,ymm28
	vpaddq	ymm23,ymm23,ymm29
	vmovdqu64	ymm26,YMMWORD PTR[rsi]
	vmovdqu64	ymm27,YMMWORD PTR[32+rsi]
	lea	rsi,QWORD PTR[64+rsi]
	vpunpcklqdq	ymm25,ymm26,ymm27
	vpunpckhqdq	ymm27,ymm26,ymm27
	vpsrlq	ymm29,ymm18,44
	vpsllq	ymm19,ymm19,8
	vpandq	ymm0,ymm18,ymm30
	vpaddq	ymm19,ymm19,ymm29
	vpsrlq	ymm26,ymm27,24
	vporq	ymm26,ymm26,ymm31
	vpaddq	ymm20,ymm20,ymm19
	vpsrlq	ymm29,ymm20,44
	vpsllq	ymm21,ymm21,8
	vpandq	ymm1,ymm20,ymm30
	vpaddq	ymm21,ymm21,ymm29
	vpandq	ymm24,ymm25,ymm30
	vpsrlq	ymm25,ymm25,44
	vpsllq	ymm27,ymm27,20
	vpaddq	ymm22,ymm22,ymm21
	vpsrlq	ymm29,ymm22,42
	vpsllq	ymm23,ymm23,10
	vpandq	ymm2,ymm22,YMMWORD PTR[$L$x_mask42]
	vpaddq	ymm23,ymm23,ymm29
	vpaddq	ymm2,ymm2,ymm26
	vpaddq	ymm0,ymm0,ymm23
	vpsllq	ymm23,ymm23,2
	vpaddq	ymm0,ymm0,ymm23
	vporq	ymm25,ymm25,ymm27
	vpandq	ymm25,ymm25,ymm30
	vpsrlq	ymm29,ymm0,44
	vpandq	ymm0,ymm0,ymm30
	vpaddq	ymm1,ymm1,ymm29
	sub	rdx,4
	jnz	$L$poly1305_loop_vpmadd52_4x

$L$tail_vpmadd52_4x::
	vmovdqu64	ymm5,YMMWORD PTR[128+rdi]
	vmovdqu64	ymm16,YMMWORD PTR[160+rdi]
	vmovdqu64	ymm3,YMMWORD PTR[64+rdi]
	vmovdqu64	ymm4,YMMWORD PTR[96+rdi]

$L$tail_vpmadd52_2x::
	vpsllq	ymm17,ymm5,2
	vpaddq	ymm17,ymm17,ymm5
	vpsllq	ymm17,ymm17,2
	vpaddq	ymm0,ymm0,ymm24
	vpaddq	ymm1,ymm1,ymm25
	vpxorq	ymm18,ymm18,ymm18
	vpxorq	ymm19,ymm19,ymm19
	vpxorq	ymm20,ymm20,ymm20
	vpxorq	ymm21,ymm21,ymm21
	vpxorq	ymm22,ymm22,ymm22
	vpxorq	ymm23,ymm23,ymm23
	vpmadd52luq	ymm18,ymm16,ymm2
	vpxorq	ymm24,ymm24,ymm24
	vpxorq	ymm25,ymm25,ymm25
	vpmadd52huq	ymm19,ymm16,ymm2
	vpxorq	ymm26,ymm26,ymm26
	vpxorq	ymm27,ymm27,ymm27
	vpmadd52luq	ymm20,ymm17,ymm2
	vpxorq	ymm28,ymm28,ymm28
	vpxorq	ymm29,ymm29,ymm29
	vpmadd52huq	ymm21,ymm17,ymm2
	vpmadd52luq	ymm22,ymm3,ymm2
	vpmadd52huq	ymm23,ymm3,ymm2
	vpmadd52luq	ymm24,ymm3,ymm0
	vpmadd52huq	ymm25,ymm3,ymm0
	vpmadd52luq	ymm26,ymm4,ymm0
	vpmadd52huq	ymm27,ymm4,ymm0
	vpmadd52luq	ymm28,ymm5,ymm0
	vpmadd52huq	ymm29,ymm5,ymm0
	vpmadd52luq	ymm18,ymm17,ymm1
	vpmadd52huq	ymm19,ymm17,ymm1
	vpmadd52luq	ymm20,ymm3,ymm1
	vpmadd52huq	ymm21,ymm3,ymm1
	vpaddq	ymm18,ymm18,ymm24
	vpaddq	ymm19,ymm19,ymm25
	vpmadd52luq	ymm22,ymm4,ymm1
	vpaddq	ymm20,ymm20,ymm26
	vpaddq	ymm21,ymm21,ymm27
	vpmadd52huq	ymm23,ymm4,ymm1
	vpaddq	ymm22,ymm22,ymm28
	vpaddq	ymm23,ymm23,ymm29
	mov	eax,1
	kmovw	k1,eax
	vpsrldq	ymm24,ymm18,8
	vpsrldq	ymm0,ymm19,8
	vpsrldq	ymm25,ymm20,8
	vpsrldq	ymm1,ymm21,8
	vpaddq	ymm18,ymm18,ymm24
	vpaddq	ymm19,ymm19,ymm0
	vpsrldq	ymm26,ymm22,8
	vpsrldq	ymm2,ymm23,8
	vpaddq	ymm20,ymm20,ymm25
	vpaddq	ymm21,ymm21,ymm1
	vpermq	ymm24,ymm18,02h
	vpermq	ymm0,ymm19,02h
	vpaddq	ymm22,ymm22,ymm26
	vpaddq	ymm23,ymm23,ymm2
	vpermq	ymm25,ymm20,02h
	vpermq	ymm1,ymm21,02h
	vpaddq	ymm18{k1}{z},ymm18,ymm24
	vpaddq	ymm19{k1}{z},ymm19,ymm0
	vpermq	ymm26,ymm22,02h
	vpermq	ymm2,ymm23,02h
	vpaddq	ymm20{k1}{z},ymm20,ymm25
	vpaddq	ymm21{k1}{z},ymm21,ymm1
	vpaddq	ymm22{k1}{z},ymm22,ymm26
	vpaddq	ymm23{k1}{z},ymm23,ymm2
	vpsrlq	ymm29,ymm18,44
	vpsllq	ymm19,ymm19,8
	vpandq	ymm0,ymm18,ymm30
	vpaddq	ymm19,ymm19,ymm29
	vpaddq	ymm20,ymm20,ymm19
	vpsrlq	ymm29,ymm20,44
	vpsllq	ymm21,ymm21,8
	vpandq	ymm1,ymm20,ymm30
	vpaddq	ymm21,ymm21,ymm29
	vpaddq	ymm22,ymm22,ymm21
	vpsrlq	ymm29,ymm22,42
	vpsllq	ymm23,ymm23,10
	vpandq	ymm2,ymm22,YMMWORD PTR[$L$x_mask42]
	vpaddq	ymm23,ymm23,ymm29
	vpaddq	ymm0,ymm0,ymm23
	vpsllq	ymm23,ymm23,2
	vpaddq	ymm0,ymm0,ymm23
	vpsrlq	ymm29,ymm0,44
	vpandq	ymm0,ymm0,ymm30
	vpaddq	ymm1,ymm1,ymm29
	sub	rdx,2
	ja	$L$blocks_vpmadd52_4x_do
	vmovq	QWORD PTR[rdi],xmm0
	vmovq	QWORD PTR[8+rdi],xmm1
	vmovq	QWORD PTR[16+rdi],xmm2
	vzeroall

$L$poly1305_no_data_vpmadd52_4x::
	mov	rdi,QWORD PTR[8+rsp]	;WIN64 epilogue
	mov	rsi,QWORD PTR[16+rsp]
	DB	0F3h,0C3h		;repret
$L$SEH_end_poly1305_blocks_vpmadd52_4x::
poly1305_blocks_vpmadd52_4x	ENDP

ALIGN	32
Poly1305EmitAVX512IFMA	PROC PUBLIC
	DB	243,15,30,250
	mov	QWORD PTR[8+rsp],rdi	;WIN64 prologue
	mov	QWORD PTR[16+rsp],rsi
	mov	rax,rsp
$L$SEH_begin_poly1305_emit_base2_44::
	mov	rdi,rcx
	mov	rsi,rdx
	mov	rdx,r8
	mov	r8,QWORD PTR[rdi]
	mov	r9,QWORD PTR[8+rdi]
	mov	r10,QWORD PTR[16+rdi]
	mov	rax,r9
	shr	r9,20
	shl	rax,44
	mov	rcx,r10
	shr	r10,40
	shl	rcx,24
	add	r8,rax
	adc	r9,rcx
	adc	r10,0
	mov	rax,r8
	add	r8,5
	mov	rcx,r9
	adc	r9,0
	adc	r10,0
	shr	r10,2
	cmovnz	rax,r8
	cmovnz	rcx,r9
	add	rax,QWORD PTR[rdx]
	adc	rcx,QWORD PTR[8+rdx]
	mov	QWORD PTR[rsi],rax
	mov	QWORD PTR[8+rsi],rcx
	mov	rdi,QWORD PTR[8+rsp]	;WIN64 epilogue
	mov	rsi,QWORD PTR[16+rsp]
	DB	0F3h,0C3h		;repret
$L$SEH_end_poly1305_emit_base2_44::
Poly1305EmitAVX512IFMA	ENDP
ALIGN	64
$L$const::
$L$mask24::
	DD	00ffffffh,0,00ffffffh,0,00ffffffh,0,00ffffffh,0
$L$129::
	DD	16777216,0,16777216,0,16777216,0,16777216,0
$L$mask26::
	DD	03ffffffh,0,03ffffffh,0,03ffffffh,0,03ffffffh,0
$L$permd_avx2::
	DD	2,2,2,3,2,0,2,1
$L$permd_avx512::
	DD	0,0,0,1,0,2,0,3,0,4,0,5,0,6,0,7

$L$2_44_inp_permd::
	DD	0,1,1,2,2,3,7,7
$L$2_44_inp_shift::
	DQ	0,12,24,64
$L$2_44_mask::
	DQ	0fffffffffffh,0fffffffffffh,03ffffffffffh,0ffffffffffffffffh
$L$2_44_shift_rgt::
	DQ	44,44,42,64
$L$2_44_shift_lft::
	DQ	8,8,10,64

ALIGN	64
$L$x_mask44::
	DQ	0fffffffffffh,0fffffffffffh,0fffffffffffh,0fffffffffffh
	DQ	0fffffffffffh,0fffffffffffh,0fffffffffffh,0fffffffffffh
$L$x_mask42::
	DQ	03ffffffffffh,03ffffffffffh,03ffffffffffh,03ffffffffffh
	DQ	03ffffffffffh,03ffffffffffh,03ffffffffffh,03ffffffffffh

ALIGN	16
poly1305_se_handler	PROC PRIVATE
	DB	243,15,30,250
	push	rsi
	push	rdi
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	pushfq
	sub	rsp,64
	mov	rax,QWORD PTR[120+r8]
	mov	rbx,QWORD PTR[248+r8]
	mov	rsi,QWORD PTR[8+r9]
	mov	r11,QWORD PTR[56+r9]
	mov	r10d,DWORD PTR[r11]
	lea	r10,QWORD PTR[r10*1+rsi]
	cmp	rbx,r10
	jb	$L$poly1305_common_seh_tail
	mov	rax,QWORD PTR[152+r8]
	mov	r10d,DWORD PTR[4+r11]
	lea	r10,QWORD PTR[r10*1+rsi]
	cmp	rbx,r10
	jae	$L$poly1305_common_seh_tail
	lea	rax,QWORD PTR[56+rax]
	mov	rbx,QWORD PTR[((-8))+rax]
	mov	rbp,QWORD PTR[((-16))+rax]
	mov	r12,QWORD PTR[((-24))+rax]
	mov	r13,QWORD PTR[((-32))+rax]
	mov	r14,QWORD PTR[((-40))+rax]
	mov	r15,QWORD PTR[((-48))+rax]
	mov	QWORD PTR[144+r8],rbx
	mov	QWORD PTR[160+r8],rbp
	mov	QWORD PTR[216+r8],r12
	mov	QWORD PTR[224+r8],r13
	mov	QWORD PTR[232+r8],r14
	mov	QWORD PTR[240+r8],r15
	jmp	$L$poly1305_common_seh_tail
poly1305_se_handler	ENDP

ALIGN	16
poly1305_avx_handler	PROC PRIVATE
	DB	243,15,30,250
	push	rsi
	push	rdi
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	pushfq
	sub	rsp,64
	mov	rax,QWORD PTR[120+r8]
	mov	rbx,QWORD PTR[248+r8]
	mov	rsi,QWORD PTR[8+r9]
	mov	r11,QWORD PTR[56+r9]
	mov	r10d,DWORD PTR[r11]
	lea	r10,QWORD PTR[r10*1+rsi]
	cmp	rbx,r10
	jb	$L$poly1305_common_seh_tail
	mov	rax,QWORD PTR[152+r8]
	mov	r10d,DWORD PTR[4+r11]
	lea	r10,QWORD PTR[r10*1+rsi]
	cmp	rbx,r10
	jae	$L$poly1305_common_seh_tail
	mov	rax,QWORD PTR[208+r8]
	lea	rsi,QWORD PTR[80+rax]
	lea	rax,QWORD PTR[248+rax]
	lea	rdi,QWORD PTR[512+r8]
	mov	ecx,20
	DD	0a548f3fch

$L$poly1305_common_seh_tail::
	mov	rdi,QWORD PTR[8+rax]
	mov	rsi,QWORD PTR[16+rax]
	mov	QWORD PTR[152+r8],rax
	mov	QWORD PTR[168+r8],rsi
	mov	QWORD PTR[176+r8],rdi
	mov	rdi,QWORD PTR[40+r9]
	mov	rsi,r8
	mov	ecx,154
	DD	0a548f3fch
	mov	rsi,r9
	xor	rcx,rcx
	mov	rdx,QWORD PTR[8+rsi]
	mov	r8,QWORD PTR[rsi]
	mov	r9,QWORD PTR[16+rsi]
	mov	r10,QWORD PTR[40+rsi]
	lea	r11,QWORD PTR[56+rsi]
	lea	r12,QWORD PTR[24+rsi]
	mov	QWORD PTR[32+rsp],r10
	mov	QWORD PTR[40+rsp],r11
	mov	QWORD PTR[48+rsp],r12
	mov	QWORD PTR[56+rsp],rcx
	call	QWORD PTR[__imp_RtlVirtualUnwind]
	mov	eax,1
	add	rsp,64
	popfq
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	pop	rdi
	pop	rsi
	DB	0F3h,0C3h		;repret
poly1305_avx_handler	ENDP

.text$	ENDS
.pdata	SEGMENT READONLY ALIGN(4)
ALIGN	4
	DD	imagerel $L$SEH_begin_chacha20_ctr32
	DD	imagerel $L$SEH_end_chacha20_ctr32
	DD	imagerel $L$SEH_info_chacha20_ctr32
	DD	imagerel $L$SEH_begin_chacha20_ssse3
	DD	imagerel $L$SEH_end_chacha20_ssse3
	DD	imagerel $L$SEH_info_chacha20_ssse3
	DD	imagerel $L$SEH_begin_chacha20_128
	DD	imagerel $L$SEH_end_chacha20_128
	DD	imagerel $L$SEH_info_chacha20_128
	DD	imagerel $L$SEH_begin_chacha20_4x
	DD	imagerel $L$SEH_end_chacha20_4x
	DD	imagerel $L$SEH_info_chacha20_4x
	DD	imagerel $L$SEH_begin_chacha20_avx2
	DD	imagerel $L$SEH_end_chacha20_avx2
	DD	imagerel $L$SEH_info_chacha20_avx2
	DD	imagerel $L$SEH_begin_chacha20_avx512
	DD	imagerel $L$SEH_end_chacha20_avx512
	DD	imagerel $L$SEH_info_chacha20_avx512
	DD	imagerel $L$SEH_begin_chacha20_avx512vl
	DD	imagerel $L$SEH_end_chacha20_avx512vl
	DD	imagerel $L$SEH_info_chacha20_avx512vl
	DD	imagerel $L$SEH_begin_chacha20_16x
	DD	imagerel $L$SEH_end_chacha20_16x
	DD	imagerel $L$SEH_info_chacha20_16x
	DD	imagerel $L$SEH_begin_chacha20_8xvl
	DD	imagerel $L$SEH_end_chacha20_8xvl
	DD	imagerel $L$SEH_info_chacha20_8xvl
.pdata	ENDS
.xdata	SEGMENT READONLY ALIGN(8)
ALIGN	8
$L$SEH_info_chacha20_ctr32::
DB	9,0,0,0
	DD	imagerel chacha20_se_handler

$L$SEH_info_chacha20_ssse3::
DB	9,0,0,0
	DD	imagerel chacha20_simd_handler
	DD	imagerel $L$ssse3_body,imagerel $L$ssse3_epilogue
	DD	020h,0

$L$SEH_info_chacha20_128::
DB	9,0,0,0
	DD	imagerel chacha20_simd_handler
	DD	imagerel $L$128_body,imagerel $L$128_epilogue
	DD	060h,0

$L$SEH_info_chacha20_4x::
DB	9,0,0,0
	DD	imagerel chacha20_simd_handler
	DD	imagerel $L$4x_body,imagerel $L$4x_epilogue
	DD	0a0h,0
$L$SEH_info_chacha20_avx2::
DB	9,0,0,0
	DD	imagerel chacha20_simd_handler
	DD	imagerel $L$avx2_body,imagerel $L$avx2_epilogue
	DD	0a0h,0
$L$SEH_info_chacha20_avx512::
DB	9,0,0,0
	DD	imagerel chacha20_simd_handler
	DD	imagerel $L$avx512_body,imagerel $L$avx512_epilogue
	DD	020h,0

$L$SEH_info_chacha20_avx512vl::
DB	9,0,0,0
	DD	imagerel chacha20_simd_handler
	DD	imagerel $L$avx512vl_body,imagerel $L$avx512vl_epilogue
	DD	020h,0

$L$SEH_info_chacha20_16x::
DB	9,0,0,0
	DD	imagerel chacha20_simd_handler
	DD	imagerel $L$16x_body,imagerel $L$16x_epilogue
	DD	0a0h,0

$L$SEH_info_chacha20_8xvl::
DB	9,0,0,0
	DD	imagerel chacha20_simd_handler
	DD	imagerel $L$8xvl_body,imagerel $L$8xvl_epilogue
	DD	0a0h,0
.xdata	ENDS
.pdata	SEGMENT READONLY ALIGN(4)
ALIGN	4
.pdata	ENDS
.xdata	SEGMENT READONLY ALIGN(8)
ALIGN	8

.xdata	ENDS
END

.pdata	SEGMENT READONLY ALIGN(4)
ALIGN	4
	DD	imagerel $L$SEH_begin_poly1305_init
	DD	imagerel $L$SEH_end_poly1305_init
	DD	imagerel $L$SEH_info_poly1305_init
	DD	imagerel $L$SEH_begin_poly1305_blocks
	DD	imagerel $L$SEH_end_poly1305_blocks
	DD	imagerel $L$SEH_info_poly1305_blocks
	DD	imagerel $L$SEH_begin_poly1305_emit
	DD	imagerel $L$SEH_end_poly1305_emit
	DD	imagerel $L$SEH_info_poly1305_emit
	DD	imagerel $L$SEH_begin_poly1305_blocks_avx
	DD	imagerel $L$base2_64_avx
	DD	imagerel $L$SEH_info_poly1305_blocks_avx_1
	DD	imagerel $L$base2_64_avx
	DD	imagerel $L$even_avx
	DD	imagerel $L$SEH_info_poly1305_blocks_avx_2
	DD	imagerel $L$even_avx
	DD	imagerel $L$SEH_end_poly1305_blocks_avx
	DD	imagerel $L$SEH_info_poly1305_blocks_avx_3
	DD	imagerel $L$SEH_begin_poly1305_blocks_avx2
	DD	imagerel $L$base2_64_avx2
	DD	imagerel $L$SEH_info_poly1305_blocks_avx2_1
	DD	imagerel $L$base2_64_avx2
	DD	imagerel $L$even_avx2
	DD	imagerel $L$SEH_info_poly1305_blocks_avx2_2
	DD	imagerel $L$even_avx2
	DD	imagerel $L$SEH_end_poly1305_blocks_avx2
	DD	imagerel $L$SEH_info_poly1305_blocks_avx2_3
	DD	imagerel $L$SEH_begin_poly1305_blocks_avx512
	DD	imagerel $L$SEH_end_poly1305_blocks_avx512
	DD	imagerel $L$SEH_info_poly1305_blocks_avx512
	DD	imagerel $L$SEH_begin_poly1305_init_base2_44
	DD	imagerel $L$SEH_end_poly1305_init_base2_44
	DD	imagerel $L$SEH_info_poly1305_init_base2_44
	DD	imagerel $L$SEH_begin_poly1305_blocks_base2_44
	DD	imagerel $L$SEH_end_poly1305_blocks_base2_44
	DD	imagerel $L$SEH_info_poly1305_blocks_base2_44
	DD	imagerel $L$SEH_begin_poly1305_blocks_vpmadd52
	DD	imagerel $L$SEH_end_poly1305_blocks_vpmadd52
	DD	imagerel $L$SEH_info_poly1305_blocks_vpmadd52
	DD	imagerel $L$SEH_begin_poly1305_blocks_vpmadd52_4x
	DD	imagerel $L$SEH_end_poly1305_blocks_vpmadd52_4x
	DD	imagerel $L$SEH_info_poly1305_blocks_vpmadd52_4x
	DD	imagerel $L$SEH_begin_poly1305_emit_base2_44
	DD	imagerel $L$SEH_end_poly1305_emit_base2_44
	DD	imagerel $L$SEH_info_poly1305_emit_base2_44
.pdata	ENDS
.xdata	SEGMENT READONLY ALIGN(8)
ALIGN	8
$L$SEH_info_poly1305_init::
DB	9,0,0,0
	DD	imagerel poly1305_se_handler
	DD	0,0

$L$SEH_info_poly1305_blocks::
DB	9,0,0,0
	DD	imagerel poly1305_se_handler
	DD	imagerel $L$blocks_body,imagerel $L$blocks_epilogue

$L$SEH_info_poly1305_emit::
DB	9,0,0,0
	DD	imagerel poly1305_se_handler
	DD	0,0
$L$SEH_info_poly1305_blocks_avx_1::
DB	9,0,0,0
	DD	imagerel poly1305_se_handler
	DD	imagerel $L$blocks_avx_body,imagerel $L$blocks_avx_epilogue

$L$SEH_info_poly1305_blocks_avx_2::
DB	9,0,0,0
	DD	imagerel poly1305_se_handler
	DD	imagerel $L$base2_64_avx_body,imagerel $L$base2_64_avx_epilogue

$L$SEH_info_poly1305_blocks_avx_3::
DB	9,0,0,0
	DD	imagerel poly1305_avx_handler
	DD	imagerel $L$do_avx_body,imagerel $L$do_avx_epilogue
$L$SEH_info_poly1305_blocks_avx2_1::
DB	9,0,0,0
	DD	imagerel poly1305_se_handler
	DD	imagerel $L$blocks_avx2_body,imagerel $L$blocks_avx2_epilogue

$L$SEH_info_poly1305_blocks_avx2_2::
DB	9,0,0,0
	DD	imagerel poly1305_se_handler
	DD	imagerel $L$base2_64_avx2_body,imagerel $L$base2_64_avx2_epilogue

$L$SEH_info_poly1305_blocks_avx2_3::
DB	9,0,0,0
	DD	imagerel poly1305_avx_handler
	DD	imagerel $L$do_avx2_body,imagerel $L$do_avx2_epilogue
$L$SEH_info_poly1305_blocks_avx512::
DB	9,0,0,0
	DD	imagerel poly1305_avx_handler
	DD	imagerel $L$do_avx512_body,imagerel $L$do_avx512_epilogue
$L$SEH_info_poly1305_init_base2_44::
DB	9,0,0,0
	DD	imagerel poly1305_se_handler
	DD	0,0

$L$SEH_info_poly1305_blocks_base2_44::
DB	9,0,0,0
	DD	imagerel poly1305_se_handler
	DD	imagerel $L$blocks_base2_44_body,imagerel $L$blocks_base2_44_epilogue

$L$SEH_info_poly1305_blocks_vpmadd52::
DB	9,0,0,0
	DD	imagerel poly1305_se_handler
	DD	0,0

$L$SEH_info_poly1305_blocks_vpmadd52_4x::
DB	9,0,0,0
	DD	imagerel poly1305_se_handler
	DD	0,0

$L$SEH_info_poly1305_emit_base2_44::
DB	9,0,0,0
	DD	imagerel poly1305_se_handler
	DD	0,0
.xdata	ENDS
.pdata	SEGMENT READONLY ALIGN(4)
ALIGN	4
.pdata	ENDS
.xdata	SEGMENT READONLY ALIGN(8)
ALIGN	8

.xdata	ENDS
END
