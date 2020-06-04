global _start

section .text

_start:
    mov rax,0x0A21206f6c6c6548
    push rax
    mov rsi, rsp

    xor edi, edi
    mul edi
    inc edi
    mov dl, 8
    inc eax
    syscall

    mov al, 60
    syscall
