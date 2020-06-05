; Author :      Demey Alexandre (PA-14186)
; Date :        03-06-2020
; 
; Description : SLAE assignment #3 - Egg hunter shellcode
;               
;              
;
; Shellcode length : 21 to 47 bytes
;

global _start

section .text

_start:

; Get memory address intructions set: 
; used to get the memory address of the first instruction of the decoder

    ;Option 1
    ;;;;;;;;;
    ;ftst                        ; use fpu instructions to get ftst memory address
    ;push rsp                    ; I've learned this technique from an analysis
    ;pop rbx                     ; of the "zutto dekiru" encoder
    ;and bx, 0xfff0              ; 
    ;xor eax, eaxi               ; 
    ;mov ax, 528                 ; 
    ;add rbx, rax                ;
    ;fxsave64[rbx]               ; 25 bytes
    ;mov rsi, qword [rbx + 8]    ; 
    ;hex: \xd9\xe4\x54\x5b\x66\x83\xe3\xf0\x31\xc0\x66\xb8\x10\x02\x48\x01\xc3\x48\x0f\xae\x03\x48\x8b\x73\x08

    ;Option 2
    ;;;;;;;;;
    lea rsi, [rel _start]        ; use RIP relative address
                                 ; 7 bytes
    ;hex: \x48\x8d\x35\xf9\xff\xff\xff


;Don't comment the three following instructions.

    add rsi, 31             ; add the stub size to RSI (will be set automatically)
                            ; RSI point to the start of encoded shellcode

    push 23                 ; shellcode size (will be set automatically) 
    pop rcx                 ; loop counter initialized to shellcode size

decode:
; Two's complement instructions set :
; decode the encoded byte pointed by RSI
; using the two's complement instruction or equivalent

    ;Option 1
    ;;;;;;;;;
    neg byte [rsi]      ; 2 bytes
    ;hex: \xf6\x1e
    
    ;Option 2
    ;;;;;;;;;
    ;xor eax, eax        ; 2 bytes
    ;sub al, [rsi]       ; 2 bytes
    ;mov byte [rsi], al  ; 2 bytes
    ;hex: \x31\xc0\x2a\x06\x88\x06
    
    ;Option 3
    ;;;;;;;;;
    ;not byte [rsi]       ; 2 bytes
    ;inc byte [rsi]       ; 2 bytes
    ;hex: \xf6\x16\xfe\x06


; Increment rsi instructions set : 
; used to point to the next byte to decode

    ;Option 1
    ;;;;;;;;;
    inc rsi              ; 3 bytes
    ;hex: \x48\xff\xc6
    
    ;Option 2
    ;;;;;;;;;
    ;add rsi, 1           ; 4 bytes
    ;hex: \x48\x83\xc6\x01

; Loop instructions set : 
; Jump to decode if RCX != 0
; or exit the loop and exec decoded shellcode

    ;Option 1
    ;;;;;;;;;
    ;dec rcx              ; 
    ;jnz decode           ; 5 bytes
    ;hex: \x48\xff\xc9\x75 + One byte depending of used instructions length and automatically adjusted

    ;Option 2
    ;;;;;;;;;
    loopnz decode        ; 2 bytes
    ;hex: \xe0 + One byte depending of used intructions length and automatically adjusted 


; Here will be the encoded shellcode
