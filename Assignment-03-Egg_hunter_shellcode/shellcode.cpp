#include <iostream>

#define EGG "\x90\x50\x90\x50"

unsigned char egghunter[] = "\x48\x8d\x35\xf9\xef\xff\xff\xfc\x6a\x08\x41\x5a\x66\x81\xce\xff\x0f\x48\xff\xc6\x74\xf6\x31\xff\x6a\x0d\x58\x99\x0f\x05\x3c\xf2\x74\xea\xb8\x90\x50\x90\x50\x48\x89\xf7\xaf\x75\xe4\xaf\x75\xe1\xff\xe7";


unsigned char payload[] = EGG EGG \
"\x48\xb8\x48\x65\x6c\x6c\x6f\x20\x21\x0a\x50\x48\x89\xe6\x31\xff\xf7\xe7\xff\xc7\xb2\x08\xff\xc0\x0f\x05\xb0\x3c\x0f\x05";
/*
"Hello !\n" payload
 
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
*/


int main() {

    std::cout << "Payload size : " << sizeof(payload) - 9 << std::endl;
    std::cout << "Egghunter size : " << sizeof(egghunter) - 1 << std::endl;

    void (* hunt)() = (void (*)()) egghunter;

    hunt();
    return 0;
}
