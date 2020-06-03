#!/bin/bash

echo "[x] Assembling..."
nasm $1.nasm -f elf64 -o $1.o

echo "[x] Linking..."
ld $1.o -o $1

echo "[x] Dumped shellcode :"
for i in $(objdump -d $1 -M intel |grep "^ " |cut -f2); do echo -n '\x'$i; done;echo
