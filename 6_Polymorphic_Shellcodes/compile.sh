#!/bin/bash

echo '[+] Assembling with Nasm ... '
nasm -f elf32 -o $1.o $1.nasm

echo '[+] Linking ...'
ld --omagic -z execstack -o $1 $1.o

echo '[+] Done!'



