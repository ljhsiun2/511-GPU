#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "AES.h"
#include "main.h"

using namespace std;

int main(int argc, char **argv) {
	if(argc < 3) {
		printf("USAGE: aes KEY PLAINTEXT\n");
		return 1;
	}

	byte *key;
	uint ct[4], *pt;
	uint keySize = stringToByteArray(argv[1], &key);
	uint ptSize  = stringToByteArray(argv[2], &pt);
	// printf("keysize is %d: %s\n", keySize, key);
	// printf("ptSize is %d: %s\n", ptSize, pt);

	if(keySize != 16 && keySize != 24 && keySize != 32) {
		printf("Invalid AES key size.\n");
		return 1;
	}

	// if(ptSize != 4) {
	// 	printf("Invalid AES block size. %d\n", ptSize);
	// 	return 1;
	// }

	AES *aes = new AES();

	printf("Key is %s\n", (char*)key);
	printf("Plaintext is %s\n", (char*)pt);

	aes->makeKey(key, keySize << 3, DIR_ENCRYPT);
	int time = clock();
	aes->encrypt(pt, ct);
	printf("Encrypt takes %lu cycles \n", clock()-time);

	printHexArray(ct, 4);

	aes->decrypt(ct, pt);
	printHexArray(pt, 4);

	return 0;
}

uint stringToByteArray(char *str, byte **array) {
	uint i, len  = strlen(str) >> 1;
	*array = (byte *)malloc(len * sizeof(byte));

	for(i=0; i<len; i++)
		sscanf(str + i*2, "%02hhX", *array+i);

	return len;
}

uint stringToByteArray(char *str, uint **array) {
	uint i, len  = strlen(str) >> 3;
	*array = (uint *)malloc(len * sizeof(uint));
	printf("String %s\n", str);
	for(i=0; i<len; i++)
		sscanf(str + i*8, "%08X", *array+i);

	return len;
}

void printHexArray(uint *array, uint size) {
	uint i;
	for(i=0; i<size; i++)
		printf("%08X", array[i]);
	printf("\n");
}
