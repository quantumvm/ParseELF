#include <stdio.h>
#include <string.h>

struct ELF{
	char magic_number[4];
	char _32xor64[1];
	char endianness[1];
};
	
int checkelf(struct ELF *elf, FILE *fp);


int main(int argc, char * argv[]){
	FILE *fp;
	int ERROR;
	char * FILE_NAME = argv[1];
	
	//open up file in read only mode
	fp = fopen(FILE_NAME,"r");
	if(fp == NULL){
		puts("Could not locate file.");
		return 1;
	}

	//initialize our elf struct
	struct ELF elf;
	
	//check to make sure this is a valid ELF executable 
	if(checkelf(&elf, fp)!= 0){
		puts("WOOPS! This is not a valid x86 ELF file.");
		return 1;
	}else{
		puts("Found Valid Magic Number: 0x7F 0x45 0x4c 0x46");
		puts("Found 32bit file: 0x01\n");
	}
	

}



/*
 * Check elf check to see if we have a valid 32 bit executable.
 * If we encounter an error reading the file or this is not a 
 * valid 32-bit executable return 1
 */

int checkelf(struct ELF *elf, FILE *fp){
	//The magic number for ELF: \x76 + ELF
	char magic_number[] = "\x7f\x45\x4C\x46";
	//The byte for a 32-bit elf is 0x01
	char _32bit[] = "\x01";

	fread(elf->magic_number, 4,1,fp);
	if(ferror(fp))
		return 1;
	else if(memcmp(magic_number, elf->magic_number, 4) != 0)
		return 1;
	
	fread(elf->_32xor64, 1,1,fp);
	if(ferror(fp))
		return 1;
	else if(memcmp(_32bit, elf->_32xor64, 1) != 0)
		return 1;
		
	return 0;
}



