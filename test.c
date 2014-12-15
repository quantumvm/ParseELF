#include <stdio.h>

int main(){
  puts("This sure is a normal file. :)");
	char buffer[]="TESTING NOT SHELLCODE\n";
	while(1){
		write(1,buffer,sizeof(buffer));
		sleep(1);
	}
}
