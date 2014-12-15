#include <stdio.h>

int main(){
    
	char buffer[]="TESTING NOT SHELLCODE\n";
	while(1){
		write(1,buffer,sizeof(buffer));
		sleep(1);
	}
}
