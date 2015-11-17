#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
//#include <io.h>

#include "VarInject.h"



unsigned char *FileToBuf(char *filename,int *size){
	unsigned char *tmpBuf = NULL;
 
	//Get file size
		struct stat sbuf;

	//Get Size of vars file
	if(stat(filename,&sbuf) == -1){
		printf("Failed to get vars file size\n");
		return NULL;
	}
	*size = sbuf.st_size;
	printf("file is %d bytes in size\n",sbuf.st_size);

	//Allocate memory
	tmpBuf = (unsigned char *)malloc(sbuf.st_size);
	if(tmpBuf == NULL){
		printf("Failed to allocate memory\n");
		return NULL;
	}

	//Open file
	int fd = open(filename,O_RDONLY);
	if(fd == -1){
		printf("Failed to open: %s\n",filename);
		return NULL;
	}

	//Read file
	unsigned int bytesRead = read(fd,tmpBuf,*size);
	printf("Read %d bytes from %s\n",bytesRead,filename);

	return tmpBuf;
}

int DumpBuffer(unsigned char *buf, int bufSize, char *outFile){

	if(bufSize == 0){
	  return 1;
	}

	printf("Writing out %d bytes to %s\n",bufSize,outFile);

	int fd = open(outFile,O_CREAT | O_WRONLY | O_TRUNC,0777);
	if(fd == -1){
		printf("Failed to open the output file\n");
		return 0;
	}

	unsigned int byteswritten = write(fd,buf,bufSize);

	close (fd);

	printf("wrote %d bytes\n",byteswritten);

	return 1;
}



void PrintVars(PPROXY_VARS vars){

	//Random Bytes
  	for(int i=0; i < RAND_LEN;i++){
		printf("vars->rand[%d]: 0x%02x\n",i,vars->rand[i]);
	}

	//Port
	printf("Port: %d\n",vars->port);


	//Beacon time
	printf("Beacon time: %d\n",vars->beacon_time);

	printf("Beacon jitter: %d\n",vars->beacon_jitter);

	printf("vars->URLSize: %d vars->remURL: %s\n",vars->URLSize,vars->remURL);

	printf("vars->GroupSize: %d vars->group: %s\n",vars->GroupSize,vars->group);

	printf("vars->ProxySize: %d\n",vars->ProxySize);


}
