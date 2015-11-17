#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
//#include <io.h>

#include "VarDecode.h"
#include "VarUtils.h"




int main(int argc, char **argv){

	for(int i=0; i < argc;i++){
		printf("argv[%d]: %s\n",i,argv[i]);
	}

	if( (argc<2) || (argc > 3)){
		printf("Usage: %s <vars> <proxy-out (optional)> \n",argv[0]);
		return 1;
	}
  
	unsigned char *rawBuf = NULL;
	int bufSize = 0;
	rawBuf = FileToBuf(argv[1],&bufSize);
	if(rawBuf == NULL){
		printf("Failed to read buffer from %s\n",argv[1]);
		return 1;
	}


	PPROXY_VARS vars = LoadVars(rawBuf,bufSize);
	if(vars == NULL){
		printf("Failed to load vars from buffer\n");
		return 2;
	}

	//Otherwise print out what we got
	PrintVars(vars);

	if(argc == 3){
		//dump proxy file
		DumpBuffer(vars->remProxy,vars->ProxySize,argv[2]);
	}

	return 0;

}
