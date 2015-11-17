#include <stdio.h>
#include <stdlib.h>
//#include <string.h>

#include "VarInject.h"

PPROXY_VARS LoadVars(unsigned char *buf,unsigned int size){

	unsigned char *bufPtr = buf;
	
	//Allocate the vars struct
	  PPROXY_VARS vars = (PPROXY_VARS)malloc(sizeof(PROXY_VARS));
	  if(!vars){
		  printf("Failed to allocate PROXY_VARS struct\n");
		  return NULL;
	  }

	//Decode the Buffer
          unsigned int cycles = size / RAND_LEN;
          printf("There are %d decoding cycles\n",cycles);
	  unsigned char *blockPtr = NULL;	
		
	//Second to last block of the buffer
	  blockPtr = buf + size- ( 2 * RAND_LEN);

 	//load up thelast block
          bufPtr = buf + size- (RAND_LEN);

          for(int i = 0; i < cycles; i++){
                  for(int j=0; j < RAND_LEN; j++){
                        bufPtr[j] = bufPtr [j] ^ blockPtr[j];
                  }
                  bufPtr-=RAND_LEN;
                  blockPtr-=RAND_LEN;
          }
	//Reset bufPtr
	bufPtr = buf;

	//Get Randomness
	for(int i = 0; i < RAND_LEN; i++){
		vars->rand[i] = bufPtr[i];
	}
	bufPtr += RAND_LEN;

	//First the port
	memcpy(&vars->port,bufPtr,sizeof(unsigned short));
	bufPtr += (sizeof(unsigned short));

	//Now beacon time
	memcpy(&vars->beacon_time,bufPtr,sizeof(unsigned int));
	bufPtr += (sizeof(unsigned int));

	//Jitter time
	memcpy(&vars->beacon_jitter,bufPtr,sizeof(unsigned int));
	bufPtr += (sizeof(unsigned int));

	//Size of URL
	memcpy(&vars->URLSize,bufPtr,sizeof(unsigned int));
	bufPtr+= (sizeof(unsigned int));

	//Allocate space for URL
	vars->remURL = (char *)malloc(vars->URLSize);
	memset(vars->remURL,0,vars->URLSize);

	//Copy over the URL
	memcpy(vars->remURL,bufPtr,vars->URLSize);
	bufPtr+=vars->URLSize;

	//Size of group
	memcpy(&vars->GroupSize,bufPtr,sizeof(unsigned int));
	bufPtr+= (sizeof(unsigned int));

	//Allocate space for group
	vars->group = (char *)malloc(vars->GroupSize);
	memset(vars->group,0,vars->GroupSize);

	//Copy over the group
	memcpy(vars->group,bufPtr,vars->GroupSize);
	bufPtr+=vars->GroupSize;

	//Proxy Size
	memcpy(&vars->ProxySize,bufPtr,sizeof(unsigned int));
	bufPtr+=sizeof(unsigned int);

        if(vars->ProxySize != 0){
		//allocate space for the proxy file
		vars->remProxy = (unsigned char *)malloc(vars->ProxySize);
		memset(vars->remProxy,0,vars->ProxySize);

		//Copy the proxy
		memcpy(vars->remProxy,bufPtr,vars->ProxySize);
	}


	return vars;
}
