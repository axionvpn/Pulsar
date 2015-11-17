#ifndef __VARINJECT_H__
#define __VARINJECT_H__


#define RAND_LEN 8				//Use this to XOR the var struct, we can swap in
						//a real crypto later

typedef struct _proxy_vars{
  unsigned char rand[RAND_LEN];		//Random bytes to start struct, used for XOR later
  unsigned int beacon_time;		//Beacon time in minutes
  unsigned int beacon_jitter;		//Beacon jitter in minutes
  unsigned short port;			//local port proxy will listen on
  unsigned int URLSize;			//Size in bytes of the remote URL the proxy will connect to
  char *remURL;				//The remote URL the proxy will connect two
  unsigned int GroupSize;		//Size of the group
  char *group;				//The "group" tag
  unsigned int ProxySize;		//Size of the remote proxy file
  unsigned char *remProxy;		//Pointer to the buffer holding the actual proxy
}PROXY_VARS, *PPROXY_VARS;



PPROXY_VARS InitVars(void);
int VarsAddGroup(PPROXY_VARS vars, char *group);
int VarsAddURL(PPROXY_VARS vars, char *url);
int VarsAddGroup(PPROXY_VARS vars, char *group);
int VarsAddProxy(PPROXY_VARS vars, char * ProxyPath);
unsigned char *SerializeVars(PPROXY_VARS vars,int *size);

#endif
