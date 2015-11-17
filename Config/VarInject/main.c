#include <stdio.h>
#include <unistd.h>
#include <getopt.h>

#include "VarInject.h"
#include "VarUtils.h"


void usage(char *prog){

	printf("Usage: %s -b <beacon time (mins)> -j <jitter (mins)> -p <Local Port> -r <Remote URL> -g <Group Name>  -m <Proxy Module> -o <output file>\n",prog);
	exit(1);

}



int main (int argc, char **argv){

  unsigned int beacon_time = 30; //30 mins
  unsigned int jitter_time = 5;  //5 mins
  unsigned short local_port = 8443;
  unsigned char *remoteURL = NULL;
  unsigned char *outFile = NULL;
  unsigned char *proxyFile = NULL;
  unsigned char *groupName = "default";


  //Parse out the args

    int ch;

     while ((ch = getopt(argc, argv, "b:j:p:r:g:o:m:")) != -1) {
             switch (ch) {
             case 'b':
		beacon_time = strtol(optarg,NULL,10);
		break;	
	     case 'j':
		jitter_time = strtol(optarg,NULL,10);
		break;	
	     case 'p':
		local_port = strtol(optarg,NULL,10);
		break;	
	     case 'r':
		remoteURL = optarg;
		break;	
	     case 'g':
		groupName = optarg;
		break;	
	     case 'm':
		proxyFile = optarg;
		break;	
	     case 'o':
		outFile = optarg;
		break;	
             case '?':
             default:
                     usage(argv[0]);
             }
     }
     argc -= optind;
     argv += optind;

     printf("Beacon time: %d\n",beacon_time);
     printf("Jitter: %d\n",jitter_time);
     printf("Port: %d\n",local_port);
     printf("Remote URL: %s\n",remoteURL);
     printf("Group Name: %s\n",groupName);
     printf("Proxy file: %s\n",proxyFile);
     printf("Outfile: %s\n",outFile);


	PPROXY_VARS vars;

	//Allocate and initialize the variable structure
	vars = InitVars();
	if(!vars){
		printf("Invalid Variable structure\n");
		return 2;
	}

	//Add the beacon and jitter
        vars->beacon_time = beacon_time;
        vars->beacon_jitter = jitter_time;
	vars->port = local_port;



	//Add the URL
	if(VarsAddURL(vars,remoteURL) == 0){
		printf("Failed to add URL\n");
		return 4;
	}

	//Add the Group
	if(VarsAddGroup(vars,groupName) == 0){
		printf("Failed to add the group\n");
		return 5;
	}

	//Add the Proxy if there is one
	if(VarsAddProxy(vars,proxyFile) == 0){
		printf("Failed to add Proxy\n");
	}

	PrintVars(vars);

	//Serialize the vars
	  unsigned char *buf;
	  int bufSize = 0;

	  buf = SerializeVars(vars,&bufSize);
	  if(buf == NULL){
		  printf("Failed to Serialize Var struct\n");
		  return 6;
	  }


	//Write them out
	  if ( DumpBuffer(buf,bufSize,outFile) == 0){
		  printf("Failed to write out vars\n");
		  return 7;
	  }


	return 0;
}
