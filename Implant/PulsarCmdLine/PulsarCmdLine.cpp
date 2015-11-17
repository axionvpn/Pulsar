#include "PulsarCmdLine.h"
#include "Pulsar.h"
#include "PulsarLog.h"


PPULSAR_CONTEXT pulsarCtx;


BOOL CtrlHandler(DWORD fdwCtrlType) 
{ 

	DBGPrint("Called\n");

	switch(fdwCtrlType) 
	{ 
    case CTRL_C_EVENT: 
		PulsarExit();
		return TRUE;
    case CTRL_CLOSE_EVENT: 
		PulsarExit();
		return TRUE; 
    case CTRL_BREAK_EVENT: 
		return FALSE; 
    case CTRL_LOGOFF_EVENT: 
		return FALSE; 
    case CTRL_SHUTDOWN_EVENT: 
		return FALSE; 
    default: 
		return FALSE; 
	} 

}




int wmain(int argc, CHAR* argv[])
{


	if(argc != 1){
		printf("Usage:\n \t %S \n",argv[0]);
		exit(0);
	}

	SetLogFile("PulsarCmdLine.txt");

	SetConsoleCtrlHandler((PHANDLER_ROUTINE)CtrlHandler, TRUE);


	printf("Pulsar Command Line Started\n");


	pulsarCtx = PulsarInit();
	if(!pulsarCtx){
		DBGPrint("Failed to create Pulsar Context");
		goto exit;
	}

 
	WaitForMultipleObjects(pulsarCtx->handleCount, (const HANDLE*)pulsarCtx->handles, TRUE, INFINITE);	

exit:

	printf("Pulsar Command Line Done\n");

	return 0;
}