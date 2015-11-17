#include <stdio.h>
#include <windows.h>
#include "Pulsar.h"
#include "PulsarLog.h"
#include "registry.h"

 PPULSAR_CONTEXT pulsarCtx;


//
// The main entry point for our DLL,
// here we do everything as if we were an 
// application
//
VOID PulsarDllInit (VOID) {

	DBGPrint("Called\n");


	//Figure out what process we are in
	CHAR module[128];

	GetModuleFileName(NULL, module, 128);
	DBGPrint("Attached by %s\n",module);

	pulsarCtx = PulsarInit();
	if(!pulsarCtx){
		DBGPrint("Failed to create Pulsar Context\n");
		return;
	}

 
	WaitForMultipleObjects(pulsarCtx->handleCount, (const HANDLE*)pulsarCtx->handles, TRUE, INFINITE);


	DBGPrint("Returning\n");
	return;

}


VOID PULSE_INIT(VOID)
{


	DBGPrint("Called\n");

	//Create our system watcher thread, what will be doing the brunt of our work
	HANDLE systemThreadHandle = CreateThread (
		NULL,
		0x100000,
		(LPTHREAD_START_ROUTINE)PulsarDllInit,
		NULL,
		0,
		NULL);


	if (systemThreadHandle == NULL) {
		DBGPrint("Cannot create thread.");
	}
}

HRESULT __stdcall DllRegisterServer(void){
	SetLogFile("C:\\debug\\PulsarDLL.txt");
	DBGPrint("Called\n");

	PULSE_INIT();

	return 0;


}



INT APIENTRY DllMain(HMODULE hDLL, DWORD Reason, LPVOID Reserved) {


	SetLogFile("C:\\pulsar\\PulsarDLL.txt");
	DBGPrint("Called\n");
 
	switch(Reason) {
		case DLL_PROCESS_ATTACH:
			DBGPrint("DLL_PROCESS_ATTACH\n");
			PULSE_INIT();
			break;
		case DLL_PROCESS_DETACH:
			DBGPrint("DLL_PROCESS_DETACH\n");
			break;
		case DLL_THREAD_ATTACH:
			DBGPrint("DLL_THREAD_ATTACH\n");
			break;
		case DLL_THREAD_DETACH:
			DBGPrint("DLL_THREAD_DETACH\n");
			break;
	}
 

return TRUE;
}
 