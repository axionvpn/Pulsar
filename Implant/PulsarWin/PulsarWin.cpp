#include <windows.h>
#include "Pulsar.h"
#include "PulsarLog.h"



PPULSAR_CONTEXT pulsarCtx;

//
// Default exception handler 
LONG WINAPI NullExceptionHandler(LPEXCEPTION_POINTERS ExPtr){

	return EXCEPTION_EXECUTE_HANDLER;
}

//
// Main entry point for Windows programs
//

int CALLBACK WinMain(
	_In_  HINSTANCE hInstance,
	_In_  HINSTANCE hPrevInstance,
	_In_  LPSTR lpCmdLine,
	_In_  int nCmdShow
	){


	SetLogFile("PulsarCmdLine.txt");

	DBGPrint("Pulsar Command Line (Win) Started\n");

	SetUnhandledExceptionFilter(NullExceptionHandler);


	pulsarCtx = PulsarInit();
	if (!pulsarCtx){
		DBGPrint("Failed to create Pulsar Context");
		return 1;
	}


	WaitForMultipleObjects(pulsarCtx->handleCount, (const HANDLE*)pulsarCtx->handles, TRUE, INFINITE);


	DBGPrint("Pulsar Command Line (Win) Done\n");

	return 0;
}
