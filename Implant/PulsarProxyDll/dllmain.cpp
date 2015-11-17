//===============================================================================================//
// This is a stub for the actuall functionality of the DLL.
//===============================================================================================//

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers

// Windows Header Files:
#include <windows.h>
#include <Winsock2.h>


#include "Pulsar.h"
#include "PulsarProxyLib.h"
#include "PulsarLog.h"
#include "ReflectiveDllInjection.h"





VOID PulsarProxyDll_INIT(PPROXY_CONTEXT context)
{


	//Create our system watcher thread, what will be doing the brunt of our work
	HANDLE systemThreadHandle = InstallPulsarProxy(context->localPort, context->remoteHost, context->remoteRes, context->remotePort);


	if (systemThreadHandle == NULL) {
		DBGPrint("Cannot create thread.");
	}


	WaitForSingleObject(systemThreadHandle,INFINITE);
}



// Note: REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR and REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN are
// defined in the project properties (Properties->C++->Preprocessor) so as we can specify our own 
// DllMain and use the LoadRemoteLibraryR() API to inject this DLL.

// You can use this value as a pseudo hinstDLL value (defined and set via ReflectiveLoader.c)
 HINSTANCE hAppInstance;
//===============================================================================================//
BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved )
{
	switch( dwReason ) 
    { 
		case DLL_QUERY_HMODULE:
			if( lpReserved != NULL )
				*(HMODULE *)lpReserved = hAppInstance;
			break;
		case DLL_PROCESS_ATTACH:
			hAppInstance = hinstDLL;
			SetLogFile("PulsarProxyDll.txt");
			DBGPrint("Loaded\n");
			PulsarProxyDll_INIT((PPROXY_CONTEXT) lpReserved);
			break;
		case DLL_PROCESS_DETACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
            break;
    }
	return TRUE;
}
