
#include "ServiceBase.h"
#include <assert.h>
#include <strsafe.h>
#include "PulsarLog.h"
#include "Pulsar.h"


// The name of the service
PWSTR g_name;


// The status of the service
SERVICE_STATUS g_status;

// The service status handle
SERVICE_STATUS_HANDLE g_statusHandle;

//Pulsar context
PPULSAR_CONTEXT pulsarCtx;



//
//   FUNCTION ServiceCtrlHandler(DWORD)
//
//   PURPOSE: The function is called by the SCM whenever a control code is 
//   sent to the service. 
//
//   PARAMETERS:
//   * dwCtrlCode - the control code. This parameter can be one of the 
//   following values: 
//
//     SERVICE_CONTROL_CONTINUE
//     SERVICE_CONTROL_INTERROGATE
//     SERVICE_CONTROL_NETBINDADD
//     SERVICE_CONTROL_NETBINDDISABLE
//     SERVICE_CONTROL_NETBINDREMOVE
//     SERVICE_CONTROL_PARAMCHANGE
//     SERVICE_CONTROL_PAUSE
//     SERVICE_CONTROL_SHUTDOWN
//     SERVICE_CONTROL_STOP
//
//   This parameter can also be a user-defined control code ranges from 128 
//   to 255.
//
void WINAPI ServiceCtrlHandler(DWORD dwCtrl)
{

	DBGPrint("Called\n");

    switch (dwCtrl)
    {
    case SERVICE_CONTROL_STOP:
		DBGPrint("Stop\n");
		break;
    case SERVICE_CONTROL_PAUSE:
		DBGPrint("Pause\n");	
		break;
    case SERVICE_CONTROL_CONTINUE:
		DBGPrint("Continue\n");
		break;
    case SERVICE_CONTROL_SHUTDOWN:
		DBGPrint("Shutdown\n");
		break;
    case SERVICE_CONTROL_INTERROGATE:
		DBGPrint("Interrogate\n");
		break;
    default: break;
    }

	DBGPrint("Returning");

}


//
//   FUNCTION: Start(DWORD, PWSTR *)
//
//   PURPOSE: The function starts the service. It calls the OnStart virtual 
//   function in which you can specify the actions to take when the service 
//   starts. If an error occurs during the startup, the error will be logged 
//   in the Application event log, and the service will be stopped.
//
//   PARAMETERS:
//   * dwArgc   - number of command line arguments
//   * lpszArgv - array of command line arguments
//
void Start(DWORD dwArgc, PSTR *pszArgv)
{
	DBGPrint("Called\n");
    try
    {
        // Tell SCM that the service is starting.
        BaseSetServiceStatus(SERVICE_START_PENDING,NO_ERROR,0);

        // Perform service-specific initialization.
        OnStart(dwArgc, pszArgv);

        // Tell SCM that the service is started.
        BaseSetServiceStatus(SERVICE_RUNNING,NO_ERROR,0);
    }
    catch (DWORD dwError)
    {
        // Log the error.
        DBGPrint("Service Start");

        // Set the service status to be stopped.
        SetServiceStatus((SERVICE_STATUS_HANDLE)SERVICE_STOPPED, (LPSERVICE_STATUS) dwError);
    }
    catch (...)
    {
        // Log the error.
        DBGPrint("Service failed to start.");

        // Set the service status to be stopped.
        BaseSetServiceStatus(SERVICE_STOPPED,NO_ERROR,0);
    }

	DBGPrint("Returning\n");
}


BOOL RunService(VOID){

	DBGPrint("Called\n");
	
	BOOL bRetVal = FALSE;
	SERVICE_TABLE_ENTRY ServiceTable[] = 
    {
        { SERVICE_NAME, ServiceMain },
        { NULL, NULL }
    };


    // Connects the main thread of a service process to the service control 
    // manager, which causes the thread to be the service control dispatcher 
    // thread for the calling process. This call returns when the service has 
    // stopped. The process should simply terminate when the call returns.
    if (StartServiceCtrlDispatcher (ServiceTable) == FALSE)
    {
		DBGPrint("Service failed to run w/err 0x%08x\n",GetLastError());
        goto exit;
    }

	bRetVal= TRUE;

exit:

	DBGPrint("Returning\n");
	return bRetVal;
}




//
//   FUNCTION: ServiceMain(DWORD, PWSTR *)
//
//   PURPOSE: Entry point for the service. It registers the handler function 
//   for the service and starts the service.
//
//   PARAMETERS:
//   * dwArgc   - number of command line arguments
//   * lpszArgv - array of command line arguments
//
void WINAPI ServiceMain(DWORD dwArgc, LPSTR *pszArgv)
{
	DBGPrint("Called\n");

    // Register the handler function for the service
    g_statusHandle = RegisterServiceCtrlHandler(
        SERVICE_NAME, ServiceCtrlHandler);
    if (g_statusHandle == NULL)
    {
       goto exit;
    }


	//Initialize the status object for accpeting events

    // The service runs in its own process.
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;

    // The service is starting.
    g_status.dwCurrentState = SERVICE_START_PENDING;

    // The accepted commands of the service.
    DWORD dwControlsAccepted = 0;
        dwControlsAccepted |= SERVICE_ACCEPT_STOP;
        dwControlsAccepted |= SERVICE_ACCEPT_SHUTDOWN;
        dwControlsAccepted |= SERVICE_ACCEPT_PAUSE_CONTINUE;

    g_status.dwControlsAccepted = dwControlsAccepted;
    g_status.dwWin32ExitCode = NO_ERROR;
    g_status.dwServiceSpecificExitCode = 0;
    g_status.dwCheckPoint = 0;
    g_status.dwWaitHint = 0;



    // Start the service.
      Start(dwArgc, pszArgv);

	
	//Wait for the Pulsar Threads
	  DBGPrint("Waiting for handles\n");
	  WaitForMultipleObjects(pulsarCtx->handleCount, (const HANDLE*)pulsarCtx->handles, TRUE, INFINITE);	
	  DBGPrint("Done waiting for handles\n");


exit:

	  DBGPrint("Returning\n");
}

#pragma region Helper Functions

//
//   FUNCTION: BaseSetServiceStatus(DWORD, DWORD, DWORD)
//
//   PURPOSE: The function sets the service status and reports the status to 
//   the SCM.
//
//   PARAMETERS:
//   * dwCurrentState - the state of the service
//   * dwWin32ExitCode - error code to report
//   * dwWaitHint - estimated time for pending operation, in milliseconds
//
void BaseSetServiceStatus(DWORD dwCurrentState, 
                                    DWORD dwWin32ExitCode, 
                                    DWORD dwWaitHint)
{
    static DWORD dwCheckPoint = 1;

	DBGPrint("Called with %d\n",dwCurrentState);
    // Fill in the SERVICE_STATUS structure of the service.

    g_status.dwCurrentState = dwCurrentState;
    g_status.dwWin32ExitCode = dwWin32ExitCode;
    g_status.dwWaitHint = dwWaitHint;

    g_status.dwCheckPoint = 
        ((dwCurrentState == SERVICE_RUNNING) ||
        (dwCurrentState == SERVICE_STOPPED)) ? 
        0 : dwCheckPoint++;

    // Report the status of the service to the SCM.
	if( SetServiceStatus(g_statusHandle, &g_status) == FALSE){
		//LAST_ERR();
	}

     DBGPrint("Returning\n");
}



#pragma endregion



//
//   FUNCTION: OnStart(DWORD, LPWSTR *)
//
//   PURPOSE: The function is executed when a Start command is sent to the 
//   service by the SCM or when the operating system starts (for a service 
//   that starts automatically). It specifies actions to take when the 
//   service starts. In this code sample, OnStart logs a service-start 
//   message to the Application log, and queues the main service function for 
//   execution in a thread pool worker thread.
//
//   PARAMETERS:
//   * dwArgc   - number of command line arguments
//   * lpszArgv - array of command line arguments
//
//   NOTE: A service application is designed to be long running. Therefore, 
//   it usually polls or monitors something in the system. The monitoring is 
//   set up in the OnStart method. However, OnStart does not actually do the 
//   monitoring. The OnStart method must return to the operating system after 
//   the service's operation has begun. It must not loop forever or block. To 
//   set up a simple monitoring mechanism, one general solution is to create 
//   a timer in OnStart. The timer would then raise events in your code 
//   periodically, at which time your service could do its monitoring. The 
//   other solution is to spawn a new thread to perform the main service 
//   functions, which is demonstrated in this code sample.
//
void OnStart(DWORD dwArgc, LPSTR *lpszArgv)
{

	DBGPrint("Called\n");
    DBGPrint("Pulsar Service in OnStart\n");


	//This is where Pulsar starts
	pulsarCtx = PulsarInit();
	if(!pulsarCtx){
		DBGPrint("Failed to create Pulsar Context\n");
	}

	DBGPrint("Returning\n");

}




//
//   FUNCTION: OnStop(void)
//
//   PURPOSE: The function is executed when a Stop command is sent to the 
//   service by SCM. It specifies actions to take when a service stops 
//   running. In this code sample, OnStop logs a service-stop message to the 
//   Application log, and waits for the finish of the main service function.
//
//   COMMENTS:
//   Be sure to periodically call ReportServiceStatus() with 
//   SERVICE_STOP_PENDING if the procedure is going to take long time. 
//
void OnStop()
{
	DBGPrint("Called\n");

    // Log a service stop message to the Application log.
    DBGPrint("Pulsar Service in OnStop");


	PulsarExit();

	BaseSetServiceStatus(SERVICE_STOPPED, NO_ERROR,0);

    // Indicate that the service is stopping and wait for the finish of the 
    // main service function (ServiceWorkerThread).
  //  m_fStopping = TRUE;
    //if (WaitForSingleObject(m_hStoppedEvent, INFINITE) != WAIT_OBJECT_0)
    //{
      //  throw GetLastError();
   // }
	DBGPrint("Returning\n");
}