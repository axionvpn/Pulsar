#pragma once

#include <windows.h>

// 
// Settings of the service
// 

// Internal name of the service
#define SERVICE_NAME             "Pulsar"

// Displayed name of the service
#define SERVICE_DISPLAY_NAME     "Pulsar Service"

//Service Description
#define SERVICE_DESCRIPTION     "Pulsar Service"

// Service start options.
#define SERVICE_START_TYPE       SERVICE_AUTO_START

// List of service dependencies - "dep1\0dep2\0\0"
#define SERVICE_DEPENDENCIES     ""

// The name of the account under which the service should run
#define SERVICE_ACCOUNT          "NT AUTHORITY\\LocalSystem"

// The password to the service account name
#define SERVICE_PASSWORD         NULL



//Functions we export
BOOL RunService(VOID);

void WINAPI ServiceMain(DWORD dwArgc, LPSTR *lpszArgv);

// Start the service.
void Start(DWORD dwArgc, PWSTR *pszArgv);




void BaseSetServiceStatus(DWORD dwCurrentState, 
                                    DWORD dwWin32ExitCode, 
                                    DWORD dwWaitHint);


void OnStart(DWORD dwArgc, LPSTR *lpszArgv);