
#include    <windows.h>

#include <stdio.h>
#include <Shlwapi.h>

#include "ServiceInstaller.h"
#include "PulsarLog.h"

BOOL StartPulsarSvc(PSTR pszServiceName)
{
	BOOL bRet = FALSE;
	SC_HANDLE schSCManager = NULL;
	SC_HANDLE schService = NULL;
	SERVICE_STATUS ssSvcStatus = {};
	DBGPrint("Called\n");

	// Open the local default service control manager database
	schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (schSCManager == NULL)
	{
		DBGPrint("OpenSCManager failed w/err 0x%08lx\n", GetLastError());
		goto Cleanup;
	}

	// Open the service with delete, stop, and query status permissions
	schService = OpenService(schSCManager, pszServiceName, SERVICE_ALL_ACCESS);
	if (schService == NULL)
	{
		DBGPrint("OpenService failed w/err 0x%08lx\n", GetLastError());
		goto Cleanup;
	}

	// Try to start the service
	if (StartService(schService, 0, NULL))
	{
		DBGPrint("Starting %s\n", pszServiceName);
		Sleep(1000);

		while (QueryServiceStatus(schService, &ssSvcStatus))
		{
			DBGPrint("ssSvcStatus.dwCurrentSate: %d", ssSvcStatus.dwCurrentState);
			if (ssSvcStatus.dwCurrentState == SERVICE_START_PENDING)
			{
				DBGPrint(".");
				Sleep(1000);
			}
			else break;
		}

		if (ssSvcStatus.dwCurrentState == SERVICE_START)
		{
			DBGPrint("\n%s is started.\n", pszServiceName);
		}
		else
		{
			DBGPrint("\n%s failed to start.\n", pszServiceName);
		}
	}

	bRet = TRUE;

Cleanup:
	// Centralized cleanup for all allocated resources.
	if (schSCManager)
	{
		CloseServiceHandle(schSCManager);
		schSCManager = NULL;
	}
	if (schService)
	{
		CloseServiceHandle(schService);
		schService = NULL;
	}

	DBGPrint("Returning\n");
	return bRet;
}




//
//   FUNCTION: InstallService
//
//   PURPOSE: Install the current application as a service to the local 
//   service control manager database.
//
//   PARAMETERS:
//   * pszServiceName - the name of the service to be installed
//   * pszDisplayName - the display name of the service
//   * dwStartType - the service start option. This parameter can be one of 
//     the following values: SERVICE_AUTO_START, SERVICE_BOOT_START, 
//     SERVICE_DEMAND_START, SERVICE_DISABLED, SERVICE_SYSTEM_START.
//   * pszDependencies - a pointer to a double null-terminated array of null-
//     separated names of services or load ordering groups that the system 
//     must start before this service.
//   * pszAccount - the name of the account under which the service runs.
//   * pszPassword - the password to the account name.
//
//  RETURN VALUE:
//    TRUE if the service is successfully created, otherwise FALSE
//
//   NOTE: If the function fails to install the service, it prints the error 
//   in the standard output stream for users to diagnose the problem.
//
BOOL InstallService(PSTR pszServiceName, 
                    PSTR pszDisplayName, 
                    DWORD dwStartType,
                    PSTR pszDependencies, 
                    PSTR pszAccount, 
                    PSTR pszPassword)
{
    BOOL bRet = TRUE;
    char szPath[MAX_PATH];
	char outPath[MAX_PATH];
    SC_HANDLE schSCManager = NULL;
    SC_HANDLE schService = NULL;

	DBGPrint("Called\n");


	// Open the local default service control manager database, we do this first to see
	// if we're going to be even able to install
	schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT |
		SC_MANAGER_CREATE_SERVICE);
	if (schSCManager == NULL)
	{
		DBGPrint("OpenSCManager failed w/err 0x%08lx\n", GetLastError());
		goto Cleanup;
	}


    if (GetModuleFileName(NULL, szPath, ARRAYSIZE(szPath)) == 0)
    {
        DBGPrint("GetModuleFileName failed w/err 0x%08lx\n", GetLastError());
        goto Cleanup;
    }
	DBGPrint("File is: %s\n", szPath);

	//Copy the file to win32 or syswow64, depending on bitness
		//Get windows system directory
		 GetSystemDirectory(outPath, MAX_PATH);
	
		 PTSTR filename = PathFindFileName(szPath);
		 //Set up the path
		 strcat(outPath, "\\");
		 strcat(outPath, filename);

		 DBGPrint("Outfile is: %s\n",outPath);

		 //Copy the file
		 if (CopyFile(szPath, outPath, TRUE) == FALSE){
			 DWORD dwError = GetLastError();
			 DBGPrint("Copyfile failed w/err 0x%08lx\n", dwError);
			 if (dwError != ERROR_FILE_EXISTS){
				 goto Cleanup;
			 }
			 DBGPrint("File exists, lets install anyway\n");
		 }


    // Install the service into SCM by calling CreateService
    schService = CreateService(
        schSCManager,                   // SCManager database
        pszServiceName,                 // Name of service
        pszDisplayName,                 // Name to display
        SERVICE_QUERY_STATUS,           // Desired access
        SERVICE_WIN32_OWN_PROCESS,      // Service type
        dwStartType,                    // Service start type
        SERVICE_ERROR_NORMAL,           // Error control type
        szPath,                         // Service's binary
        NULL,                           // No load ordering group
        NULL,                           // No tag identifier
        pszDependencies,                // Dependencies
       // pszAccount,                     // Service running account
       NULL,       
       pszPassword                     // Password of the account
        );
    if (schService == NULL)
    {
        DBGPrint("CreateService failed w/err 0x%08lx\n", GetLastError());
        bRet = FALSE;
        goto Cleanup;
    }

    DBGPrint("%s is installed.\n", pszServiceName);



Cleanup:
    // Centralized cleanup for all allocated resources.
    if (schSCManager)
    {
        CloseServiceHandle(schSCManager);
        schSCManager = NULL;
    }
    if (schService)
    {
        CloseServiceHandle(schService);
        schService = NULL;
    }

	DBGPrint("Returning\n");

    return bRet;
}


//
//   FUNCTION: UninstallService
//
//   PURPOSE: Stop and remove the service from the local service control 
//   manager database.
//
//   PARAMETERS: 
//   * pszServiceName - the name of the service to be removed.
//
//  RETURN VALUE:
//    TRUE if the service is successfully removed, otherwise FALSE
//
//   NOTE: If the function fails to uninstall the service, it prints the 
//   error in the standard output stream for users to diagnose the problem.
//
BOOL UninstallService(PSTR pszServiceName)
{
    BOOL bRet = FALSE;
    SC_HANDLE schSCManager = NULL;
    SC_HANDLE schService = NULL;
    SERVICE_STATUS ssSvcStatus = {};

    // Open the local default service control manager database
    schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (schSCManager == NULL)
    {
        wprintf(L"OpenSCManager failed w/err 0x%08lx\n", GetLastError());
        goto Cleanup;
    }

    // Open the service with delete, stop, and query status permissions
    schService = OpenService(schSCManager, pszServiceName, SERVICE_STOP | 
        SERVICE_QUERY_STATUS | DELETE);
    if (schService == NULL)
    {
        wprintf(L"OpenService failed w/err 0x%08lx\n", GetLastError());
        goto Cleanup;
    }

    // Try to stop the service
    if (ControlService(schService, SERVICE_CONTROL_STOP, &ssSvcStatus))
    {
        wprintf(L"Stopping %s.", pszServiceName);
        Sleep(1000);

        while (QueryServiceStatus(schService, &ssSvcStatus))
        {
            if (ssSvcStatus.dwCurrentState == SERVICE_STOP_PENDING)
            {
                wprintf(L".");
                Sleep(1000);
            }
            else break;
        }

        if (ssSvcStatus.dwCurrentState == SERVICE_STOPPED)
        {
            wprintf(L"\n%s is stopped.\n", pszServiceName);
        }
        else
        {
            wprintf(L"\n%s failed to stop.\n", pszServiceName);
        }
    }

    // Now remove the service by calling DeleteService.
    if (!DeleteService(schService))
    {
        wprintf(L"DeleteService failed w/err 0x%08lx\n", GetLastError());
        goto Cleanup;
    }

    bRet = TRUE;
    DBGPrint("%s is removed\n", pszServiceName);

Cleanup:
    // Centralized cleanup for all allocated resources.
    if (schSCManager)
    {
        CloseServiceHandle(schSCManager);
        schSCManager = NULL;
    }
    if (schService)
    {
        CloseServiceHandle(schService);
        schService = NULL;
    }

    return bRet;
}

