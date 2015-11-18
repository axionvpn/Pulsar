
#include <stdio.h>
#include <windows.h>
#include    <tlhelp32.h>
#include <Shlwapi.h>
#include "ServiceInstaller.h"
#include "ServiceBase.h"
#include "PulsarLog.h"


//
//Find the name of our parent process and determine
//if its the Service Control Manager, in which case we 
//return TRUE, or FALSE otherwise
//
BOOL IsParentSCM(VOID)
{
	HANDLE hSnapshot;
	PROCESSENTRY32 pe32;
	DWORD ppid = 0, pid = GetCurrentProcessId();
	BOOL bRetVal = FALSE;

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnapshot == INVALID_HANDLE_VALUE){
		DBGPrint("Failed to get process snapshot\n");
		return FALSE;
	};


	//First find the parent

	ZeroMemory(&pe32, sizeof(pe32));
	pe32.dwSize = sizeof(pe32);
	if (!Process32First(hSnapshot, &pe32)){
		DBGPrint("Invalid process item\n");
		CloseHandle(hSnapshot);
		return FALSE;
	}

	do{
		if (pe32.th32ProcessID == pid){
			ppid = pe32.th32ParentProcessID;
			break;
		}
	} while (Process32Next(hSnapshot, &pe32));


	//Now find the parent's name
	ZeroMemory(&pe32, sizeof(pe32));
	pe32.dwSize = sizeof(pe32);
	if (!Process32First(hSnapshot, &pe32)){
		DBGPrint("Invalid process item\n");
		CloseHandle(hSnapshot);
		return 0;
	}

	do{
		if (pe32.th32ProcessID == ppid){
			DBGPrint("Parent name is: %s\n", pe32.szExeFile);
			if (strcmp(pe32.szExeFile, "services.exe") == 0){
				DBGPrint("Parent is services.exe\n");
				CloseHandle(hSnapshot);
				return TRUE;
			}
			break;
		}
	} while (Process32Next(hSnapshot, &pe32));


	if (hSnapshot != INVALID_HANDLE_VALUE){
		CloseHandle(hSnapshot);
	}


	return FALSE;
}




	int CALLBACK WinMain(
		_In_  HINSTANCE hInstance,
		_In_  HINSTANCE hPrevInstance,
		_In_  LPSTR lpCmdLine,
		_In_  int nCmdShow
		){


    SetLogFile("C:\\PulsarService.txt");
    DBGPrint("Called\n");


	if (IsParentSCM()){
		DBGPrint("Parent is SCM\n");
		if (RunService() == FALSE){
			DBGPrint("Service failed to run w/err 0x%08x\n", GetLastError());
			return 1;
		}

	}
	else{
		DBGPrint("Parent is NOT SCM\n");
	}


	LPWSTR *argvW;
	LPTSTR *argv;
	LPTSTR tmpLine = NULL;

	int argc;

	tmpLine = GetCommandLine();

	DBGPrint("tmpLine: %s\n", tmpLine);

	//Look for the "remove string in the command line
	if (StrStrI(tmpLine,"remove")){
		DBGPrint("Removing service\n");
		BOOL removed = UninstallService(SERVICE_NAME);
		// Print indication of service removal success or failure
		if (removed)
			printf("1");
		else
			printf("0");

		return 0;
	}

	//Since we're not removing, we try to install, if install fails with a
	//we just run
	DBGPrint("Installing Service\n");
	BOOL installed = InstallService(
		SERVICE_NAME,               // Name of service
		SERVICE_DISPLAY_NAME,       // Name to display
		SERVICE_START_TYPE,         // Service start type
		SERVICE_DEPENDENCIES,       // Dependencies
		SERVICE_ACCOUNT,            // Service running account
		SERVICE_PASSWORD            // Password of the account
		);

	// Print indication of service installation success or failure
	if (installed){
		DBGPrint("Install succeeded\n");
		//Now run the service
		StartPulsarSvc(SERVICE_NAME);

	}
	else{
		DBGPrint("Install failed, just running\n");
		OnStart(0, NULL);
	}
 

exit:

    return 0;
}