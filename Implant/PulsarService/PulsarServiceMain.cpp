#pragma region Includes
#include <stdio.h>
#include <windows.h>
#include "ServiceInstaller.h"
#include "ServiceBase.h"
#include "PulsarLog.h"
#pragma endregion




//
//  FUNCTION: wmain(int, wchar_t *[])
//
//  PURPOSE: entrypoint for the application.
// 
//  PARAMETERS:
//    argc - number of command line arguments
//    argv - array of command line arguments
//
//  RETURN VALUE:
//    none
//
//  COMMENTS:
//    wmain() either performs the command line task, or run the service.
//
int main(int argc, char *argv[])
{

    SetLogFile("C:\\PulsarService.txt");
    DBGPrint("Called\n");

    if ((argc > 1) && ((*argv[1] == '-' || (*argv[1] == '/'))))
    {
        if (_stricmp("install", argv[1] + 1) == 0)
        {
            DBGPrint("Installing Service\n");
            // Install the service when the command is 
            // "-install" or "/install".
            BOOL installed = InstallService(
                SERVICE_NAME,               // Name of service
                SERVICE_DISPLAY_NAME,       // Name to display
                SERVICE_START_TYPE,         // Service start type
                SERVICE_DEPENDENCIES,       // Dependencies
                SERVICE_ACCOUNT,            // Service running account
                SERVICE_PASSWORD            // Password of the account
                );

            // Print indication of service installation success or failure
            if (installed)
                printf("1");
            else
                printf("0");
        }
        else if (_stricmp("remove", argv[1] + 1) == 0)
        {
            // Uninstall the service when the command is 
            // "-remove" or "/remove".
            DBGPrint("Removing service\n");
            BOOL removed = UninstallService(SERVICE_NAME);
            // Print indication of service removal success or failure
            if (removed)
                printf("1");
            else
                printf("0");

            goto exit;
        } else {
            goto exit;
        }
    }

    if (RunService() == FALSE)
    {
        DBGPrint("Service failed to run w/err 0x%08x\n", GetLastError());
    }
 


exit:

    return 0;
}