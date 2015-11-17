#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#include <iostream>
#include <map>
#include <vector>
// Windows Header Files:
#include <windows.h>
#include <Winsock2.h>
#include <winhttp.h>
#include <Strsafe.h>


#include "PulsarInternal.h"
#include "PulsarLog.h"
#include "PulsarProxyLib.h"
#include "ProxyCreds.h"
#include "creds.h"


struct METERPROXY_CONFIG g_meterproxy_config;

DWORD ChooseAuthScheme(DWORD dwSupportedSchemes) {
	//  It is the server's responsibility only to accept 
	//  authentication schemes that provide a sufficient
	//  level of security to protect the servers resources.
	//
	//  The client is also obligated only to use an authentication
	//  scheme that adequately protects its username and password.

	DBGPrint("Called\n");
	DBGPrint("Supported Schemes: 0x%x\n",dwSupportedSchemes);

	if ( dwSupportedSchemes & WINHTTP_AUTH_SCHEME_BASIC ) {
		DBGPrint("AUTH_SCHEME_BASIC\n");
		return WINHTTP_AUTH_SCHEME_BASIC;
	} else if ( dwSupportedSchemes & WINHTTP_AUTH_SCHEME_NEGOTIATE ) {
		DBGPrint("AUTH_SCHEME_NEGOTIATE\n");
		return WINHTTP_AUTH_SCHEME_NEGOTIATE;
	} else if ( dwSupportedSchemes & WINHTTP_AUTH_SCHEME_NTLM ) {
		DBGPrint("AUTH_SCHEME_NTLM\n");	
		return WINHTTP_AUTH_SCHEME_NTLM;
	} else if ( dwSupportedSchemes & WINHTTP_AUTH_SCHEME_PASSPORT ) {
		DBGPrint("AUTH_SCHEME_PASSPORT\n");
		return WINHTTP_AUTH_SCHEME_PASSPORT;
	} else if ( dwSupportedSchemes & WINHTTP_AUTH_SCHEME_DIGEST ) {
		DBGPrint("AUTH_SCHEME_DIGEST\n");
		return WINHTTP_AUTH_SCHEME_DIGEST;
	} else {
		DBGPrint("AUTH_SCHEME_UNKNOWN\n");
	}

	DBGPrint("Returning\n\n");
	return 0;
}

//
//Load the proxy for a handle
//
BOOL LoadTargetForHandle(HINTERNET hRequest, LPSTR *lpSite) {
	BOOL bRetVal = FALSE;

  	DBGPrint("Called\n");
	
	// Make sure we loaded a good proxy

	WINHTTP_PROXY_INFO  lpProxy;
	DWORD proxySize = sizeof(WINHTTP_PROXY_INFO);

	// Use WinHttpQueryOption to retrieve internet options.
	if (WinHttpQueryOption( hRequest, 
							WINHTTP_OPTION_PROXY, 
							&lpProxy, &proxySize)) {
		DBGPrint("Proxy Info: %s\n",lpProxy.lpszProxy);
			
		if(!lpProxy.lpszProxy){
			DBGPrint("No Valid PRoxy\n");
			goto exit;
		}else{
			const CHAR *lpConvertedSite;
			int nChars = WideCharToMultiByte(CP_UTF8, 0, lpProxy.lpszProxy, -1, NULL, 0, NULL, NULL);
			lpConvertedSite = new CHAR[nChars];
			WideCharToMultiByte(CP_UTF8, 0, lpProxy.lpszProxy, -1, (LPSTR)lpConvertedSite, nChars, NULL, NULL);

			*lpSite = (LPSTR)lpConvertedSite;
			bRetVal = TRUE;
		}
	} else {
		DBGPrint("WinhttpQueryOption Failed: %d\n", GetLastError());
	}  

exit:

	if(lpProxy.lpszProxyBypass){
		GlobalFree(lpProxy.lpszProxyBypass);
	}

	DBGPrint("Returning\n\n");

	return bRetVal;
}

//
// Apply the redirect flags to insure that we handle http/https
// redirects correctly
//
VOID SetHandleGlobalCredFlags(HINTERNET hHandle){
	BOOL bSetValue;

  	DBGPrint("Called\n");

	bSetValue = TRUE;

	//Set some session options, such as allow http/https redirects
	if (!WinHttpSetOption(hHandle,WINHTTP_OPTION_USE_GLOBAL_SERVER_CREDENTIALS, &bSetValue,sizeof(bSetValue))) {
		DBGPrint("Setting options failed, curious but continuing: %d\n", GetLastError());
	} else {
		DBGPrint("Settings options success\n");
	}
	DBGPrint("Returning\n\n");
}

//
// Set flags to make sure we handle all kinds of cert issues
//
VOID SetHandleProtFlags(HINTERNET hHandle) {
	DWORD dwSetValue;

	//DBGPrint("Called\n");

	dwSetValue = WINHTTP_FLAG_SECURE_PROTOCOL_ALL;

	//Make sure we handle secure ALL secure protocols
	if (!WinHttpSetOption(hHandle, WINHTTP_OPTION_SECURE_PROTOCOLS, &dwSetValue, sizeof(dwSetValue))) {
		DBGPrint("Setting  secure prot options failed, curious but continuing: %d\n", GetLastError());
	}
	else {
		//DBGPrint("Settings Secure prot options success\n");
	}




	//DBGPrint("Returning\n\n");
}

//
// Set flags to make sure we handle all kinds of cert issues
//
VOID SetHandleCERTFlags(HINTERNET hHandle) {
	DWORD dwSetValue;

  	//DBGPrint("Called\n");



	//Now all the cert issues
	
	dwSetValue =	SECURITY_FLAG_IGNORE_CERT_CN_INVALID	|
					SECURITY_FLAG_IGNORE_CERT_DATE_INVALID	|
					SECURITY_FLAG_IGNORE_UNKNOWN_CA			|
					SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;

	//Set some session options, such as allow http/https redirects
	if (!WinHttpSetOption(hHandle, WINHTTP_OPTION_SECURITY_FLAGS, &dwSetValue, sizeof(dwSetValue))) {
		DBGPrint("Setting securty flags  options failed, curious but continuing: %d\n", GetLastError());
	} else {
		//DBGPrint("Settings security  options success\n");
	}

	//DBGPrint("Returning\n\n");
}


//
// Apply the redirect flags to insure that we handle http/https
// redirects correctly
//
VOID SetHandleRedirFlags(HINTERNET hHandle) {
	DWORD dwSetValue;
  	//DBGPrint("Called\n");

	dwSetValue = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS;

	//Set some session options, such as allow http/https redirects
	if (!WinHttpSetOption(hHandle,WINHTTP_OPTION_REDIRECT_POLICY,
						 //WINHTTP_OPTION_SECURE_PROTOCOLS |
						 //SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
						 //SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
						 // SECURITY_FLAG_IGNORE_UNKNOWN_CA |
						 // SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE
						 &dwSetValue,sizeof(dwSetValue))) {
		DBGPrint("Setting options failed, curious but continuing: %d\n", GetLastError());
	} else {
		//DBGPrint("Settings options success\n");
	}
	//DBGPrint("Returning\n\n");
}

//
//Get the status of a web request, and if it needs
//authentication, we do that as well. We use this as an
//opportunity to figure out how we will authenticate our way out 
//of the network
//
BOOL GetStatusAndAuthenticate(HINTERNET hRequest) {
	BOOL bRetVal = FALSE;
	BOOL bResults = FALSE;

	DWORD dwStatusCode = 0;
	DWORD dwLastStatus = 0;
	DWORD dwSize=sizeof(DWORD);
	DWORD dwSupportedSchemes;
	DWORD dwFirstScheme;
	DWORD dwSelectedScheme;
	DWORD dwTarget;

	LPSTR lpPassword = NULL;
	LPSTR lpUserName = NULL;
	LPSTR lpSite = NULL;

	DBGPrint("Called\n");

	//First check the response for a valid code 200
	bResults = WinHttpQueryHeaders(hRequest,
									WINHTTP_QUERY_STATUS_CODE |
									WINHTTP_QUERY_FLAG_NUMBER,
									NULL,
									&dwStatusCode,
									&dwSize,
									NULL);
	if (!bResults) {
		DBGPrint("Failed to retrieve status code: %d\n", GetLastError());
		goto exit;
	}

	while(1) {
		DBGPrint("Status code %d\n", dwStatusCode);
		switch (dwStatusCode) {
		case 200:
			DBGPrint("Status code %d, Success!\n",dwStatusCode);
			bRetVal = TRUE;
			goto exit;
		
		case 401:
			DBGPrint("Status code %d, Server requires authentication\n",dwStatusCode);
			// The server requires authentication.
			//DecryptIEHttpAuthPasswords();
			// Obtain the supported and preferred schemes.
			bResults = WinHttpQueryAuthSchemes( hRequest, 
												&dwSupportedSchemes, 
												&dwFirstScheme, 
												&dwTarget );
          
			// Set the credentials before resending the request.
			if (bResults) {
				dwSelectedScheme = ChooseAuthScheme( dwSupportedSchemes);

				if( dwSelectedScheme == 0 ) {
					goto exit;
				} else {
					if (LoadTargetForHandle(hRequest,&lpSite)) {
						GetCredsForSite(lpSite, &lpUserName,&lpPassword);
					}

					const WCHAR *pwcsUserName;
					int nChars = MultiByteToWideChar(CP_UTF8, 0, lpUserName, -1, NULL, 0);
					pwcsUserName = new WCHAR[nChars];
					MultiByteToWideChar(CP_UTF8, 0, lpUserName, -1, (LPWSTR)pwcsUserName, nChars);

					const WCHAR *pwcsPassword;
					nChars = MultiByteToWideChar(CP_UTF8, 0, lpPassword, -1, NULL, 0);
					pwcsPassword = new WCHAR[nChars];
					MultiByteToWideChar(CP_UTF8, 0, lpPassword, -1, (LPWSTR)pwcsPassword, nChars);

					DBGPrint("UserName: %s Password: %s\n",lpUserName,lpPassword);
					bResults = WinHttpSetCredentials(hRequest, 
										             dwTarget, 
													 dwSelectedScheme,
													 pwcsUserName,
													 pwcsPassword,
													 NULL );

					delete [] pwcsUserName;
					delete [] pwcsPassword;

				}
			}

			// If the same credentials are requested twice, abort the
			// request.  For simplicity, this sample does not check
			// for a repeated sequence of status codes.
			if( dwLastStatus == 401 ){
				DBGPrint("Status 401 Twice in a row\n");
				goto exit;
			}
				
			break;

		case 407:
			DBGPrint("Status code %d, Proxy requires authentication\n",dwStatusCode);
			//DecryptIEHttpAuthPasswords();

			// Obtain the supported and preferred schemes.
			bResults = WinHttpQueryAuthSchemes( hRequest, 
												&dwSupportedSchemes, 
												&dwFirstScheme, 
												&dwTarget );

			// Set the credentials before resending the request.
			if (bResults) {
				dwSelectedScheme = ChooseAuthScheme( dwSupportedSchemes);

				if (dwSelectedScheme == 0) {
					goto exit;
				} else {
					if (LoadTargetForHandle(hRequest,&lpSite)) {
						GetCredsForSite(lpSite, &lpUserName,&lpPassword);
					}	

					const WCHAR *pwcsUserName;
					int nChars = MultiByteToWideChar(CP_UTF8, 0, lpUserName, -1, NULL, 0);
					pwcsUserName = new WCHAR[nChars];
					MultiByteToWideChar(CP_UTF8, 0, lpUserName, -1, (LPWSTR)pwcsUserName, nChars);

					const WCHAR *pwcsPassword;
					nChars = MultiByteToWideChar(CP_UTF8, 0, lpPassword, -1, NULL, 0);
					pwcsPassword = new WCHAR[nChars];
					MultiByteToWideChar(CP_UTF8, 0, lpPassword, -1, (LPWSTR)pwcsPassword, nChars);

					DBGPrint("UserName: %s Password: %s\n",lpUserName,lpPassword);
					bResults = WinHttpSetCredentials(hRequest, 
									                 dwTarget, 
													 dwSelectedScheme,
													 pwcsUserName,
													 pwcsPassword,
													 NULL );
					if(bResults == FALSE){
						DBGPrint("Failed to set creds\n");
					}

					delete [] pwcsUserName;
					delete [] pwcsPassword;
				}
			}

			// If the same credentials are requested twice, abort the
			// request.  For simplicity, this sample does not check
			// for a repeated sequence of status codes.
			if( dwLastStatus == 407 ){
				DBGPrint("Status 407 Twice in a row\n");
				goto exit;
			}

			break;

		default:
			DBGPrint("Status code %d, we're not handling\n",dwStatusCode);
			goto exit;
		}

		//Preserve status
		dwLastStatus = dwStatusCode;


		// Send a request.
		bResults = WinHttpSendRequest( hRequest,
									   WINHTTP_NO_ADDITIONAL_HEADERS,
									   0,
									   WINHTTP_NO_REQUEST_DATA,
									   0, 
									   0, 
									   0);

		// End the request.
		if( bResults )
			bResults = WinHttpReceiveResponse( hRequest, NULL );

		// Resend the request in case of 
		// ERROR_WINHTTP_RESEND_REQUEST error.
		if( !bResults && GetLastError( ) == ERROR_WINHTTP_RESEND_REQUEST)
			continue;

		// Check the status code.
		if( bResults ) 
			bResults = WinHttpQueryHeaders( hRequest, 
				                          WINHTTP_QUERY_STATUS_CODE |
					                      WINHTTP_QUERY_FLAG_NUMBER,
						                  NULL, 
							              &dwStatusCode, 
								          &dwSize, 
									      NULL );
	}

exit:
	DBGPrint("Returning\n\n");
	return bRetVal;
}

//
// Check for a direct connection to the test 
// site
//
BOOL TestDirectConnect(PWCHAR testHost, USHORT testPort,PWCHAR resource, DWORD dwReqFlags) {
	BOOL bRetVal = FALSE;
	BOOL bResults = FALSE;

	HINTERNET hSession = NULL;
	HINTERNET hConnect = NULL;
	HINTERNET hRequest = NULL;

	//Establish the session
	hSession = WinHttpOpen(USER_AGENT,
							WINHTTP_ACCESS_TYPE_NO_PROXY,
							WINHTTP_NO_PROXY_NAME,
							WINHTTP_NO_PROXY_BYPASS,
							0);

	if(!hSession) {
		DBGPrint("hSession NULL\n");
		goto exit;
	} else {
		DBGPrint("hSession VALID\n");
	}


	//Set the security flags
	SetHandleProtFlags(hSession);
	
	// Specify an HTTP server.
	hConnect = WinHttpConnect(hSession, testHost,testPort, 0 );


	if (!hConnect) {
		DBGPrint("hConnect NULL\n");
		goto exit;
	} else {
		DBGPrint("hConnect VALID\n");
	}

	//Create an HTTP request handle.
	hRequest = WinHttpOpenRequest( hConnect,NULL, resource,
                                   NULL, WINHTTP_NO_REFERER, 
                                   WINHTTP_DEFAULT_ACCEPT_TYPES, 
								   dwReqFlags);

    if(!hRequest) {
		DBGPrint("hRequest NULL\n");
		goto exit;
	} else {
		DBGPrint("hRequest VALID\n");
	}

	//Set the redirection flags
	SetHandleRedirFlags(hRequest);

	//Set the security flags
	SetHandleCERTFlags(hRequest);


	//Now send the request)
    bResults = WinHttpSendRequest( hRequest,
								   WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                   WINHTTP_NO_REQUEST_DATA, 0, 
                                   0, 0 );
	if (!bResults) {
		DBGPrint("Send Request Failed: %d\n", GetLastError());
		goto exit;
	}

	// End the request.
    bResults = WinHttpReceiveResponse( hRequest, NULL );
	if (!bResults) {
		DBGPrint("Receive Response Failed: %d\n", GetLastError());
		goto exit;
	} else {
		DBGPrint("Receive Response Success\n");
		if (GetStatusAndAuthenticate(hRequest)) {
			bRetVal = TRUE;
		}
	}

exit:
	if (hSession)
		WinHttpCloseHandle(hSession);
	if(hConnect)
		WinHttpCloseHandle(hConnect);
	if(hRequest)
		WinHttpCloseHandle(hRequest);

	DBGPrint("Returning\n\n");
  
	return bRetVal;
}


//
// Try to connect to the test site using the default proxy
//
//
BOOL TestWithDefaultProxy(PWCHAR testHost,USHORT testPort,PWCHAR testResource,DWORD dwReqFlags) {
	BOOL bRetVal = FALSE;
	BOOL bResults = FALSE;

	HINTERNET hSession = NULL;
	HINTERNET hConnect = NULL;
	HINTERNET hRequest = NULL;

	DBGPrint("Called\n");

	//Establish the session
	hSession = WinHttpOpen(USER_AGENT,
							WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
							WINHTTP_NO_PROXY_NAME,
							WINHTTP_NO_PROXY_BYPASS,
							0);

	if (!hSession) {
		DBGPrint("hSession NULL\n");
		goto exit;
	} else {
		DBGPrint("hSession VALID\n");
	}

	//Make sure we loaded a good proxy

	WINHTTP_PROXY_INFO  lpProxy;
	DWORD proxySize = sizeof(WINHTTP_PROXY_INFO);

	// Use WinHttpQueryOption to retrieve internet options.
	if (WinHttpQueryOption( hSession, WINHTTP_OPTION_PROXY, &lpProxy, &proxySize)) {
		DBGPrint("Proxy Info: %s\n\n",lpProxy.lpszProxy);
	} else {
		DBGPrint("WinhttpQueryOption Failed: %d\n", GetLastError());
	}  
	
	SetHandleProtFlags(hSession);

	//Set to use WinInet's creds if we can
	SetHandleGlobalCredFlags(hSession);

	// Specify an HTTP server.
	hConnect = WinHttpConnect( hSession, testHost,testPort, 0 );


	if (!hConnect) {
		DBGPrint("hConnect NULL\n");
		goto exit;
	} else {
		DBGPrint("hConnect VALID\n");
	}

	//Create an HTTP request handle.
	hRequest = WinHttpOpenRequest( hConnect,NULL, testResource,
                                   NULL, WINHTTP_NO_REFERER, 
                                   WINHTTP_DEFAULT_ACCEPT_TYPES, 
                                   dwReqFlags );


    if (!hRequest) {
		DBGPrint("hRequest NULL\n");
		goto exit;
	} else {
		DBGPrint("hRequest VALID\n");

		//Set the redirection flags
		SetHandleRedirFlags(hRequest);

		//Set the security flags
		SetHandleCERTFlags(hRequest);
	}


	//Now send the request)
    bResults = WinHttpSendRequest( hRequest,
                                   WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                   WINHTTP_NO_REQUEST_DATA, 0, 
                                   0, 0 );
	if (!bResults) {
		DBGPrint("Send Request Failed: %d\n", GetLastError());
		goto exit;
	}

	// End the request.
    bResults = WinHttpReceiveResponse( hRequest, NULL );
	if (!bResults) {
		DBGPrint("Receive Response Failed: %d\n", GetLastError());
		goto exit;
	} else {
		DBGPrint("Receive Response Success\n");
		if (GetStatusAndAuthenticate(hRequest)) {
			bRetVal = TRUE;
		}
	}

exit:
    // Display the proxy servers and free memory 
    // allocated to this string.
    if (lpProxy.lpszProxy != NULL) {
        DBGPrint("Proxy server list: %S\n", lpProxy.lpszProxy);
        GlobalFree( lpProxy.lpszProxy );
    }

    // Display the bypass list and free memory 
    // allocated to this string.
    if (lpProxy.lpszProxyBypass != NULL) {
        DBGPrint("Proxy bypass list: %S\n", lpProxy.lpszProxyBypass);
	    GlobalFree( lpProxy.lpszProxyBypass );
    }
      
	if (hSession) {
		WinHttpCloseHandle(hSession);
	}

	if (hConnect) {
		WinHttpCloseHandle(hConnect);
	}

	if (hRequest) {
		WinHttpCloseHandle(hRequest);
	}

	DBGPrint("Returning\n");
	return bRetVal;
}

//
// Try to connect to the test site using the proxy
// discovery
//
//
BOOL TestDiscoverProxy(PWCHAR testHost, USHORT testPort,PWCHAR testResource, DWORD dwReqFlags) {
	BOOL bRetVal = FALSE;
	BOOL bResults = FALSE;

	HINTERNET hSession = NULL;
	HINTERNET hConnect = NULL;
	HINTERNET hRequest = NULL;

	DBGPrint("Called\n");

	// Now process the auto-proxy file
	WINHTTP_PROXY_INFO  ProxyInfo;
	WINHTTP_AUTOPROXY_OPTIONS AutoProxyOptions;
	DWORD proxySize = sizeof(WINHTTP_PROXY_INFO);

	ProxyInfo.lpszProxy = NULL;
	ProxyInfo.lpszProxyBypass = NULL;
	
	//Establish the session
	hSession = WinHttpOpen(USER_AGENT,
							WINHTTP_ACCESS_TYPE_NO_PROXY,
							WINHTTP_NO_PROXY_NAME,
							WINHTTP_NO_PROXY_BYPASS,
							0);


	if (!hSession) {
		DBGPrint("hSession NULL\n");
		goto exit;
	} else {
		DBGPrint("hSession VALID\n");
	}
	


	//Set the security flags
	SetHandleProtFlags(hSession);

	//Set to use WinInet's creds if we can
	SetHandleGlobalCredFlags(hSession);

	// Specify an HTTP server.
	hConnect = WinHttpConnect( hSession, testHost,
                              testPort, 0 );

	if (!hConnect) {
		DBGPrint("hConnect NULL\n");
		goto exit;
	} else {
		DBGPrint("hConnect VALID\n");
	}


	//Create an HTTP request handle.
	hRequest = WinHttpOpenRequest( hConnect,NULL, testResource,
                                   NULL, WINHTTP_NO_REFERER, 
                                   WINHTTP_DEFAULT_ACCEPT_TYPES, 
                                   dwReqFlags );

    if (!hRequest) {
		DBGPrint("hRequest NULL\n");
		goto exit;
	} else {
		DBGPrint("hRequest VALID\n");
		//Set the redirection flags
		SetHandleRedirFlags(hRequest);

		//Set the security flags
		SetHandleCERTFlags(hRequest);
	}

	// Try to find the proxy
	// Use auto-detection because the Proxy 
	// Auto-Config URL is not known.
	AutoProxyOptions.dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT;

	// Use DHCP and DNS-based auto-detection.
	AutoProxyOptions.dwAutoDetectFlags = 
                             WINHTTP_AUTO_DETECT_TYPE_DHCP |
                             WINHTTP_AUTO_DETECT_TYPE_DNS_A;

	// If obtaining the PAC script requires NTLM/Negotiate
	// authentication, then automatically supply the client
	// domain credentials.
	AutoProxyOptions.fAutoLogonIfChallenged = TRUE;

	// Call WinHttpGetProxyForUrl with our target URL. If 
	// auto-proxy succeeds, then set the proxy info on the 
	// request handle. If auto-proxy fails, ignore the error 
	// and attempt to send the HTTP request directly to the 
	// target server (using the default WINHTTP_ACCESS_TYPE_NO_PROXY 
	// configuration, which the requesthandle will inherit 
	// from the session).

	if (WinHttpGetProxyForUrl(hSession, testHost, &AutoProxyOptions, &ProxyInfo)) {
		// A proxy configuration was found, set it on the
		// request handle.
		DBGPrint("Proxy found, setting it\n");
		if (!WinHttpSetOption( hRequest, WINHTTP_OPTION_PROXY, &ProxyInfo, proxySize)) {
			// Exit if setting the proxy info failed.
			DBGPrint("Failed to set proxy info\n");
			goto exit;
		}
	} else {
		DBGPrint("No proxy found, done\n");
		goto exit;
	}

	//Now send the request
    bResults = WinHttpSendRequest( hRequest,
                                   WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                   WINHTTP_NO_REQUEST_DATA, 0, 
                                   0, 0 );
	if (!bResults) {
		DBGPrint("Send Request Failed: %d\n", GetLastError());
		goto exit;
	}


	// End the request.
    bResults = WinHttpReceiveResponse( hRequest, NULL );
	if (!bResults) {
		DBGPrint("Receive Response Failed: %d\n", GetLastError());
		goto exit;
	} else {
		DBGPrint("Receive Response Success\n");
		if (GetStatusAndAuthenticate(hRequest)) {
			bRetVal = TRUE;
		}
	}

exit:
    // Display the proxy servers and free memory 
    // allocated to this string.
    if (ProxyInfo.lpszProxy != NULL) {
        DBGPrint("Proxy server list: %S\n", ProxyInfo.lpszProxy);
        GlobalFree( ProxyInfo.lpszProxy );
    }

    // Display the bypass list and free memory 
    // allocated to this string.
    if (ProxyInfo.lpszProxyBypass != NULL) {
        DBGPrint("Proxy bypass list: %S\n", ProxyInfo.lpszProxyBypass);
	    GlobalFree( ProxyInfo.lpszProxyBypass );
    }
      
	if (hSession) {
		WinHttpCloseHandle(hSession);
	}

	if (hConnect) {
		WinHttpCloseHandle(hConnect);
	}

	if (hRequest) {
		WinHttpCloseHandle(hRequest);
	}


	DBGPrint("Returning\n");
	return bRetVal;
}

//
// Try to connect to the test site using the Internet Explorer proxy
//
//
BOOL TestIEProxy(PWCHAR testHost,USHORT testPort,PWCHAR testResource,DWORD dwReqFlags) {
	DBGPrint("Called\n");
	BOOL bRetVal = FALSE;
	BOOL bResults = FALSE;

	HINTERNET hSession = NULL;
	HINTERNET hConnect = NULL;
	HINTERNET hRequest = NULL;

	// Now process the auto-proxy file
	WINHTTP_PROXY_INFO  ProxyInfo;
	WINHTTP_AUTOPROXY_OPTIONS AutoProxyOptions;
	DWORD proxySize = sizeof(WINHTTP_PROXY_INFO);


	// See if we can grab the current user's IE config
	WINHTTP_CURRENT_USER_IE_PROXY_CONFIG IEProxyConfig;
	IEProxyConfig.lpszAutoConfigUrl = NULL;
	IEProxyConfig.lpszProxy = NULL;
	IEProxyConfig.lpszProxyBypass = NULL;
	if (!WinHttpGetIEProxyConfigForCurrentUser(&IEProxyConfig)) {
		DBGPrint("Failed to get current user config \n");
		goto exit;
	}else{
		DBGPrint("Successfully got proxy config\n");
	}

	//Continue on with the set up for the connection
	//Otherwise we are bust
	//Establish the session
	hSession = WinHttpOpen(USER_AGENT,
							WINHTTP_ACCESS_TYPE_NO_PROXY,
							WINHTTP_NO_PROXY_NAME,
							WINHTTP_NO_PROXY_BYPASS,
							0);

	if(!hSession){
		DBGPrint("hSession NULL\n");
		goto exit;
	}else{
		DBGPrint("hSession VALID\n");
	}

	// Set the security flags
	SetHandleProtFlags(hSession);

	// Set to use WinInet's creds if we can
	SetHandleGlobalCredFlags(hSession);

	// Specify an HTTP server.
	hConnect = WinHttpConnect( hSession, testHost,
                               testPort, 0 );

	if (!hConnect) {
		DBGPrint("hConnect NULL\n");
		goto exit;
	} else {
		DBGPrint("hConnect VALID\n");
	}

	// Create an HTTP request handle.
	hRequest = WinHttpOpenRequest( hConnect,NULL, testResource,
                                   NULL, WINHTTP_NO_REFERER, 
                                   WINHTTP_DEFAULT_ACCEPT_TYPES, 
                                   dwReqFlags );
    
	if (!hRequest) {
		DBGPrint("hRequest NULL\n");
		goto exit;
	} else {
		DBGPrint("hRequest VALID\n");
		// Set the redirection flags
		SetHandleRedirFlags(hRequest);

		// Set the security flags
		SetHandleCERTFlags(hRequest);
	}

	// Set up the proxy if we figured out one
	// If we got autoconfig URL try that first
	if (IEProxyConfig.lpszAutoConfigUrl) {
		DBGPrint("Loaded proxy.pac URL: %S\n", IEProxyConfig.lpszAutoConfigUrl);
		AutoProxyOptions.dwFlags = WINHTTP_AUTOPROXY_CONFIG_URL;
		AutoProxyOptions.lpszAutoConfigUrl = IEProxyConfig.lpszAutoConfigUrl;
		AutoProxyOptions.fAutoLogonIfChallenged = TRUE;

		// Our test host needs a schema or WinHttpGetProxyForUrl will blow up.
		DWORD testHostLen = wcslen(L"http://") + wcslen(testHost);
		WCHAR *testHost = new WCHAR[testHostLen];
		testHost[0] = L'\0';
		StringCchCatW(testHost, testHostLen, L"http://");
		StringCchCatW(testHost, testHostLen, testHost);

		DBGPrint("Test Host: %S\n", testHost);

		if (!WinHttpGetProxyForUrl(hSession, testHost, &AutoProxyOptions, &ProxyInfo)) {
			DBGPrint("Failed to get proxy from autoconfig: %d\n", GetLastError());
			delete [] testHost;
			goto exit;
		}
		delete [] testHost;
	} else if (IEProxyConfig.lpszProxy) {
		//If we got a proxy try that
		DBGPrint("Loaded proxy from IE\n");
		ProxyInfo.lpszProxy = IEProxyConfig.lpszProxy;
		ProxyInfo.lpszProxyBypass = IEProxyConfig.lpszProxyBypass;
		ProxyInfo.dwAccessType = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
	} else {
		DBGPrint("Got Nothing from IE\n");
		goto exit;
	}

	// A proxy configuration was found, set it on the
	// request handle.
    DBGPrint("Proxy found, setting it\n");
    if (!WinHttpSetOption( hRequest, WINHTTP_OPTION_PROXY, &ProxyInfo, proxySize)) {
		// Exit if setting the proxy info failed.
		DBGPrint("Failed to set proxy info: %d\n", GetLastError());
		goto exit;
    }	

	//Now send the request)
    bResults = WinHttpSendRequest( hRequest,
                                   WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                   WINHTTP_NO_REQUEST_DATA, 0, 
                                   0, 0 );
	if (!bResults) {
		DBGPrint("Send Request Failed: %d\n", GetLastError());
		goto exit;
	}


	// End the request.
    bResults = WinHttpReceiveResponse( hRequest, NULL );
	if (!bResults) {
		DBGPrint("Receive Response Failed: %d\n", GetLastError());
		goto exit;
	} else {
		DBGPrint("Receive Response Success\n");
		if (GetStatusAndAuthenticate(hRequest)) {
			bRetVal = TRUE;
		}
	}

exit:
    // Display the proxy servers and free memory 
    // allocated to this string.
    if (IEProxyConfig.lpszProxy != NULL) {
        DBGPrint("Proxy server list: %S\n", IEProxyConfig.lpszProxy);
        GlobalFree( IEProxyConfig.lpszProxy );
    }

    // Display the bypass list and free memory 
    // allocated to this string.
    if (IEProxyConfig.lpszProxyBypass != NULL) {
        DBGPrint("Proxy bypass list: %S\n", IEProxyConfig.lpszProxyBypass);
	    GlobalFree( IEProxyConfig.lpszProxyBypass );
    }
     
	if (IEProxyConfig.lpszAutoConfigUrl != NULL) {
		DBGPrint("Auto Config URL: %S\n", IEProxyConfig.lpszAutoConfigUrl);
		GlobalFree( IEProxyConfig.lpszAutoConfigUrl );
	}


	if (hSession) {
		WinHttpCloseHandle(hSession);
	}

	if (hConnect) {
		WinHttpCloseHandle(hConnect);
	}

	if(hRequest) {
		WinHttpCloseHandle(hRequest);
	}

	DBGPrint("Returning\n");
	return bRetVal;
}


//
//Sets up the HTTP Session, detect all proxy settings, verifies the test connection works
// and sets the global handle for the session
//
BOOL InitializeHttpSession(PWCHAR testHost,USHORT testPort, PWCHAR testResource,DWORD dwReqFlags){
	BOOL bRetVal = FALSE;

	DBGPrint("Called\n");

	//First try a direct connect
	if(TestDirectConnect(testHost,testPort,testResource,dwReqFlags) != TRUE){
		DBGPrint("Direct Connect failed, need to resolve proxy\n");
		
		//Now try default proxy
		if(TestWithDefaultProxy(testHost,testPort,testResource,dwReqFlags) != TRUE){
			DBGPrint("Default proxy failed,trying discovery\n");

			if(TestDiscoverProxy(testHost,testPort,testResource,dwReqFlags) != TRUE){
				DBGPrint("Discovery proxy failed,trying IESettings\n");

				if(TestIEProxy(testHost,testPort,testResource,dwReqFlags) != TRUE){
					DBGPrint("IEProxy failed, can't connect\n");
				} else {
					DBGPrint("IEPRoxy successful\n");
					g_meterproxy_config.bUseIESettings = TRUE;
					bRetVal = TRUE;
				}
			} else {
				DBGPrint("AutoConfig of  proxy successful\n");
				g_meterproxy_config.bConnectAutoConfigURL = TRUE;
				bRetVal = TRUE;
			}
		} else {
			DBGPrint("Default proxy successful\n");
			g_meterproxy_config.bConnectDefaultProxy = TRUE;
			bRetVal  = TRUE;
		}
	} else {
		DBGPrint("Direct Connect successful, no proxy necessary\n");
		g_meterproxy_config.bConnectDirect = TRUE;
		bRetVal = TRUE;
	}

	DBGPrint("Returning\n");

	return bRetVal;
}
