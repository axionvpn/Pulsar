#include <windows.h>
#include <wincred.h>
#include "PulsarInternal.h"
#include "PulsarLog.h"


#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383



//
// Deterimine the storage requirements for a string stored
// in the registry
//
DWORD GetSizeOfRegistryStr(HKEY regkey, PCHAR name){

	DWORD dwSize;
	DWORD dwType;

  //Determine size of value
  LONG status = RegQueryValueEx(regkey, name, NULL, &dwType, NULL, &dwSize);
  if (status != ERROR_SUCCESS){
    DBGPrint("Failed to read in size of %s\n",name);
	return 0;
  }
  
  DBGPrint("Value at %s is %d bytes\n",name,dwSize);
  return dwSize;

}
 


//
// Read in a string from the registry. "data" must be already allocated
// with enough storage to hold the results.
//
BOOL GetRegistryValueStr(HKEY regkey, PCHAR name, PCHAR data, DWORD len)
{
  LONG status;
  DWORD type;
  DWORD data_len;

  data_len = len * sizeof(*data);

  //Determine size of value
  status = RegQueryValueEx(regkey, name, NULL, &type, (LPBYTE )data, &data_len);
  if (status != ERROR_SUCCESS || type != REG_SZ){
    DBGPrint("Failed to read in size of %s\n",name);
	return FALSE;
  }
  
  DBGPrint("Value at %s is %d bytes\n",name,data_len);

  return TRUE;

}


//
// Get a numeric value from the registry. We always return a DWORD, so
// sometimes we have to read into a temporary value when we're casting a
// short.
//
BOOL GetRegistryValueNum(HKEY regkey, PCHAR name, DWORD *data)
{
  DWORD dwType;
  DWORD size = sizeof(DWORD);
  LONG status = RegQueryValueEx(regkey, name, NULL, &dwType, (PBYTE) data, &size);
  
  if(status != ERROR_SUCCESS){
	  DBGPrint("Failed to read %d\n",name);
	  return FALSE;
  }

  return TRUE;
}

//
// Read a binary value in from the registry. We allocate space for it on the 
// heap, and therefore the caller must later free it.
//

BOOL GetRegistryValueBin(HKEY regkey, PCHAR name, PVOID data, DWORD *dwSize)
{
  LONG status;
  DWORD type;

  //See how many bytes we need
  status = RegQueryValueEx(regkey, name, NULL, &type, NULL, dwSize);
  if (status != ERROR_SUCCESS || dwSize == 0){
     DBGPrint("Query failed or needed no bytes\n");
	 return FALSE;
  }

  //Allocate on the heap the Bytes we need
  DBGPrint("Size needed is %d",*dwSize);
  data = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,*dwSize);
  if(data == NULL){
	DBGPrint("Failed to allocate memory\n");
	return FALSE;
  }


  //Now really query for our Data.
  status = RegQueryValueEx(regkey, name, NULL, &type, (byte *) data, dwSize);
    if (status != ERROR_SUCCESS || *dwSize == 0){
     DBGPrint("Failed to read value for %s\n",name);
	 HeapFree(GetProcessHeap(),0,data);
  }


  return TRUE;

}




//
// Write a string to the registry key passed in and return
// a TRUE or FALSE depending on success or failure
//
BOOL SetRegistryValueStr(HKEY regkey, PCHAR name, PCHAR value)
{

  DBGPrint("Called. Writing %s to %s\n", value, name);


  DWORD size = (strlen(value) + 1) * sizeof(CHAR);

  LONG status = RegSetValueEx(regkey, name, 0, REG_SZ, (PBYTE) value, size);
  if(status  != ERROR_SUCCESS)
  {
	  DBGPrint("Failed to write key: %s %d\n",name,GetLastError());
      return FALSE;
  }

  return TRUE;

}

//
// Write a numeric value to the registry key passed in, and return a
// TRUE or FALSE depending on success or failure
//
BOOL SetRegistryValueNum(HKEY regkey, PCHAR name, DWORD value)
{

  DBGPrint("Called. Writing %d to %s\n", value, name);

  LONG status = RegSetValueEx(regkey, name, 0, REG_DWORD, (PBYTE) &value, sizeof(value));
  if (status != ERROR_SUCCESS){
	  DBGPrint("Failed to write key: %s\n",name);
	  return FALSE;
  }

  return TRUE;
}


//
// Write a buffer of size "size" to the key as binary data
//
BOOL SetRegistryValueBin(HKEY regkey, PCHAR name, PVOID data, DWORD size)
{
	DBGPrint("Called. Writing %d bytes to %s\n",size,name);

	LONG status = RegSetValueEx(regkey, name, 0, REG_BINARY, (PBYTE)data, size);
	if( status != ERROR_SUCCESS)
	{
		DBGPrint("Failed to write to %s\n",name);
		return FALSE;
    }

  return TRUE;

}




//
// Given a string with the creds, use MS's data protection function and write it to the 
// registry
//
BOOL StoreCredsInReg(CHAR *name, CHAR *creds)
{

	DBGPrint("Called. Writing %s to key %s\n",creds,name);
	HKEY hKey;


	//Check for registry key and create if its not there
	LONG lResult = RegOpenKeyEx (HKEY_LOCAL_MACHINE, CRED_STORE_KEY, 0, KEY_READ | KEY_WRITE , &hKey);

	if (lResult != ERROR_SUCCESS) 
	{

		DBGPrint("Failed to open Registry Key\n");
		return FALSE;
	}

	DATA_BLOB DataIn;
	DATA_BLOB DataOut;
    DWORD cbDataInput = strlen(creds) + 1;
	

   DataIn.pbData = (BYTE*)creds;    
   DataIn.cbData = cbDataInput;



	if(CryptProtectData(
		 &DataIn,
		 NULL,								 // A description string. 
		 NULL,                               // Optional entropy
											 // not used.
		 NULL,                               // Reserved.
		 NULL,								 // No PromptStruct.
		 0,
		 &DataOut))
	{
		 DBGPrint("Encryption Success\n");
	}
	else
	{
		DBGPrint("Encryption error!\n");
		RegCloseKey(hKey);
		return FALSE;
	}

	// Set a registry binary value
	if(RegSetValueEx(hKey, name, 0, REG_BINARY, (PBYTE) DataOut.pbData, DataOut.cbData) != ERROR_SUCCESS)
    {
      // Error writing registry value
      DBGPrint("Failed to write to Registry Key\n");
      RegCloseKey(hKey);
	  return FALSE;
    }


	RegCloseKey(hKey);
	return TRUE;

}


//
// Takes a key and actually recovers the creds from
// it
//
CHAR *GetCredsFromKey(HKEY hKey, CHAR *site){

	DBGPrint("Called. Reading creds for %s\n",site);
	CHAR *retVal;
	LONG lResult;
	DWORD type;
	DWORD dwBytesNeeded = 0;

	DATA_BLOB DataIn;
	DATA_BLOB DataOut;

	void *encData = NULL;


	//See how many bytes we need
	lResult = RegQueryValueEx(hKey, site, NULL, &type, NULL, &dwBytesNeeded);
	if (lResult != ERROR_SUCCESS || dwBytesNeeded == 0){
		DBGPrint("Query failed or needed no bytes\n");
		return NULL;
	}

	//Allocate on the heap the Bytes we need into a temporarary heap space
	//This will hold the encrypted creds
	DBGPrint("Size needed is %d\n",dwBytesNeeded);
	encData = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,dwBytesNeeded);
    if(encData == NULL){
	  DBGPrint("Failed to allocate memory\n");
	  return NULL;
    }


	//Now really query for our Data.
	lResult = RegQueryValueEx(hKey, site, NULL, &type, (byte *) encData, &dwBytesNeeded);
    if (lResult != ERROR_SUCCESS || dwBytesNeeded == 0){
		DBGPrint("Second query failed\n");
		HeapFree(GetProcessHeap(),0,encData);
		return NULL;
	}

  //Set up pointers
  DataIn.pbData = (BYTE *)encData; 
  DataIn.cbData = dwBytesNeeded;

 
  //Decrypt the data
  if (CryptUnprotectData(
        &DataIn,
        NULL,
        NULL,                 // Optional entropy
        NULL,                 // Reserved
        NULL,				  // No PromptStruct
        0,
        &DataOut))
	{
	     
		 //We can free the encrypted data before we continue
		 HeapFree(GetProcessHeap(),0,encData);

		 DBGPrint("Decrypted data len is: %d\n",DataOut.cbData);

		 //Allocate a string for the return value
		 retVal = (CHAR *)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,DataOut.cbData);
		 if(!retVal){
			return NULL;
		 }

		 memcpy(retVal,DataOut.pbData,DataOut.cbData);

	}
	else
	{
		DBGPrint("Decryption error!");
		HeapFree(GetProcessHeap(),0,encData);
		return NULL;
	}

  DBGPrint("Returning: %s\n", retVal);
  return retVal;

}



//
// Given a site, recover the creds and return the
// decrypted but unparsed creds string. This cred
// string is allocated on the heap and should be
// freed by the user
//
CHAR *GetCredsFromReg(CHAR *site){

	DBGPrint("Called. Reading creds for %s\n",site);
	
	HKEY hKey;
	CHAR *retVal = NULL;


    DWORD    cSubKeys=0;               // number of subkeys 
    DWORD    cbMaxSubKey;              // longest subkey size 
    DWORD    cchMaxClass;              // longest class string 
    DWORD    cValues;              // number of values for key 
    DWORD    cchMaxValue;          // longest value name 
    DWORD    cbMaxValueData;       // longest value data 

	//Open the main Cred Store key
	LONG lResult = RegOpenKeyEx (HKEY_LOCAL_MACHINE, CRED_STORE_KEY, 0, KEY_READ | KEY_WRITE , &hKey);
	if (lResult != ERROR_SUCCESS) 
	{
		DBGPrint("Failed to open Registry Key\n");
		return NULL;
	}

	// Get the class name and the value count. 
    lResult = RegQueryInfoKey(
        hKey,                    // key handle 
        NULL,				     // buffer for class name 
        NULL,				     // size of class string 
        NULL,                    // reserved 
        &cSubKeys,               // number of subkeys 
        &cbMaxSubKey,            // longest subkey size 
        &cchMaxClass,            // longest class string 
        &cValues,                // number of values for this key 
        &cchMaxValue,            // longest value name 
        &cbMaxValueData,         // longest value data 
        NULL,   // security descriptor 
        NULL);					 // last write time 


	if(lResult != ERROR_SUCCESS){
		DBGPrint("Failed to query Registry Key\n");
		RegCloseKey(hKey);
		return NULL;
	}


	//Now iterate through all the values
	DBGPrint("There are %d key values\n",cValues);
    CHAR  achValue[MAX_VALUE_NAME]; 
    DWORD cchValue = MAX_VALUE_NAME;
	for (int i=0; i<cValues; i++) 
        { 
            cchValue = MAX_VALUE_NAME; 
            achValue[0] = '\0'; 
            lResult = RegEnumValue(hKey, i, 
                achValue, 
                &cchValue, 
                NULL, 
                NULL,
                NULL,
                NULL);
 
            if (lResult == ERROR_SUCCESS ) 
            { 
                DBGPrint("(%d) %s\n", i+1, achValue); 
				if(strcmp(site,achValue) == 0){
					retVal = GetCredsFromKey(hKey,site);
					break;
				}
            } 
        }



	RegCloseKey(hKey);


	return retVal;
}
