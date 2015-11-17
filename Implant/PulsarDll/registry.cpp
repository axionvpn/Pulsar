#include <Windows.h>
#include "PulsarLog.h"

//
// Reads the DWORD value found in hkRoot\lpKey\lpValue
// and returns it. 
//
DWORD ReadRegDword(HKEY hkRoot, PCHAR lpKey, PCHAR lpValue)
{

	HKEY hKey = NULL;
	LONG lRetVal;
	DWORD dwRetVal = 0;

	DBGPrint("Called, Reading %s\\%s\n",lpKey,lpValue);


	//lRetVal = RegOpenKeyEx(hkRoot, lpKey, KEY_WOW64_64KEY, KEY_READ, &hKey);
	lRetVal = RegOpenKeyEx(hkRoot, lpKey, 0, KEY_READ, &hKey);

	if(lRetVal != ERROR_SUCCESS){
       DBGPrint("Could not open registry key\n");
	   goto exit;
	}

	DWORD type;
    DWORD cbData = sizeof(DWORD);


	lRetVal = RegQueryValueEx(hKey, lpValue, NULL, &type, NULL, &cbData);
    if (lRetVal != ERROR_SUCCESS)
		
    {
		DBGPrint("Could not perform initial query on key\n");
		goto exit;
    }

    if (type != REG_DWORD)
    {
		DBGPrint("Value is not dword type\n");
		goto exit;
    }
	

	lRetVal = RegQueryValueEx(hKey, lpValue, NULL, NULL,(LPBYTE) &dwRetVal, &cbData);
    if (lRetVal != ERROR_SUCCESS)
		
    {
		DBGPrint("Could not perform second query on key\n");
		goto exit;
    }




	

exit:

	if(hKey){
		RegCloseKey(hKey);
	}

	DBGPrint("Returning: %d\n",dwRetVal);
	return dwRetVal;
}


//
// Reads the string value found in hkRoot\lpKey\lpValue
// and returns it. The memory is allocated on the
// heap and it is the responsibiilty of the caller to free it
//
LPSTR ReadRegStr(HKEY hkRoot, PCHAR lpKey, PCHAR lpValue)
{

	HKEY hKey = NULL;
	LONG lRetVal;
	LPSTR lpStrVal = NULL;

	DBGPrint("Called, Reading %s\\%s\n",lpKey,lpValue);


	//lRetVal = RegOpenKeyEx(hkRoot, lpKey, KEY_WOW64_64KEY, KEY_READ, &hKey);
	lRetVal = RegOpenKeyEx(hkRoot, lpKey, 0, KEY_READ, &hKey);

	if(lRetVal != ERROR_SUCCESS){
       DBGPrint("Could not open registry key\n");
	   goto exit;
	}

	DWORD type;
    DWORD cbData;

	lRetVal = RegQueryValueEx(hKey, lpValue, NULL, &type, NULL, &cbData);
    if (lRetVal != ERROR_SUCCESS)
		
    {
		DBGPrint("Could not perform initial query on key\n");
		goto exit;
    }

    if (type != REG_SZ)
    {
		DBGPrint("Value is not string type\n");
		goto exit;
    }

	DBGPrint("String needs %d bytes\n",cbData);
	//Allocate bytes
	lpStrVal = (PCHAR) HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,cbData);
	if(!lpStrVal){
		DBGPrint("Heap Allocation Failed\n");
		goto exit;
	}

	lRetVal = RegQueryValueEx(hKey, lpValue, NULL, &type, (LPBYTE)lpStrVal, &cbData);
    if (lRetVal != ERROR_SUCCESS)
		
    {
		DBGPrint("Could not perform second query on key\n");
		goto exit;
    }

	

exit:

	if(hKey){
		RegCloseKey(hKey);
	}

	printf("Returning: %s\n",lpStrVal);
	return lpStrVal;
}
