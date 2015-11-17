#pragma once


//
// Reads the string value found in hkRoot\lpKey\lpValue
// and returns it. The memory is allocated on the
// heap and it is the responsibiilty of the caller to free it
//
LPWSTR ReadRegStr(HKEY hkRoot, PCHAR lpKey, PCHAR lpValue);


//
// Reads the DWORD value found in hkRoot\lpKey\lpValue
// and returns it. 
//
DWORD ReadRegDword(HKEY hkRoot, PCHAR lpKey, PCHAR lpValue);