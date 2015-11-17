#pragma once


BOOL StoreCredsInReg(CHAR *name, CHAR *creds);
CHAR *GetCredsFromReg(CHAR *site);

DWORD GetSizeOfRegistryStr(HKEY regkey, PCHAR name);

BOOL SetRegistryValueStr(HKEY regkey, PCHAR name, PCHAR value);
BOOL SetRegistryValueNum(HKEY regkey, PCHAR name, DWORD value);
BOOL SetRegistryValueBin(HKEY regkey, PCHAR name, PVOID data, DWORD size);

BOOL GetRegistryValueStr(HKEY regkey, PCHAR name, PCHAR data, DWORD len);
BOOL GetRegistryValueNum(HKEY regkey, PCHAR name, DWORD *data);
BOOL GetRegistryValueBin(HKEY regkey, PCHAR name, PVOID data, DWORD *dwSize);





