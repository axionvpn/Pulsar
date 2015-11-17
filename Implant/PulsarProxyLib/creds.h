#pragma once

#include <windows.h>

void DecryptIEHttpAuthPasswords();

BOOL GetCredsForSite(LPSTR lpSite, LPSTR *lpUserName, LPSTR *lpPassword);