#pragma once

#include <winhttp.h>

BOOL InitializeHttpSession(PWCHAR testSite, USHORT testPort,PWCHAR resource, DWORD dwReqFlags);
VOID SetHandleRedirFlags(HINTERNET hHandle);
VOID SetHandleCERTFlags(HINTERNET hHandle);
VOID SetHandleProtFlags(HINTERNET hHandle);