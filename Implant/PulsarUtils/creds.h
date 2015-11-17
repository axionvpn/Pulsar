#pragma once

BOOL GetCredsForCurrentUser(LPSTR lpSite);

BOOL GetCredsForSite(LPSTR lpSite, LPSTR *lpUserName, LPSTR *lpPassword);

BOOL StoreCreds(LPSTR lpSite, LPSTR lpCreds);

BOOL InitCredStore(VOID);