#ifndef __VAR_UTILS__
#define __VAR_UTILS__




int DumpBuffer(unsigned char *buf, int bufSize, char *outFile);
void PrintVars(PPROXY_VARS vars);
unsigned char *FileToBuf(char *filename,int *size);


#endif

