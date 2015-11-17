#include "PulsarLog.h"

#ifdef _DEBUG

CHAR LogFile[MAX_PATH];
int FileSet = LOG_FILE_NOT_SET;



//
// Establish a global log file
//
//
VOID SetLogFile(LPSTR File){

	if(File){
       FileSet = LOG_FILE_SET;
	   ZeroMemory(LogFile,MAX_PATH);
	   CopyMemory(LogFile,File,strlen(File) * sizeof(CHAR));
	}
  
  HANDLE hFile;
  DWORD dwBytesWritten;
  BYTE BOM[3]={0xEF,0xBB,0xBF};


  if(FileSet == LOG_FILE_SET){
	  return;
  }

  	//Set up actual keylogger
    if ((hFile = CreateFile(File, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, NULL)) == INVALID_HANDLE_VALUE)
	{
		return;
	}

	//Add the UTF-8 Byte Order Mark (BOM), otherwise Windows won't
	//handle the file correctly
	  WriteFile(hFile,BOM,3,&dwBytesWritten,0);


   //Close the file
	  CloseHandle(hFile);


   //Set the global so we don't re-create it
	  FileSet = LOG_FILE_SET;


}


//
// A simple printf replacement for windows, that logs to our
// default log file. It also prints the current function 
// name
//
VOID LogOutPutStr(LPSTR funcname, const CHAR *fmt, ...) {
  FILE  *ofp;
  va_list ap;
  errno_t err;

  if(FileSet == LOG_FILE_SET){
   err = fopen_s(&ofp,LogFile,"a");
  }else{
   err = fopen_s(&ofp,LOGFILE,"a");
  }
   if(err != 0){
	   return;
   }

   fprintf(ofp,"[%s]",funcname);

   va_start(ap,fmt);

     vfprintf(ofp,fmt,ap);

   va_end(ap);

   fclose(ofp);

};


//
// Log to our file the textual representation of the last
// system error
//
void LogLastError(LPSTR func){

    DWORD dwRet;
    LPSTR lpszTemp = NULL;
	CHAR lpszBuf[512];
	DWORD dwSize = 512;

    dwRet = FormatMessage( FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |FORMAT_MESSAGE_ARGUMENT_ARRAY,
                           NULL,
                           GetLastError(),
                           LANG_NEUTRAL,
                           (LPSTR)&lpszTemp,
                           0,
                           NULL );

    // supplied buffer is not long enough
    if ( !dwRet || ( (long)dwSize < (long)dwRet+14 ) )
        lpszBuf[0] = '\0';
    else
    {
        lpszTemp[lstrlen(lpszTemp)-2] = '\0';  //remove cr and newline character
        sprintf_s( lpszBuf, 512, "%s (0x%x)", lpszTemp, GetLastError() );
    }

    if ( lpszTemp )
        LocalFree((HLOCAL) lpszTemp );

	LogOutPutStr(func,"%s\n", lpszBuf);

    return;
}


#endif