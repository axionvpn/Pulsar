#ifndef __PULSAR_LOG__
#define __PULSAR_LOG__

// The following macros define the minimum required platform.  The minimum required platform
// is the earliest version of Windows, Internet Explorer etc. that has the necessary features to run 
// your application.  The macros work by enabling all features available on platform versions up to and 
// including the version specified.

// Modify the following defines if you have to target a platform prior to the ones specified below.
// Refer to MSDN for the latest info on corresponding values for different platforms.
#ifndef _WIN32_WINNT            // Specifies that the minimum required platform is Windows Vista.
#define _WIN32_WINNT 0x0600     // Change this to the appropriate value to target other versions of Windows.
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <windows.h>

#define MAX_LOG_FILE_SZ 15*1024*1024
#define LOGFILE "PulsarLog.txt"
#define LOG_FILE_SET	 1
#define LOG_FILE_NOT_SET 0



#ifdef _DEBUG


#define DBGPrint(a,...) LogOutPutStr(__FUNCTION__,a,__VA_ARGS__);
#define LAST_ERR()		 LogLastError(__FUNCTION__);

  VOID LogOutPutStr(LPSTR funcname, const CHAR *fmt, ...);
  VOID LogLastError(LPSTR);
  VOID SetLogFile(LPSTR);
#else
  #define DBGPrint {}
  #define LogLastError(LPTSTR) {}
  #define SetLogFile(LPTSTR) {}

#endif



#endif