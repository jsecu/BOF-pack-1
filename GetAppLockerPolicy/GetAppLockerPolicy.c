#include <windows.h>
#include "interface.h"
#include "beacon.h"
#include <windows.h>

DECLSPEC_IMPORT WINOLEAPI OLE32$CoInitializeEx(LPVOID pvReserved,DWORD);
DECLSPEC_IMPORT WINOLEAPI OLE32$CoCreateInstance(const IID *,LPUNKNOWN,DWORD,const IID *,LPVOID*);
DECLSPEC_IMPORT WINOLEAPI OLE32$CoUninitialize(void);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);
WINBASEAPI HANDLE WINAPI KERNEL32$CloseHandle(HANDLE);




void go(char * args, int len){
HRESULT status=0;
BSTR effectivepolicy = NULL;
BOOL bstatus = FALSE;


IAppIdPolicyHandler * policy = NULL;
status = OLE32$CoInitializeEx(NULL,COINIT_MULTITHREADED);
if(FAILED(status)){
    BeaconPrintf(CALLBACK_OUTPUT,"CoInitialize Failed with 0x%08lx\n",status);
    goto cleanup;
}
status = OLE32$CoCreateInstance(&CLSID_AppIdPolicyHandler,NULL,CLSCTX_INPROC_SERVER,&IID_IAppIdPolicyHandler,(void **)&policy);
if(FAILED(status)){
    BeaconPrintf(CALLBACK_OUTPUT,"CoCreateInstance Failed with 0x%08lx\n",status);
    goto cleanup;
}
status = policy->lpVtbl->GetEffectivePolicy(policy, &effectivepolicy);
if(FAILED(status)){
    BeaconPrintf(CALLBACK_OUTPUT,"GetEffectivePolicy Failed with 0x%08lx\n",status);
    goto cleanup;
}

BeaconPrintf(CALLBACK_OUTPUT,"Effective Policy %S\n",effectivepolicy);
goto cleanup;

cleanup:

    OLE32$CoUninitialize();
    if(policy != NULL){
        policy->lpVtbl->Release(policy);
    }



}
