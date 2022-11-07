#include <Windows.h>


#ifndef _INTERFACES_H
#define _INTERFACES_H


CONST IID IID_IAppIdPolicyHandler ={ 0xB6FEA19E, 0x32DD, 0x4367, {0xB5, 0xB7, 0x2F, 0x5D, 0xA1, 0x40, 0xE8, 0x7D} };

CONST GUID CLSID_AppIdPolicyHandler= {0xF1ED7D4C, 0xF863, 0x4DE6,{0xA1, 0xCA, 0x72, 0x53, 0xEF, 0xDE, 0xE1, 0xF3}};



typedef interface IAppIdPolicyHandler IAppIdPolicyHandler;

#if defined(__cplusplus) && !defined(CINTERFACE)
MIDL_INTERFACE("B6FEA19E-32DD-4367-B5B7-2F5DA140E87D")
IAppPolicyHandler : public IUnknown,public IDispatch{
public:
    virtual void STDMETHODCALLTYPE SetPolicy(
			_In_ BSTR bstrLdapPath,
			_In_ BSTR bstrXmlPolicy
		);

		virtual BSTR STDMETHODCALLTYPE GetPolicy(_In_ BSTR bstrLdapPath);

		virtual BSTR STDMETHODCALLTYPE GetEffectivePolicy();

		virtual INT STDMETHODCALLTYPE IsFileAllowed(
			_In_ BSTR bstrXmlPolicy,
			_In_ BSTR bstrFilePath,
			_In_ BSTR bstrUserSid,
			_Out_ GUID * pguidResponsibleRuleId
		);

		virtual INT STDMETHODCALLTYPE IsPackageAllowed(
			_In_ BSTR bstrXmlPolicy,
			_In_ BSTR bstrPublisherName,
			_In_ BSTR bstrPackageName,
			_In_ uint64 ullPackageVersion,
			_In_ BSTR bstrUserSid,
			_Out_ GUID * pguidResponsibleRuleId
		);






};
#else

typedef struct AppPolicyHandlerVtbl{
     BEGIN_INTERFACE
      		HRESULT(STDMETHODCALLTYPE * QueryInterface)(
            _In_  IAppIdPolicyHandler* This,
			_In_ GUID * riid,
			_Out_ void** ppvObj
		);

		LONG(STDMETHODCALLTYPE * AddRef)(_In_  IAppIdPolicyHandler* This);

		LONG(STDMETHODCALLTYPE *  Release)(_In_  IAppIdPolicyHandler* This);

		HRESULT (STDMETHODCALLTYPE * GetTypeInfoCount)(_In_  IAppIdPolicyHandler* This,_Out_ unsigned int* pctinfo);

		HRESULT (STDMETHODCALLTYPE *  GetTypeInfo)(
            _In_  IAppIdPolicyHandler* This,
			_In_ unsigned int itinfo,
			_In_ unsigned long lcid,
			_Out_ void** pptinfo
		);

		HRESULT (STDMETHODCALLTYPE * GetIDsOfNames)(
            _In_  IAppIdPolicyHandler* This,
			_In_ GUID* riid,
			_In_ char** rgszNames,
			_In_ unsigned int cNames,
			_In_ unsigned long lcid,
			_Out_ long* rgdispid
		);

		 HRESULT (STDMETHODCALLTYPE * Invoke)(
            _In_  IAppIdPolicyHandler* This,
			_In_ long dispidMember,
			_In_ GUID * riid,
			_In_ unsigned long lcid,
			_In_ unsigned short wFlags,
			_In_ DISPPARAMS * pdispparams,
			_Out_ VARIANT* pvarResult,
			_Out_ EXCEPINFO * pexcepinfo,
			_Out_ unsigned int* puArgErr
		);

      HRESULT (STDMETHODCALLTYPE * SetPolicy)(
        _In_  IAppIdPolicyHandler* This,
		_In_ BSTR bstrLdapPath,
		_In_ BSTR bstrXmlPolicy
	);

	HRESULT (STDMETHODCALLTYPE * GetPolicy)(
        _In_  IAppIdPolicyHandler* This,
		_In_ BSTR bstrLdapPath,
		_Out_ BSTR* pbstrXmlPolicy
	);

	HRESULT (STDMETHODCALLTYPE * GetEffectivePolicy)( _In_  IAppIdPolicyHandler* This,_Out_ BSTR* pbstrXmlPolicy);

    HRESULT (STDMETHODCALLTYPE * IsFileAllowed)(
        _In_  IAppIdPolicyHandler* This,
		_In_ BSTR bstrXmlPolicy,
		_In_ BSTR bstrFilePath,
		_In_ BSTR bstrUserSid,
		_Out_ GUID * pguidResponsibleRuleId,
		_Out_ long* pbStatus
	);

	HRESULT (STDMETHODCALLTYPE * IsPackageAllowed)(
        _In_  IAppIdPolicyHandler* This,
		_In_ BSTR bstrXmlPolicy,
		_In_ BSTR bstrPublisherName,
		_In_ BSTR bstrPackageName,
		_In_ ULONG ullPackageVersion,
		_In_ BSTR bstrUserSid,
		_Out_ GUID * pguidResponsibleRuleId,
		_Out_ long* pbStatus
	);
	END_INTERFACE

}AppPolicyHandlerVtbl;

interface IAppIdPolicyHandler{

    CONST_VTBL struct AppPolicyHandlerVtbl *lpVtbl;


};

#endif

#endif // _INTERFACES_H




