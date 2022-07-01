#include <windows.h> 
#include <stdio.h> 

typedef int(__cdecl* MYPROC)(LPWSTR);

int main(void)
{
    HINSTANCE sgxCryptoLib;
    MYPROC ProcAdd;
    BOOL fFreeResult, fRunTimeLinkSuccess = FALSE;

    // Get a handle to the DLL module.

    sgxCryptoLib = LoadLibrary(TEXT("sgx_crypto.dll"));

    // If the handle is valid, try to get the function address.

    if (sgxCryptoLib != NULL)
    {
        ProcAdd = (MYPROC)GetProcAddress(sgxCryptoLib, "getEncrypt");

        // If the function address is valid, call the function.

        if (NULL != ProcAdd)
        {
            fRunTimeLinkSuccess = TRUE;
            (ProcAdd)(L"Message sent to the DLL function\n");
        }
        // Free the DLL module.

        fFreeResult = FreeLibrary(sgxCryptoLib);
    }

    // If unable to call the DLL function, use an alternative.
    if (!fRunTimeLinkSuccess)
        printf("Message printed from executable\n");

    return 0;

}