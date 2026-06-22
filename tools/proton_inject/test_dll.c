#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    (void)hinstDLL; (void)lpvReserved;
    if (fdwReason == DLL_PROCESS_ATTACH) {
        HANDLE h = CreateFileA("Z:\\home\\deck\\.sls_dll_loaded.txt",
                               GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            const char msg[] = "SLSsteam DLL injection test OK\r\n";
            DWORD written;
            WriteFile(h, msg, sizeof(msg) - 1, &written, NULL);
            CloseHandle(h);
        }
    }
    return TRUE;
}
