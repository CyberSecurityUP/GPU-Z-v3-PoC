// ioctl_scan.c  — mapeia IOCTLs de \\\\.\\GPU-Z-v3
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <stdio.h>

static inline DWORD CTL_CODE32(DWORD devType, DWORD func, DWORD method, DWORD access) {
    return (devType<<16) | (access<<14) | (func<<2) | method;
}

int wmain() {
    HANDLE h = CreateFileW(L"\\\\.\\GPU-Z-v3",
                           GENERIC_READ|GENERIC_WRITE,   // admin
                           FILE_SHARE_READ|FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        wprintf(L"open fail: %lu\n", GetLastError());
        return 1;
    }

    BYTE inTiny[16] = {0}, outTiny[256] = {0};
    DWORD dev = 0x22; // FILE_DEVICE_UNKNOWN
    DWORD hits = 0;

    for (DWORD func = 0; func < 0x1000; ++func) {         // 0..4095
        for (DWORD method = 0; method < 4; ++method) {    // 0..3
            for (DWORD access = 0; access < 4; ++access) {// ANY, READ, WRITE, RW
                DWORD code = CTL_CODE32(dev, func, method, access);
                DWORD ret = 0;
                BOOL ok = DeviceIoControl(h, code,
                                          inTiny, sizeof(inTiny),
                                          outTiny, sizeof(outTiny),
                                          &ret, NULL);
                if (ok || GetLastError() != ERROR_INVALID_FUNCTION) {
                    wprintf(L"[IOCTL] code=0x%08X func=%4lu meth=%lu acc=%lu -> ok=%d gle=%lu out=%lu\n",
                            code, func, method, access, ok, GetLastError(), ret);
                    ++hits;
                }
            }
        }
    }
    wprintf(L"\nTotal candidatos: %lu\n", hits);
    CloseHandle(h);
    return 0;
}
