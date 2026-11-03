#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <string.h>

typedef unsigned long long u64;
typedef unsigned char u8;
#define MAX_PATTERN_BYTES 128
#define MAX_AOB_RESULTS 100

struct Patch {
    u64 offset;
    u8 expect;
    u8 bytes;
};

struct PatchAOB {
    u8 pattern[MAX_PATTERN_BYTES];
    SIZE_T pattern_len;
    SIZE_T offset;
    u8 expect;
    u8 bytes;
};

struct Version {
    const Patch* patches;
    SIZE_T patch_count;
};

BOOL GetModuleInfo(DWORD pid, const wchar_t* moduleName, u64* base, SIZE_T* size) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return FALSE;
    MODULEENTRY32W me; me.dwSize = sizeof(me);
    BOOL found = FALSE;
    if (Module32FirstW(snap, &me)) {
        do {
            if (_wcsicmp(me.szModule, moduleName) == 0) {
                if (base) *base = (u64)me.modBaseAddr;
                if (size) *size = me.modBaseSize;
                found = TRUE;
                break;
            }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return found;
}

BOOL ReadAndCompareByte(HANDLE hProc, u64 addr, u8 expected) {
    u8 buf = 0; SIZE_T rd = 0;
    if (!ReadProcessMemory(hProc, (LPCVOID)addr, &buf, 1, &rd)) return FALSE;
    return rd == 1 && buf == expected;
}

BOOL WriteByte(HANDLE hProc, u64 addr, u8 data) {
    DWORD oldProt = 0;
    if (!VirtualProtectEx(hProc, (LPVOID)addr, 1, PAGE_EXECUTE_READWRITE, &oldProt))
        return FALSE;
    SIZE_T written = 0;
    BOOL ok = WriteProcessMemory(hProc, (LPVOID)addr, &data, 1, &written);
    VirtualProtectEx(hProc, (LPVOID)addr, 1, oldProt, &oldProt);
    return ok && written == 1;
}

BOOL PatchDirectAddresses(HANDLE hProc, u64 moduleBase, const Version* ver) {
    if (!ver) return FALSE;

    BOOL allAlreadyApplied = TRUE;
    for (SIZE_T i = 0; i < ver->patch_count; ++i) {
        const Patch* p = &ver->patches[i];
        if (!ReadAndCompareByte(hProc, moduleBase + p->offset, p->bytes)) {
            allAlreadyApplied = FALSE;
            break;
        }
    }
    if (allAlreadyApplied) return TRUE;

    for (SIZE_T i = 0; i < ver->patch_count; ++i) {
        const Patch* p = &ver->patches[i];
        if (!ReadAndCompareByte(hProc, moduleBase + p->offset, p->expect)) return FALSE;
    }

    for (SIZE_T i = 0; i < ver->patch_count; ++i) {
        const Patch* p = &ver->patches[i];
        if (!WriteByte(hProc, moduleBase + p->offset, p->bytes)) return FALSE;
    }
    return TRUE;
}

struct AOBResults {
    u64* results;
    SIZE_T count;
};

AOBResults AOBScanBuffer(const u8* buffer, SIZE_T size, u64 base,
                         const u8* pattern, SIZE_T pattern_len) {
    AOBResults results = {0};
    if (!buffer || size < pattern_len || pattern_len == 0 || pattern_len > MAX_PATTERN_BYTES)
        return results;

    SIZE_T cap = 4;
    results.results = (u64*)LocalAlloc(LPTR, cap * sizeof(u64));
    if (!results.results) return results;

    const u8* bufEnd = buffer + size;
    const u8* lastStart = bufEnd - pattern_len;
    const u8 first = pattern[0];
    const u8* p = buffer;

    while (p <= lastStart) {
        const u8* hit = (const u8*)memchr(p, first, (SIZE_T)(lastStart - p) + 1);
        if (!hit) break;

        BOOL match = TRUE;
        for (SIZE_T j = 1; j < pattern_len; j++) {
            if (pattern[j] != 0xCC && hit[j] != pattern[j]) { match = FALSE; break; }
        }
        if (match) {
            if (results.count == cap) {
                if (cap >= MAX_AOB_RESULTS) break;
                SIZE_T newCap = cap * 2;
                if (newCap > MAX_AOB_RESULTS) newCap = MAX_AOB_RESULTS;
                u64* grown = (u64*)LocalAlloc(LPTR, newCap * sizeof(u64));
                if (!grown) break;
                RtlCopyMemory(grown, results.results, results.count * sizeof(u64));
                LocalFree(results.results);
                results.results = grown;
                cap = newCap;
            }
            results.results[results.count++] = base + (u64)(hit - buffer);
        }
        p = hit + 1;
    }

    if (results.count == 0) { LocalFree(results.results); results.results = NULL; }
    return results;
}

void FreeAOBResults(AOBResults* results) {
    if (results && results->results) {
        LocalFree(results->results);
        results->results = NULL;
        results->count = 0;
    }
}

static void ToggleProcessThreads(HANDLE hProcess, BOOL suspend) {
    DWORD pid = GetProcessId(hProcess);
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;
    THREADENTRY32 te; te.dwSize = sizeof(te);
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (hThread) {
                    if (suspend) SuspendThread(hThread);
                    else         ResumeThread(hThread);
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
}

void SuspendProcess(HANDLE hProcess) { ToggleProcessThreads(hProcess, TRUE); }
void ResumeProcess(HANDLE hProcess)  { ToggleProcessThreads(hProcess, FALSE); }

static const u8 aob_pattern[] = {
    0x48, 0x8B, 0x0D, 0xCC, 0xCC, 0xCC, 0xCC, 0x83, 0xB9, 0xE4, 0x00, 0x00, 0x00, 0x00, 0x75, 0x0C,
    0xE8, 0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0x8B, 0x0D, 0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0x8B, 0x81, 0xB8,
    0x00, 0x00, 0x00, 0x83, 0x38, 0x01, 0x74, 0x1E, 0x83, 0xB9, 0xE4, 0x00, 0x00, 0x00, 0x00, 0x75,
    0x05, 0xE8, 0xCC, 0xCC, 0xCC, 0xCC, 0x33, 0xD2, 0xB9, 0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0x83, 0xC4,
    0x28, 0xE9, 0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0x83, 0xC4, 0x28, 0xC3
};
static const SIZE_T aob_pattern_len = sizeof(aob_pattern);

//filled below, to avoid duplication, pattern_len, offset 0x39 (decimal 57), expect, bytes (patch)
static const PatchAOB aob_patch = { {0}, 0, 0x39, 0x01, 0x08 };

void FallbackAOB(HANDLE hProc, u64 moduleBase, SIZE_T moduleSize) {
    if (!moduleSize) return;
    SuspendProcess(hProc);

    u8* buffer = (u8*)LocalAlloc(LMEM_FIXED, moduleSize);
    if (buffer) {
        SIZE_T bytesRead = 0;
        if (ReadProcessMemory(hProc, (LPCVOID)moduleBase, buffer, moduleSize, &bytesRead)
            && bytesRead >= aob_pattern_len) {
            AOBResults results = AOBScanBuffer(buffer, bytesRead, moduleBase,
                                               aob_pattern, aob_pattern_len);
            for (SIZE_T j = 0; j < results.count; j++) {
                u64 addr = results.results[j] + aob_patch.offset;
                if (ReadAndCompareByte(hProc, addr, aob_patch.bytes)) continue;
                if (ReadAndCompareByte(hProc, addr, aob_patch.expect)) {
                    WriteByte(hProc, addr, aob_patch.bytes);
                }
            }
            FreeAOBResults(&results);
        }
        LocalFree(buffer);
    }

    ResumeProcess(hProc);
}

static const Patch patches_v0_0_10[] = { { 0x54494EULL, 0x01, 0x08 } };
static const Patch patches_v0_0_11[] = { { 0x67B9EEULL, 0x01, 0x08 } };
static const Patch patches_v0_0_12[] = { { 0x6C863EULL, 0x01, 0x08 } };
static const Patch patches_v0_0_13[] = { { 0x6D28CEULL, 0x01, 0x08 } };

static const Version versions[] = {
    { patches_v0_0_10, sizeof(patches_v0_0_10) / sizeof(patches_v0_0_10[0]) },
    { patches_v0_0_11, sizeof(patches_v0_0_11) / sizeof(patches_v0_0_11[0]) },
    { patches_v0_0_12, sizeof(patches_v0_0_12) / sizeof(patches_v0_0_12[0]) },
    { patches_v0_0_13, sizeof(patches_v0_0_13) / sizeof(patches_v0_0_13[0]) }
};
static const SIZE_T versions_count = sizeof(versions) / sizeof(versions[0]);

int WINAPI wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance,
                    _In_ PWSTR lpCmdLine, _In_ int nShowCmd) {
    WCHAR selfDir[MAX_PATH] = {};
    DWORD len = GetModuleFileNameW(NULL, selfDir, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) return 1;
    WCHAR* lastSlash = wcsrchr(selfDir, L'\\');
    if (!lastSlash) return 1;
    *lastSlash = L'\0';

    const WCHAR* exeName = L"Swords & Slippers Patreon.exe";

    WCHAR gamePath[MAX_PATH] = {};
    const WCHAR* sep = L"\\";
    if (lstrlenW(selfDir) + lstrlenW(sep) + lstrlenW(exeName) >= MAX_PATH)
        return 1;
    lstrcpyW(gamePath, selfDir);
    lstrcatW(gamePath, sep);
    lstrcatW(gamePath, exeName);

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(gamePath, NULL, NULL, NULL, FALSE, 0, NULL, selfDir, &si, &pi)) {
        char msg[256];
        wsprintfA(msg, "Failed to start %ls", exeName);
        MessageBoxA(NULL, msg, "Launcher", MB_OK | MB_ICONERROR);
        return 1;
    }

    DWORD pid = GetProcessId(pi.hProcess);

    u64 base = 0;
    SIZE_T moduleSize = 0;
    int waited = 0;
    const int maxWait = 30000, step = 250;
    while (waited < maxWait) {
        if (WaitForSingleObject(pi.hProcess, 0) == WAIT_OBJECT_0) break;
        if (GetModuleInfo(pid, L"GameAssembly.dll", &base, &moduleSize)) break;
        Sleep(step); waited += step;
    }
    if (!base) { CloseHandle(pi.hProcess); CloseHandle(pi.hThread); return 1; }

    HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) {
        MessageBoxA(NULL, "Failed to access game process", "Launcher", MB_OK | MB_ICONERROR);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 1;
    }

    BOOL applied = FALSE;
    for (SIZE_T i = 0; i < versions_count; ++i) {
        if (PatchDirectAddresses(hProc, base, &versions[i])) { applied = TRUE; break; }
    }

    if (!applied) {
        FallbackAOB(hProc, base, moduleSize);
    }

    CloseHandle(hProc);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}