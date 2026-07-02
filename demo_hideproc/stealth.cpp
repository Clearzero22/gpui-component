// stealth.cpp - Inline Hook DLL
// Hooks NtQuerySystemInformation to hide a target process.
// NOTE: The hook only affects the PROCESS THAT LOADS THIS DLL.
//       It does NOT affect Task Manager or other processes.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <string>

// ─── Configuration (change this to hide a different process) ────────────────
static const wchar_t* TARGET_NAME = L"notepad.exe";

// ─── NtQuerySystemInformation function pointer type ─────────────────────────
typedef NTSTATUS(WINAPI* NtQuerySystemInfoFn)(
    ULONG SystemInfoClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

// Address of the real NtQuerySystemInformation in this process
static NtQuerySystemInfoFn RealNtQuerySystemInfo = nullptr;

// Saved original bytes (for unhooking + recursive-safe calls)
static BYTE OriginalBytes[5] = { 0 };

// SystemProcessInformation enum value is already defined in winternl.h

// ─── Forward declaration ───────────────────────────────────────────────────
static NTSTATUS WINAPI HookedNtQuerySystemInformation(
    ULONG SystemInfoClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

// ─── Safely call the REAL NtQuerySystemInformation even while hooked ───────
// Temporarily restores original bytes, calls the function, then re-hooks.
// NOT thread-safe, but fine for a single-threaded demo.
static NTSTATUS CallRealNtQuerySystemInfo(
    ULONG SystemInfoClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
) {
    DWORD oldProtect = 0;
    VirtualProtect(RealNtQuerySystemInfo, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(RealNtQuerySystemInfo, OriginalBytes, 5);
    FlushInstructionCache(GetCurrentProcess(), RealNtQuerySystemInfo, 5);

    NTSTATUS status = RealNtQuerySystemInfo(
        SystemInfoClass,
        SystemInformation,
        SystemInformationLength,
        ReturnLength
    );

    // Re-apply hook
    intptr_t hookAddr = reinterpret_cast<intptr_t>(HookedNtQuerySystemInformation);
    intptr_t origAddr = reinterpret_cast<intptr_t>(RealNtQuerySystemInfo);
    intptr_t offset = hookAddr - origAddr - 5;
    BYTE jmpCode[5] = { 0xE9 };
    memcpy(&jmpCode[1], &offset, sizeof(offset));
    memcpy(RealNtQuerySystemInfo, jmpCode, 5);
    VirtualProtect(RealNtQuerySystemInfo, 5, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), RealNtQuerySystemInfo, 5);

    return status;
}

// ─── Hook function ─────────────────────────────────────────────────────────
// Called instead of the real NtQuerySystemInformation when hook is active.
// Calls the real function, then removes TARGET_NAME from the results.
static NTSTATUS WINAPI HookedNtQuerySystemInformation(
    ULONG SystemInfoClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
) {
    NTSTATUS status = CallRealNtQuerySystemInfo(
        SystemInfoClass, SystemInformation,
        SystemInformationLength, ReturnLength
    );

    if (SystemInfoClass != SystemProcessInformation || status != 0)
        return status;

    BYTE* current = static_cast<BYTE*>(SystemInformation);
    BYTE* prev = nullptr;

    while (true) {
        auto* spi = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(current);
        std::wstring name;

        if (spi->ImageName.Buffer && spi->ImageName.Length > 0) {
            name.assign(spi->ImageName.Buffer, spi->ImageName.Length / sizeof(wchar_t));
        }

        if (!name.empty() && name.find(TARGET_NAME) != std::wstring::npos) {
            if (spi->NextEntryOffset != 0) {
                BYTE* src = current + spi->NextEntryOffset;
                SIZE_T remaining = reinterpret_cast<BYTE*>(SystemInformation) +
                                   SystemInformationLength - src;
                MoveMemory(current, src, remaining);
                continue;
            } else if (prev != nullptr) {
                reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(prev)->NextEntryOffset = 0;
                break;
            } else {
                reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(current)->NextEntryOffset = 0;
                break;
            }
        }

        if (spi->NextEntryOffset == 0) break;
        prev = current;
        current += spi->NextEntryOffset;
    }

    return status;
}

// ─── Install the inline hook ───────────────────────────────────────────────
extern "C" __declspec(dllexport) bool InstallHook() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return false;

    RealNtQuerySystemInfo = reinterpret_cast<NtQuerySystemInfoFn>(
        GetProcAddress(ntdll, "NtQuerySystemInformation")
    );
    if (!RealNtQuerySystemInfo) {
        return false;
    }

    memcpy(OriginalBytes, RealNtQuerySystemInfo, 5);

    intptr_t hookAddr = reinterpret_cast<intptr_t>(HookedNtQuerySystemInformation);
    intptr_t origAddr = reinterpret_cast<intptr_t>(RealNtQuerySystemInfo);
    intptr_t offset = hookAddr - origAddr - 5;

    if (offset > 0x7FFFFFFFLL || offset < -0x80000000LL) {
        return false;
    }

    DWORD oldProtect = 0;
    if (!VirtualProtect(RealNtQuerySystemInfo, 5,
                        PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return false;
    }

    BYTE jmpCode[5] = { 0xE9 };
    memcpy(&jmpCode[1], &offset, sizeof(offset));
    memcpy(RealNtQuerySystemInfo, jmpCode, 5);

    VirtualProtect(RealNtQuerySystemInfo, 5, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), RealNtQuerySystemInfo, 5);
    return true;
}

// ─── Remove the hook (restore original code) ───────────────────────────────
extern "C" __declspec(dllexport) void UninstallHook() {
    if (!RealNtQuerySystemInfo) return;

    DWORD oldProtect = 0;
    VirtualProtect(RealNtQuerySystemInfo, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(RealNtQuerySystemInfo, OriginalBytes, 5);
    VirtualProtect(RealNtQuerySystemInfo, 5, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), RealNtQuerySystemInfo, 5);
}

// ─── DLL entry point ───────────────────────────────────────────────────────
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        if (!InstallHook()) {
            return FALSE;
        }
        break;
    case DLL_PROCESS_DETACH:
        if (lpReserved == nullptr) {
            UninstallHook();
        }
        break;
    }
    return TRUE;
}
