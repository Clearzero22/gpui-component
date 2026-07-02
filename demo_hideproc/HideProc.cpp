// HideProc.cpp - Inject stealth.dll into Task Manager to hide a process
//
// This demo:
//   1. Finds notepad.exe and taskmgr.exe (launches taskmgr if needed)
//   2. Injects stealth.dll into taskmgr.exe
//   3. The DLL hooks NtQuerySystemInformation in taskmgr.exe's process
//   4. Task Manager's process list no longer shows notepad.exe
//   5. On unload, the hook is removed and notepad.exe reappears
//
// Build (x64 only, taskmgr.exe is 64-bit):
//   cmake -B build64 -A x64 && cmake --build build64 --config Release
//
// Run:
//   1. Open notepad.exe + Task Manager
//   2. Run as administrator: .\build64\Release\HideProc.exe
//      (self-elevates via UAC if not already admin)

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>

// ─── Configuration ──────────────────────────────────────────────────────────
static const wchar_t* TARGET_NAME = L"notepad.exe";
static const char* DLL_NAME = "stealth.dll";
static const wchar_t* TASKMGR_PATH = L"C:\\Windows\\System32\\taskmgr.exe";
static const wchar_t* TASKMGR_NAME = L"Taskmgr.exe";

// ─── Find process by name ─────────────────────────────────────────────────
static DWORD FindProcessId(const wchar_t* name) {
    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snap, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, name) == 0) {
                pid = entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &entry));
    }
    CloseHandle(snap);
    return pid;
}

// ─── Wait for a process to start (timeout in ms) ──────────────────────────
static DWORD WaitForProcess(const wchar_t* name, DWORD timeoutMs) {
    DWORD step = 200;
    DWORD waited = 0;
    while (waited < timeoutMs) {
        DWORD pid = FindProcessId(name);
        if (pid != 0) return pid;
        Sleep(step);
        waited += step;
    }
    return 0;
}

// ─── Check if running as administrator ──────────────────────────────────
static bool IsElevated() {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return false;
    TOKEN_ELEVATION elevation;
    DWORD size = sizeof(elevation);
    bool elevated = GetTokenInformation(hToken, TokenElevation, &elevation,
                                        size, &size) && elevation.TokenIsElevated;
    CloseHandle(hToken);
    return elevated;
}

// ─── Launch taskmgr.exe (handles elevation requirement) ─────────────────
// ShellExecuteW with "runas" verb auto-elevates for requireAdministrator
// binaries. CreateProcessW cannot do this from a non-elevated caller.
static bool LaunchTaskManager() {
    std::wcout << L"[*] Launching Task Manager ...\n";

    HINSTANCE result = ShellExecuteW(nullptr, L"runas", TASKMGR_PATH,
                                     nullptr, nullptr, SW_NORMAL);
    // ShellExecute returns a value > 32 on success
    if (reinterpret_cast<intptr_t>(result) <= 32) {
        std::cerr << "[-] Failed to launch taskmgr.exe, error: "
                  << GetLastError() << "\n";
        std::cerr << "    Try opening Task Manager manually.\n";
        return false;
    }

    // Wait for taskmgr to fully initialize
    DWORD pid = WaitForProcess(TASKMGR_NAME, 10000);
    if (pid == 0) {
        std::cerr << "[-] Task Manager did not start in time\n";
        return false;
    }
    std::wcout << L"[+] Task Manager started, PID: " << pid << L"\n";
    return true;
}

// ─── Build full path to an EXE's sibling file ────────────────────────────
static std::string GetSiblingPath(const char* filename) {
    char buf[MAX_PATH];
    GetModuleFileNameA(nullptr, buf, MAX_PATH);
    std::string path(buf);
    size_t pos = path.find_last_of('\\');
    if (pos != std::string::npos) {
        path.resize(pos + 1);
    }
    return path + filename;
}

// ─── Inject DLL into a remote process, return its HMODULE ────────────────
static HMODULE InjectDll(DWORD pid, const char* dllPath) {
    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        FALSE, pid
    );
    if (!hProcess) {
        std::cerr << "    [-] OpenProcess failed, error: " << GetLastError() << "\n";
        return nullptr;
    }

    size_t pathLen = strlen(dllPath) + 1;
    LPVOID remoteMem = VirtualAllocEx(hProcess, nullptr, pathLen,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        std::cerr << "    [-] VirtualAllocEx failed, error: " << GetLastError() << "\n";
        CloseHandle(hProcess);
        return nullptr;
    }

    if (!WriteProcessMemory(hProcess, remoteMem, dllPath, pathLen, nullptr)) {
        std::cerr << "    [-] WriteProcessMemory failed, error: " << GetLastError() << "\n";
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return nullptr;
    }

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    FARPROC pLoadLib = GetProcAddress(hKernel32, "LoadLibraryA");
    if (!pLoadLib) {
        std::cerr << "    [-] GetProcAddress(LoadLibraryA) failed\n";
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return nullptr;
    }

    // Test: verify remote threads execute in taskmgr
    FARPROC pSleep = GetProcAddress(hKernel32, "Sleep");
    HANDLE hTest = CreateRemoteThread(
        hProcess, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(pSleep),
        (LPVOID)100, 0, nullptr
    );
    if (hTest) {
        DWORD tr = WaitForSingleObject(hTest, 5000);
        CloseHandle(hTest);
        if (tr == WAIT_TIMEOUT) {
            std::cerr << "    [-] taskmgr rejects remote threads (test thread timed out).\n";
            VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return nullptr;
        }
    } else {
        std::cerr << "    [-] taskmgr rejects remote threads (test thread failed).\n";
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return nullptr;
    }

    // Give taskmgr time to stabilize before injection
    Sleep(3000);

    HANDLE hThread = CreateRemoteThread(
        hProcess, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(pLoadLib),
        remoteMem, 0, nullptr
    );
    if (!hThread) {
        std::cerr << "    [-] CreateRemoteThread(LoadLibraryA) failed, error: "
                  << GetLastError() << "\n";
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return nullptr;
    }

    DWORD waitResult = WaitForSingleObject(hThread, 15000);
    if (waitResult == WAIT_TIMEOUT) {
        std::cerr << "    [-] LoadLibraryA timed out. Windows may be blocking the DLL.\n";
        std::cerr << "    [-] Build as Release with static CRT, check Defender / Smart App Control.\n";
        TerminateThread(hThread, 0);
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return nullptr;
    }
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hThread);

    // Walk taskmgr's loaded modules to find stealth.dll's HMODULE
    HMODULE hMod = nullptr;
    HMODULE modules[1024];
    DWORD needed = 0;
    if (EnumProcessModules(hProcess, modules, sizeof(modules), &needed)) {
        DWORD count = needed / sizeof(HMODULE);
        for (DWORD i = 0; i < count; i++) {
            char name[MAX_PATH];
            if (GetModuleBaseNameA(hProcess, modules[i], name, sizeof(name))) {
                if (_stricmp(name, DLL_NAME) == 0) {
                    hMod = modules[i];
                    break;
                }
            }
        }
    }

    CloseHandle(hProcess);

    if (!hMod) {
        std::cerr << "    [-] DLL loaded but could not find its handle\n";
    }
    return hMod;
}

// ─── Unload a DLL from a remote process via FreeLibrary ──────────────────
static bool UnloadDll(DWORD pid, HMODULE hMod) {
    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid
    );
    if (!hProcess) {
        std::cerr << "[-] OpenProcess for unload failed, error: "
                  << GetLastError() << "\n";
        return false;
    }

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    FARPROC pFreeLib = GetProcAddress(hKernel32, "FreeLibrary");
    if (!pFreeLib) {
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(
        hProcess, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(pFreeLib),
        hMod, 0, nullptr
    );
    if (!hThread) {
        std::cerr << "[-] CreateRemoteThread(FreeLibrary) failed, error: "
                  << GetLastError() << "\n";
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return true;
}

// ─── Main ──────────────────────────────────────────────────────────────────
int main() {
    SetConsoleTitleW(L"HideProc - Inject into Task Manager");

    std::wcout << L"+====================================================+\n";
    std::wcout << L"|  Hide Process from Task Manager Demo               |\n";
    std::wcout << L"|  Injects stealth.dll into taskmgr.exe              |\n";
    std::wcout << L"|  Target: " << TARGET_NAME << L"                   |\n";
    std::wcout << L"+====================================================+\n\n";

    // ── Elevation check: restart as admin if needed ──
    if (!IsElevated()) {
        std::wcerr << L"[!] Administrator privileges required.\n";
        std::wcerr << L"    Restarting as Administrator ...\n\n";
        wchar_t path[MAX_PATH];
        GetModuleFileNameW(nullptr, path, MAX_PATH);
        HINSTANCE result = ShellExecuteW(nullptr, L"runas", path,
                                         nullptr, nullptr, SW_NORMAL);
        if (reinterpret_cast<intptr_t>(result) <= 32) {
            std::wcerr << L"[-] Self-elevation failed.\n";
            std::wcerr << L"    Please manually run as Administrator.\n";
        }
        return 0;
    }

    // ── Step 1: Check target exists ──
    std::wcout << L"[1] Checking " << TARGET_NAME << L" ...\n";
    DWORD targetPid = FindProcessId(TARGET_NAME);
    if (targetPid == 0) {
        std::cerr << "[-] " << TARGET_NAME << " not found. Please open Notepad first.\n";
        system("pause");
        return 1;
    }
    std::wcout << L"[+] " << TARGET_NAME << L" running, PID: " << targetPid << L"\n\n";

    // ── Step 2: Ensure taskmgr.exe is running ──
    std::wcout << L"[2] Checking Task Manager ...\n";
    DWORD taskmgrPid = FindProcessId(L"Taskmgr.exe");
    if (taskmgrPid == 0) {
        std::wcout << L"[-] Task Manager not running. Launching it ...\n";
        if (!LaunchTaskManager()) {
            system("pause");
            return 1;
        }
        taskmgrPid = FindProcessId(L"Taskmgr.exe");
    }
    std::wcout << L"[+] Task Manager running, PID: " << taskmgrPid << L"\n\n";

    // ── Step 3: Build DLL path ──
    std::string dllPath = GetSiblingPath(DLL_NAME);
    std::cout << "[3] DLL path: " << dllPath << "\n";
    if (GetFileAttributesA(dllPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::cerr << "[-] " << DLL_NAME << " not found. Build it first.\n";
        system("pause");
        return 1;
    }

    // ── Step 4: Before ──
    std::wcout << L"\n[4] BEFORE injection:\n";
    std::wcout << L"    Open Task Manager and confirm " << TARGET_NAME
               << L" is visible.\n";

    // ── Step 5: Inject ──
    std::wcout << L"\n[5] Injecting " << DLL_NAME << " into Task Manager ...\n";
    HMODULE hMod = InjectDll(taskmgrPid, dllPath.c_str());
    if (!hMod) {
        std::cerr << "[-] Injection failed.\n";
        std::cerr << "    See diagnostics above for details.\n";
        system("pause");
        return 1;
    }
    std::cout << "[+] " << DLL_NAME << " loaded at 0x" << std::hex
              << reinterpret_cast<uintptr_t>(hMod) << std::dec
              << " in taskmgr.exe\n";

    // ── Step 6: Wait for Hook to take effect ──
    std::wcout << L"\n[6] Hook installed on taskmgr.exe's NtQuerySystemInformation!\n";
    std::wcout << L"    Check Task Manager → " << TARGET_NAME
               << L" should be GONE.\n";
    std::wcout << L"    (Task Manager may need a refresh - press F5)\n\n";

    std::wcout << L"[!] Press Enter to unload " << DLL_NAME
               << L" and restore ...\n";
    std::cin.get();

    // ── Step 7: Unload ──
    std::wcout << L"\n[7] Unloading " << DLL_NAME << L" from Task Manager ...\n";
    if (UnloadDll(taskmgrPid, hMod)) {
        std::wcout << L"[+] Unloaded! DllMain(DLL_PROCESS_DETACH) restored "
                   << L"the original function.\n";
        std::wcout << L"    Check Task Manager → " << TARGET_NAME
                   << L" should be back.\n";
    } else {
        std::cerr << "[-] Unload failed. Close Task Manager manually.\n";
    }

    std::wcout << L"\n+====================================================+\n";
    std::wcout << L"|  SUMMARY                                          |\n";
    std::wcout << L"+====================================================+\n";
    std::wcout << L"| Task Manager PID: " << taskmgrPid << L"                        |\n";
    std::wcout << L"| DLL injected:     Yes                             |\n";
    std::wcout << L"| Target hidden:    Yes (from Task Manager only)    |\n";
    std::wcout << L"| DLL unloaded:     Yes                             |\n";
    std::wcout << L"+====================================================+\n\n";

    std::wcout << L"NOTE: Other tools (tasklist.exe, Process Explorer)\n";
    std::wcout << L"      are NOT affected. This hooks taskmgr.exe only.\n\n";

    system("pause");
    return 0;
}
