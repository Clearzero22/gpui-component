# Windows Inline Hook 进程隐藏 — 完整技术文档

## 概述

通过 Inline Hook 技术隐藏进程的 Windows 演示项目。运行时修改 `ntdll.dll` 中
`NtQuerySystemInformation` 的函数代码，使其在返回进程列表时移除目标进程
（notepad.exe），从而让任务管理器无法看到它。

```

                            用户视角
    ┌──────────────────────────────────────────────────────────┐
    │      任务管理器 (taskmgr.exe)                            │
    │      进程列表: [system, svchost, ...]                    │
    │      不包含: notepad.exe  ← 被我们的 Hook 过滤了         │
    └──────────────────────┬───────────────────────────────────┘
                           │ 调用 NtQuerySystemInformation
                           ▼
                    ┌──────────────┐
                    │   Hook 函数   │ ← 5 字节 JMP 指向这里
                    │   过滤结果     │
                    └──────┬───────┘
                           │ 调用真实函数
                           ▼
                    ┌──────────────┐
                    │ ntdll.dll    │
                    │ NtQuerySystem│
                    │ Information  │
                    └──────────────┘
```

---

## 一、架构

### 组件

| 组件 | 职责 |
|------|------|
| `HideProc.exe` | 注入器 — 自提权、发现 taskmgr、注入 DLL、卸载 DLL |
| `stealth.dll` | Hook DLL — DllMain 自动安装/卸载 `NtQuerySystemInformation` 的 Inline Hook |

### 执行流程

```
用户 → 打开 notepad.exe + taskmgr.exe
                        │
                  HideProc.exe (管理员)
                        │
             ┌──────────┴───────────┐
             │  1. 权限检查          │ ← 非管理员 → ShellExecuteW("runas") 自提权
             │  2. 检查目标进程       │ ← FindProcessId("notepad.exe")
             │  3. 检查/启动 taskmgr │ ← 未运行 → ShellExecuteW("runas")
             └──────────┬───────────┘
                        │
             ┌──────────┴────────────────────────────────────┐
             │  4. 注入 stealth.dll (InjectDll)              │
             │                                               │
             │   a. OpenProcess → 打开 taskmgr 进程句柄      │
             │   b. VirtualAllocEx → 在 taskmgr 中分配内存   │
             │   c. WriteProcessMemory → 写入 DLL 路径       │
             │   d. 诊断: Sleep(100) 测试远程线程是否可用     │
             │   e. Sleep(3000) → 等待 taskmgr 稳定          │
             │   f. CreateRemoteThread(LoadLibraryA)          │
             │          ↓                                    │
             │      taskmgr.exe 内部:                        │
             │        DllMain(DLL_PROCESS_ATTACH)             │
             │          ↓                                    │
             │        InstallHook() — 写入 JMP 到 ntdll      │
             │          ↓                                    │
             │        Hook 激活, notepad.exe 被过滤           │
             │                                               │
             │   g. EnumProcessModules → 找到 HMODULE        │
             └──────────┬────────────────────────────────────┘
                        │
             ┌──────────┴───────────┐
             │  5. 用户确认          │ ← cin.get()
             │     notepad 已隐藏    │
             └──────────┬───────────┘
                        │
             ┌──────────┴───────────────────────────────────┐
             │  6. 卸载 (UnloadDll)                         │
             │    CreateRemoteThread(FreeLibrary, hModule)   │
             │         ↓                                    │
             │     taskmgr.exe 内部:                        │
             │       DllMain(DLL_PROCESS_DETACH)             │
             │         ↓                                    │
             │       UninstallHook() — 恢复原始 5 字节      │
             │         ↓                                    │
             │       Hook 移除, notepad.exe 恢复显示         │
             └──────────────────────────────────────────────┘
```

---

## 二、Inline Hook 原理

### Hook 安装

```
虚拟内存布局 (ntdll.dll 代码页):

  偏移   ┌─────────────────────────────────────────────────┐
  0x00   │ [48 89 5C 24 08]     mov [rsp+8], rbx           │  ← 原始: 函数序言
         │ [48 89 74 24 10]     mov [rsp+10], rsi           │
         │ [57]                 push rdi                    │
         │ ...                                              │
         └─────────────────────────────────────────────────┘

  安装后:
  偏移   ┌─────────────────────────────────────────────────┐
  0x00   │ [E9 xx xx xx xx]     jmp HookedFunction          │  ← 5 字节 JMP
         │ [48 89 74 24 10]     mov [rsp+10], rsi           │  ← 后续不变
         │ [57]                 push rdi                    │
         │ ...                                              │
         └─────────────────────────────────────────────────┘

  JMP 编码: 0xE9 + 4 字节有符号偏移
  offset = (intptr_t)HookedFunction - (intptr_t)RealFunction - 5
  必须满足: -2³¹ ≤ offset ≤ 2³¹-1（否则 Hook 失败）
```

### Hook 函数执行

```
HookedNtQuerySystemInformation(ulong SystemInfoClass, void* buf, ...)
│
├── 只处理 SystemProcessInformation 类 (0x05)
│   其他类 → 直接透传
│
├── 1. memcpy(RealFunction, OriginalBytes, 5)  // 临时恢复原始代码
├── 2. FlushInstructionCache(GetCurrentProcess(), RealFunction, 5)
│
├── 3. 调用真实 NtQuerySystemInformation(buf, ...)
│
├── 4. 遍历 SYSTEM_PROCESS_INFORMATION 链表:
│
│     [Entry1] → [Entry2] → [notepad.exe] → [Entry4] → ... → NULL
│                     │                         ↑
│               NextEntryOffset    │            │
│                                  ▼            │
│                           [Entry3]─────────────┘
│                           (被摘除)
│
│     for each entry in linked list:
│       if ImageName contains "notepad.exe":
│         if 不是尾节点:
│           src = current + NextEntryOffset
│           remaining = buffer_end - src
│           MoveMemory(current, src, remaining)  // 链表坍塌
│           continue  // 重新检查当前位置
│         else (尾节点):
│           prev->NextEntryOffset = 0  // 前一个变成尾节点
│
├── 5. 重新写入 JMP Hook (与安装时相同)
│
└── 6. FlushInstructionCache
```

### 防递归设计

直接在 Hook 函数内部调用真实函数会导致**无限递归**（因为真实函数入口已被 Hook 覆盖）。
解决方案：`CallRealNtQuerySystemInfo` 辅助函数。

```
CallRealNtQuerySystemInfo
│
├── VirtualProtect(PAGE_EXECUTE_READWRITE, &oldProtect)
├── memcpy(RealFunction, OriginalBytes, 5)   → 临时恢复
├── FlushInstructionCache
│
├── NTSTATUS = RealNtQuerySystemInfo(...)     → 安全调用真实函数
│
├── 计算 JMP offset (与安装时相同)
├── memcpy(RealFunction, jmpCode, 5)         → 重新 Hook
├── VirtualProtect(oldProtect)
└── FlushInstructionCache
```

---

## 三、跨进程注入

### CreateRemoteThread + LoadLibraryA 注入法

```
HideProc.exe (注入器)                    taskmgr.exe (目标)
       │                                        │
       │  1. OpenProcess                        │
       │     PROCESS_CREATE_THREAD              │
       │     PROCESS_VM_OPERATION               │
       │     PROCESS_VM_WRITE                   │
       │     PROCESS_VM_READ                    │
       │     PROCESS_QUERY_INFORMATION          │
       │──────────────────────────────────────→ │
       │                                        │
       │  2. VirtualAllocEx                     │
       │     MEM_COMMIT | MEM_RESERVE           │
       │     PAGE_READWRITE                     │
       │──────────────────────────────────────→ │
       │                                        │
       │  3. WriteProcessMemory(dllPath)        │
       │──────────────────────────────────────→ │
       │                                        │
       │  4. GetProcAddress(kernel32,           │
       │       "LoadLibraryA")                  │
       │       → 获取 LoadLibraryA 地址         │
       │       (kernel32 在所有进程中的         │
       │        基地址相同)                     │
       │                                        │
       │  5. CreateRemoteThread(LoadLibraryA,   │
       │       dllPath)                         │
       │──────────────────────────────────────→ │
       │                              LoadLibraryA("stealth.dll")
       │                                        │
       │                               ntdll!LdrLoadDll
       │                                        │
       │                               ┌────────┴────────┐
       │                               │  加载 DLL        │
       │                               │  解析导入表      │
       │                               │  调用 DllMain    │
       │                               └────────┬────────┘
       │                                        │
       │                                        │ InstallHook()
       │                                        │ → JMP 写入成功
       │                                        │
       │  WaitForSingleObject(hThread, 15s)  ← │ 线程退出
       │                                        │
       │  6. VirtualFreeEx(remoteMem)           │
       │     CloseHandle(hThread)               │
       │     CloseHandle(hProcess)              │
       │                                        │
       │  7. EnumProcessModules                 │
       │     → 找到 stealth.dll 的 HMODULE      │
       │                                        │
       │  [用户按 Enter 确认]                   │
       │                                        │
       │  8. CreateRemoteThread(FreeLibrary,    │
       │       hModule)                         │
       │──────────────────────────────────────→ │
       │                                        │ FreeLibrary(hModule)
       │                                        │
       │                               ┌────────┴────────┐
       │                               │  DllMain(DETACH)│
       │                               │  UninstallHook()│
       │                               └────────┬────────┘
       │                                        │
       │                                        │ 原始字节已恢复
       │                                        │ Hook 已移除
       │                                        │
       │  WaitForSingleObject ←─────────────── │ 线程退出
       │                                        │
```

### 为什么需要 EnumProcessModules

`CreateRemoteThread` 的线程入口是 `LoadLibraryA`（签名 `HMODULE WINAPI(LPCSTR)`），
但所有线程函数的返回值都被转换为 `DWORD`（32 位）。在 x64 Windows 上，`HMODULE` 是
64 位指针，其高 32 位在 `GetExitCodeThread` 返回值中丢失。

因此不能依靠线程退出码来获取模块句柄。改用 `EnumProcessModules` 遍历目标进程的
已加载模块列表，按名字匹配找到 stealth.dll 的正确 HMODULE。

---

## 四、开发问题与修复

### 问题 1：错误的目标进程（最初版本）

```
旧设计: Inject into notepad.exe → Hook notepad.exe's NtQuerySystemInformation
         → notepad.exe 自身看不到自己了
         → 但任务管理器不受影响

为什么无效: Hook 只影响它被加载到的那个进程。notepad.exe 的 Hook 不影响 taskmgr.exe。

修复: 改为注入 taskmgr.exe。
```

### 问题 2：启动 taskmgr.exe 失败（错误 740）

```
症状: CreateProcessW("C:\\Windows\\System32\\taskmgr.exe") 返回 ERROR_ELEVATION_REQUIRED

根因: taskmgr.exe 有 requireAdministrator 清单，CreateProcessW 不会自动提权。

修复: 改用 ShellExecuteW(nullptr, L"runas", path, ...)。
       "runas" 动词会触发 UAC 提权。
```

### 问题 3：OpenProcess 拒绝访问（错误 5）

```
症状: 从非管理员进程打开管理员进程时失败。

根因: Windows 的完整性级别 (Integrity Level) 机制。
      低完整性级别 → 高完整性级别 = 拒绝。

修复: 程序开始时检测完整性级别。
      非管理员 → ShellExecuteW("runas", self) 自提权重启。
```

### 问题 4：LoadLibrary 远程线程超时（核心问题）

```
症状: CreateRemoteThread(LoadLibraryA) 成功，但 WaitForSingleObject 超时 10 秒。
      诊断线程 Sleep(100) 正常执行，说明远程线程功能本身是好的。
      只有 LoadLibraryA 卡住了。

调查过程:
  - Debug 构建的 stealth.dll 链接了 msvcp140d.dll (Debug CRT)
  - 这个 DLL 只在 Visual Studio 安装目录下
  - taskmgr.exe 的 DLL 搜索路径不包括 VS 目录
  - LoadLibrary 在解析依赖时卡住

验证:
  - 构建 Release 版本 → 链接 msvcp140.dll (Release CRT) → 存在于 C:\Windows\System32
  - 仍然有问题？继续改静态 CRT (/MT)

最终修复:
  - Release 配置 + MSVC_RUNTIME_LIBRARY = "MultiThreaded" (/MT)
  - 所有 CRT 代码静态链接进 stealth.dll
  - 无运行时 DLL 依赖 → LoadLibrary 快速成功
```

### 问题 5：获取模块句柄错误

```
问题: LoadLibrary 在目标进程中的返回值被截断为 32 位。

修复: 用 EnumProcessModules 遍历目标进程的已加载模块列表，按名字匹配。

代码:
  HMODULE modules[1024];
  DWORD needed = 0;
  if (EnumProcessModules(hProcess, modules, sizeof(modules), &needed)) {
      for (DWORD i = 0; i < needed / sizeof(HMODULE); i++) {
          char name[MAX_PATH];
          GetModuleBaseNameA(hProcess, modules[i], name, sizeof(name));
          if (strcmp(name, "stealth.dll") == 0)
              hMod = modules[i];  // 找到正确的 64 位句柄
      }
  }
```

---

## 五、关键技术细节

### 5.1 SYSTEM_PROCESS_INFORMATION 链表

`NtQuerySystemInformation(SystemProcessInformation)` 返回的数据格式：

```c
typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;         // 到下一个条目的偏移，0 = 尾节点
    ULONG NumberOfThreads;         // 线程数
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;      // 进程名（如 notepad.exe）
    LONG BasePriority;
    HANDLE UniqueProcessId;        // PID
    HANDLE InheritedFromUniqueProcessId;  // 父 PID
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR PageDirectoryBase;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;
```

链表遍历：

```c
BYTE* current = (BYTE*)buffer;
while (true) {
    auto* spi = (SYSTEM_PROCESS_INFORMATION*)current;
    // 处理 spi
    if (spi->NextEntryOffset == 0) break;
    current += spi->NextEntryOffset;
}
```

### 5.2 链表摘除算法

移除中间节点：

```
Before:  [A] → [B] → [notepad] → [C] → [D]
                  │                    ↑
                  └──── NextEntryOffset ┘

1. src = notepad + notepad->NextEntryOffset  (指向 C)
2. remaining = buffer_end - src               (C + D 的大小)
3. MoveMemory(notepad, src, remaining)

After:   [A] → [B] → [C] → [D]
```

移除尾节点：

```
Before:  [A] → [B] → [C] → [notepad]

1. prev = C
2. C->NextEntryOffset = 0

After:   [A] → [B] → [C]
```

### 5.3 进程完整性级别

Windows Vista+ 的 Mandatory Integrity Control (MIC)：

| 完整性级别 | 名称 | SID |
|-----------|------|-----|
| 0x0000 | Untrusted | S-1-16-0 |
| 0x1000 | Low | S-1-16-4096 |
| 0x2000 | Medium | S-1-16-8192 |
| 0x3000 | High | S-1-16-12288 |
| 0x4000 | System | S-1-16-16384 |

规则：低完整性级别不能向高完整性级别进程写入。
管理员令牌可以启动提权（以管理员身份运行 → UAC → 高完整性）。

```
检查代码:
  HANDLE hToken;
  OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
  TOKEN_ELEVATION elevation;
  DWORD size = sizeof(elevation);
  GetTokenInformation(hToken, TokenElevation, &elevation, size, &size);
  bool elevated = elevation.TokenIsElevated;
```

### 5.4 诊断线程

在注入 LoadLibrary 前，先注入一个 `Sleep(100)` 线程来验证远程线程功能：

```
目的: 区分"taskmgr 拒绝执行远程线程"与"LoadLibrary 因 DLL 问题卡住"

过程:
  1. GetProcAddress(kernel32, "Sleep") → 函数地址（跨进程相同）
  2. CreateRemoteThread(Sleep, (LPVOID)100)
  3. WaitForSingleObject(5000)
     - WAIT_OBJECT_0 (正常返回): 线程执行成功，Sleep 了 100ms
     - WAIT_TIMEOUT: taskmgr 拒绝执行远程线程 → 放弃注入
     - 失败: taskmgr 拒绝创建远程线程 → 放弃注入
```

---

## 六、构建与运行

### 构建

```powershell
cd demo_hideproc

# 配置 CMake（x64）
cmake -B build64 -A x64

# 编译 Release 版本（必须 Release + 静态 CRT）
cmake --build build64 --config Release
```

`CMakeLists.txt` 关键配置：

```cmake
# stealth.dll 使用静态 CRT，消除运行时依赖
add_library(stealth SHARED stealth.cpp)
set_target_properties(stealth PROPERTIES
    MSVC_RUNTIME_LIBRARY "MultiThreaded"    # /MT
)

# HideProc.exe 需要 psapi.dll（EnumProcessModules）
add_executable(HideProc HideProc.cpp)
target_link_libraries(HideProc PRIVATE psapi)
```

### 运行

```powershell
# 1. 打开目标进程
notepad

# 2. 打开任务管理器（可选，程序可以自动启动）
taskmgr

# 3. 以管理员身份运行注入器
Start-Process -Verb RunAs "build64\Release\HideProc.exe"
```

### 预期输出

```
+====================================================+
|  Hide Process from Task Manager Demo               |
|  Injects stealth.dll into taskmgr.exe              |
|  Target: notepad.exe                               |
+====================================================+

[1] Checking notepad.exe ...
[+] notepad.exe running, PID: 12345

[2] Checking Task Manager ...
[+] Task Manager running, PID: 67890

[3] DLL path: E:\...\build64\Release\stealth.dll

[4] BEFORE injection:
    Open Task Manager and confirm notepad.exe is visible.

[5] Injecting stealth.dll into Task Manager ...
[+] stealth.dll loaded at 0x7ffb09a80000 in taskmgr.exe

[6] Hook installed on taskmgr.exe's NtQuerySystemInformation!
    Check Task Manager → notepad.exe should be GONE.
    (Task Manager may need a refresh - press F5)

[!] Press Enter to unload stealth.dll and restore ...

[7] Unloading stealth.dll from Task Manager ...
[+] Unloaded! DllMain(DLL_PROCESS_DETACH) restored the original function.
    Check Task Manager → notepad.exe should be back.
```

---

## 七、局限性与安全考量

### 技术局限

| 局限 | 原因 | 影响 |
|------|------|------|
| 只影响 taskmgr.exe | Hook 加载在 taskmgr.exe 的进程空间 | `tasklist.exe`、Process Explorer、WMI 不受影响 |
| 需要管理员权限 | VirtualProtect 修改 ntdll 代码页需要提权 | 普通用户无法运行 |
| 不适用于 PPL 进程 | Protected Process Light 禁止非签名模块注入 | 无法注入系统级保护进程（如 Windows Defender） |
| 单线程安全 | 临时恢复-再 Hook 模式 | 多线程同时调用可能触发竞态条件 |
| 可被 EDR 检测 | 修改 ntdll 代码页是常见恶意行为 | EDR 产品会告警或阻断 |
| 架构限制 | 必须 x64（taskmgr.exe 是 64 位） | 32 位注入器无法注入 64 位进程 |

### Windows 安全机制

可能阻止注入的 Windows 防护：

| 机制 | 影响 | 备注 |
|------|------|------|
| Smart App Control | 阻止未签名 DLL | Windows 11 新功能 |
| Windows Defender | 实时扫描未签名模块 | 可能增加加载延迟 |
| Process Mitigation Policy | 禁止远线程创建或未签名 DLL | 系统进程可能启用 |
| UAC / 完整性级别 | 限制跨完整性级别操作 | 需要管理员权限 |
| 内核补丁防护 (KPP) | 阻止内核级别 Hook | 本 Demo 是用户态 Hook，不受影响 |

---

## 八、代码结构

```
demo_hideproc/
├── CMakeLists.txt              # CMake 构建配置
├── HideProc.cpp                # 注入器主程序
│   ├── FindProcessId()         # 按名称查找进程 PID
│   ├── WaitForProcess()        # 等待进程出现（轮询）
│   ├── IsElevated()            # 检查是否管理员
│   ├── LaunchTaskManager()     # ShellExecute 启动 taskmgr
│   ├── GetSiblingPath()        # 获取同目录下文件路径
│   ├── InjectDll()             # 注入 DLL 到目标进程
│   ├── UnloadDll()             # 卸载目标进程中的 DLL
│   └── main()                  # 主流程编排
│
├── stealth.cpp                 # Inline Hook DLL
│   ├── OriginalBytes[]         # 保存原始 5 字节
│   ├── RealNtQuerySystemInfo   # 真实函数地址
│   ├── InstallHook()           # 安装 Inline Hook
│   ├── UninstallHook()         # 卸载 Inline Hook
│   ├── CallRealNtQuerySystemInfo()  # 安全调用真实函数
│   ├── HookedNtQuerySystemInformation()  # Hook 函数
│   └── DllMain()               # DLL 入口点
│
├── README.md                   # 快速入门
├── ARCHITECTURE.md             # 本文档
│
├── build/                      # x86 构建产物（排除）
└── build64/                    # x64 构建产物（排除）
```

---

## 九、扩展思路

### 注入其他进程

修改 `TARGET_NAME` 和注入目标即可：

| 场景 | 注入目标 | TARGET_NAME |
|------|---------|-------------|
| 隐藏 notepad.exe | taskmgr.exe | notepad.exe |
| 隐藏任意进程 | taskmgr.exe | 目标进程名 |
| 调试器绕过 | 调试器进程 | 被调试进程名 |
| 自保护 | 自身进程 | 目标进程名 |

### 替代注入方法

| 方法 | 说明 | 难度 |
|------|------|------|
| Shellcode 注入 | 手动调用 LdrLoadDll，不依赖 LoadLibrary | 高 |
| SetWindowsHookEx | 通过消息钩子注入 DLL | 中 |
| COM 注册 | 通过 COM 对象加载 DLL | 中 |
| AppInit_DLLs | 注册表全局 DLL 加载（已废弃） | 低 |
| 线程上下文劫持 | 挂起目标线程，修改 EIP 执行 shellcode | 高 |

### 更难被检测的技术

| 技术 | 规避检测 |
|------|---------|
| 直接系统调用 (syscall) | 绕过 ntdll Hook 检测 |
| 间接系统调用 | 混淆调用栈 |
| API 哈希 | 隐藏导入的 API |
| VEH Hook | 使用异常处理机制替代 JMP Hook |
| 硬件断点 Hook | 使用 DR0-DR3 调试寄存器 |
