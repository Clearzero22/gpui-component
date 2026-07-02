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

---

## 十、DLL 注入方式完全列表

### 10.1 总览

| # | 方法 | 原理 | 难度 | 检测难度 | 是否需要文件 | 适用场景 |
|---|------|------|------|---------|-------------|---------|
| 1 | **CreateRemoteThread + LoadLibrary** | 远线程调用 LoadLibraryA/W | ★☆☆☆☆ | ★☆☆☆☆ | 是 | 入门，教学 |
| 2 | **NtCreateThreadEx + LoadLibrary** | 底层 NT API 创建远线程 | ★★☆☆☆ | ★★☆☆☆ | 是 | 绕过 CreateRemoteThread 监控 |
| 3 | **RtlCreateUserThread + LoadLibrary** | 未文档化 NT API | ★★★☆☆ | ★★☆☆☆ | 是 | 某些 EDR 不监控此调用 |
| 4 | **SetWindowsHookEx** | 全局消息钩子自动注入 | ★★☆☆☆ | ★★☆☆☆ | 是 | GUI 进程，有消息循环 |
| 5 | **QueueUserAPC** | APC 注入到 alertable 线程 | ★★★☆☆ | ★★★☆☆ | 是 | 线程处于可唤醒状态 |
| 6 | **SetThreadContext** | 修改线程上下文 RIP 执行 shellcode | ★★★☆☆ | ★★★☆☆ | 否 | 绕过 LoadLibrary 检测 |
| 7 | **线程上下文劫持 (Context Stealing)** | 保存/恢复上下文 + shellcode | ★★★★☆ | ★★★☆☆ | 否 | 需要精确控制 |
| 8 | **AppInit_DLLs** | 注册表全局加载 | ★☆☆☆☆ | ★☆☆☆☆ | 是 | Win7 以下可用 |
| 9 | **KnownDLLs 劫持** | 替换 KnownDLLs 表 | ★★★☆☆ | ★★★★☆ | 是 | 全局影响，风险高 |
| 10 | **DLL 劫持 (DLL Hijacking)** | 利用搜索顺序加载恶意 DLL | ★★☆☆☆ | ★★☆☆☆ | 是 | 依赖目标进程加载顺序 |
| 11 | **DLL Side-Loading** | WinSxS / manifest 搜索顺序 | ★★★☆☆ | ★★★☆☆ | 是 | 需要特定系统配置 |
| 12 | **COM 劫持** | CLSID 注册加载 DLL | ★★★★☆ | ★★★★☆ | 是 | 需要 COM 知识 |
| 13 | **PE 注入** | 手动映射 PE 到目标进程 | ★★★★★ | ★★★★★ | 否 | 无文件落地 |
| 14 | **反射式 DLL 注入** | DLL 内嵌加载器自行加载 | ★★★★★ | ★★★★★ | 否 | 绕过模块加载回调 |
| 15 | **Process Hollowing** | 替换暂停进程的映像 | ★★★★☆ | ★★★☆☆ | 否 | 适用于无文件执行 |
| 16 | **AtomBombing** | 原子表传递 shellcode | ★★★★★ | ★★★★★ | 否 | 绕过 VirtualAllocEx 监控 |
| 17 | **ExtraWindowBytes** | 利用窗口额外字节存储 shellcode | ★★★★☆ | ★★★★☆ | 否 | 需要窗口句柄 |
| 18 | **断点注入 (Breakpoint Injection)** | 硬件断点触发异常 → VEH 执行 shellcode | ★★★★★ | ★★★★★ | 否 | 极其隐蔽 |

### 10.2 各方法详解

---

#### 1. CreateRemoteThread + LoadLibrary

**原理**：在目标进程中创建线程，线程入口为 kernel32!LoadLibraryA/W。

**实现**：
```cpp
HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
FARPROC pLoadLib = GetProcAddress(hKernel32, "LoadLibraryA");
LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, pathLen, MEM_COMMIT, PAGE_READWRITE);
WriteProcessMemory(hProcess, remoteMem, dllPath, pathLen, NULL);
HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
    (LPTHREAD_START_ROUTINE)pLoadLib, remoteMem, 0, NULL);
WaitForSingleObject(hThread, INFINITE);
```

**优点**：实现简单，稳定可靠，适合教学。
**缺点**：最容易被检测，几乎所有 EDR 都监控 CreateRemoteThread。

**检测规避**：
- 改用 `NtCreateThreadEx` 或 `RtlCreateUserThread`
- 恢复线程入口签名检查

---

#### 2. NtCreateThreadEx + LoadLibrary

**原理**：CreateRemoteThread 底层调用的是 `NtCreateThreadEx`。直接调用可绕过部分上层监控。

```cpp
typedef NTSTATUS(NTAPI* NtCreateThreadExFn)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG Flags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);
NtCreateThreadExFn NtCreateThreadEx = (NtCreateThreadExFn)
    GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
HANDLE hThread;
NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess,
    pLoadLib, remoteMem, 0, 0, 0, 0, NULL);
```

**优点**：可设置 `HIDE_FROM_DEBUGGER` 标志，更灵活。
**缺点**：仍然被许多 EDR 监控。

---

#### 3. RtlCreateUserThread + LoadLibrary

**原理**：另一个未公开的 NT API，位于 ntdll.dll 中。

```cpp
typedef NTSTATUS(NTAPI* RtlCreateUserThreadFn)(
    HANDLE Process,
    PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
    BOOLEAN CreateSuspended,
    ULONG ZeroBits,
    SIZE_T MaximumStackSize,
    SIZE_T CommittedStackSize,
    PVOID StartAddress,
    PVOID Parameter,
    PHANDLE Thread,
    PCLIENT_ID ClientId
);
```

**优点**：某些 EDR 不监控此 API。
**缺点**：已文档化程度低，行为与 CreateRemoteThread 略有不同。

---

#### 4. SetWindowsHookEx

**原理**：安装全局钩子（如 `WH_GETMESSAGE`），Windows 在将钩子消息发送到目标进程时，会自动将钩子 DLL 加载到该进程。

```cpp
HMODULE dll = LoadLibraryA("hook.dll");
HOOKPROC proc = (HOOKPROC)GetProcAddress(dll, "HookProc");
SetWindowsHookEx(WH_GETMESSAGE, proc, dll, targetThreadId);
```

**优点**：系统自动加载 DLL，不需要 CreateRemoteThread。
**缺点**：
- 只对 GUI 进程有效
- 需要目标进程有窗口消息循环
- 钩子 DLL 加载到所有接收消息的进程，不是精确注入

---

#### 5. QueueUserAPC

**原理**：Asynchronous Procedure Call（异步过程调用）。将 `LoadLibrary` 注册到目标线程的 APC 队列，当线程进入 alertable 等待状态时执行。

```cpp
HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, threadId);
QueueUserAPC((PAPCFUNC)pLoadLib, hThread, (ULONG_PTR)remoteMem);
// 目标线程需要执行 WaitForSingleObjectEx/SleepEx 等 alertable 调用
```

**优点**：
- 不需要 CREATE_THREAD 权限
- 某些 EDR 不监控 APC 注入

**缺点**：
- 需要目标线程主动进入 alertable wait
- 不确定执行时机

---

#### 6. SetThreadContext

**原理**：挂起目标线程，修改其指令寄存器（RIP/EIP）指向 shellcode，恢复线程执行。

```cpp
SuspendThread(hThread);
CONTEXT ctx;
GetThreadContext(hThread, &ctx);
ctx.Rip = (DWORD64)remoteShellcode;
SetThreadContext(hThread, &ctx);
ResumeThread(hThread);
```

**优点**：不需要 CreateRemoteThread。
**缺点**：
- 线程恢复后执行位置被改变，极易崩溃
- 需要精确的上下文保存/恢复
- 多线程环境下复杂

**核心**：shellcode 末尾必须恢复原始指令和 RIP，否则目标进程崩溃。

---

#### 7. 线程上下文劫持（Stealing）

**原理**：与 SetThreadContext 类似，但更彻底 — 保存完整线程上下文，恢复线程原始状态。

```
1. SuspendThread → GetThreadContext → 保存 ctx
2. 将 shellcode 写入远程内存
3. ctx.Rip = shellcode_addr (shellcode 末尾恢复 ctx 并跳回)
4. SetThreadContext → ResumeThread
5. 稍后 WaitForSingleObject(hThread, ...) 等待 shellcode 完成
```

**优点**：不创建新线程，很难检测。
**缺点**：实现复杂，容易出现竞态条件。

---

#### 8. AppInit_DLLs

**原理**：注册表键控制哪些 DLL 被自动加载到加载 User32.dll 的进程。

```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows
  AppInit_DLLs = "c:\path\to\stealth.dll"
  LoadAppInit_DLLs = 1
  RequireSignedAppInit_DLLs = 0
```

**优点**：实现极其简单，全局自动加载。
**缺点**：
- Win8+ 需签名且默认禁用
- 影响所有加载 User32.dll 的进程（全局）
- 已基本废弃

---

#### 9. KnownDLLs 劫持

**原理**：KnownDLLs 是系统启动时预加载的 DLL 列表。修改这个列表可以让系统加载恶意版本替换系统 DLL。

```
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs
  lpk = "c:\malicious\lpk.dll"
```

**优点**：影响全局，系统启动时生效。
**缺点**：极易导致系统不稳定，需要重启。

---

#### 10. DLL 劫持（DLL Hijacking）

**原理**：Windows DLL 搜索顺序：
1. 进程同目录（先解除 KnownDLLs）
2. System32
3. System
4. Windows 目录
5. PATH 环境变量

将恶意 DLL 放在目标进程同目录，命名为目标进程会加载的真实 DLL 名。

**常见目标**：`version.dll`、`dbghelp.dll`、`wtsapi32.dll`

**优点**：实现简单，部分应用程序存在已知劫持点。
**缺点**：依赖应用程序的具体行为。

---

#### 11. DLL Side-Loading

**原理**：利用 WinSxS（并行程序集）或 .local 文件的 DLL 搜索行为。与 DLL 劫持类似，但利用的是更复杂的搜索顺序。

```
app.exe.local → app.exe 会在当前目录搜索 DLL
```

**优点**：比标准 DLL 劫持更隐蔽。
**缺点**：需要特定版本的 Windows 或应用程序配置。

---

#### 12. COM 劫持

**原理**：注册一个 COM 组件，其实现 DLL 是我们的恶意 DLL。当目标进程通过 CLSID 创建 COM 对象时，加载我们的 DLL。

```
注册表:
  HKCR\CLSID\{GUID}\InprocServer32\(default) = "c:\malicious.dll"

目标进程:
  CoCreateInstance(CLSID_SomeObject, ...) → 加载我们的 dll
```

**优点**：对于使用 COM 的大型应用程序（Office、浏览器）非常有效。
**缺点**：需要了解目标进程的 COM 使用情况。

---

#### 13. PE 注入

**原理**：不依赖 LoadLibrary，手动将 DLL 的 PE 映像加载到目标进程内存。需要：
1. 读取 DLL 文件
2. 在目标进程分配内存（按 Section 对齐）
3. 写 Section 到目标进程
4. 解析并修复导入表
5. 应用重定位
6. 设置节权限
7. 调用 DllMain

```cpp
// 伪代码
BYTE* dllData = ReadFile("stealth.dll");
IMAGE_NT_HEADERS* nt = GetNtHeaders(dllData);
// 分配 PE 头部
LPVOID base = VirtualAllocEx(hProcess, NULL, nt->OptionalHeader.SizeOfImage, ...);
// 写 Section
for (每个 section)
    WriteProcessMemory(hProcess, base + section.VirtualAddress, ...);
// 修复导入
for (每个导入)
    LoadLibrary + GetProcAddress → 写入 IAT
// 修复重定位
if (实际基址 != 首选基址)
    for (每个重定位项)
        修正指针 + delta
// 设置节权限
for (每个 section)
    VirtualProtectEx(hProcess, base + section.VirtualAddress, ...);
// 创建线程调用 DllMain
CreateRemoteThread(hProcess, ..., (LPTHREAD_START_ROUTINE)((BYTE*)base + ...), ...);
```

**优点**：
- 无文件落地（DLL 存在于内存中）
- 不触发 LoadLibrary 监控
- DllMain 不在模块列表中显示

**缺点**：实现复杂，需要完整 PE 解析器。

---

#### 14. 反射式 DLL 注入（Reflective DLL Injection）

**原理**：DLL 本身包含一个加载器（stub），当该 stub 被执行时，它会将自身完整加载到进程空间。

```
DLL 结构:
  [PE 头] [Section 数据] [加载器 Stub]

注入过程:
  VirtualAllocEx → WriteProcessMemory(DLL 完整数据)
  CreateRemoteThread(指向 DLL 内的加载器 stub)
  加载器 stub:
    → 解析自身 PE 头
    → 分配更多内存（如果需要）
    → 修复导入表
    → 应用重定位
    → 调用 DllMain
```

**优点**：
- 不调用 LoadLibrary
- 不被 LdrpLoadDll 监控
- 模块不在 PEB 的加载列表中（可选）
- 完全内存加载

**缺点**：实现复杂，需要将加载器 stub 嵌入 DLL。

---

#### 15. Process Hollowing（进程空心化）

**原理**：创建一个挂起进程（通常是合法系统进程如 svchost.exe），卸载其原始映像，写入恶意代码，恢复线程。

```
1. CreateProcess(svchost.exe, CREATE_SUSPENDED)
2. NtUnmapViewOfSection(hProcess, imageBase)      → 卸载原始映像
3. VirtualAllocEx(hProcess, imageBase, ...)        → 分配新映像所需空间
4. WriteProcessMemory(hProcess, ...)               → 写入 PE 头 + Section
5. SetThreadContext(hProcess, hThread, ctx)        → 设置入口点
6. ResumeThread(hThread)                           → 执行恶意代码
```

**优点**：
- 无文件落地
- 进程伪装成合法系统进程
- 不创建远程线程（复用主线程）

**缺点**：
- 适用于 EXE 启动，不是 DLL 注入
- Windows 10/11 上某些进程有保护（PPL）
- 模块检查很麻烦

---

#### 16. AtomBombing

**原理**：使用 Windows 原子表（GlobalAddAtom/GlobalGetAtomName）在进程间传递数据，不需要 WriteProcessMemory。

```
1. 利用 SetThreadContext 或 APC 让目标线程执行 shellcode
2. shellcode 代码：
   a. GlobalGetAtomName → 从原子表读取数据（第二阶段 shellcode）
   b. VirtualAlloc → 分配执行内存
   c. 复制阶段2 shellcode 并执行
   d. 第二阶段 shellcode 调用 LoadLibrary
```

**优点**：
- 不调用 VirtualAllocEx + WriteProcessMemory（绕过活跃监控）
- 原子表是全局机制，不需要跨进程内存操作

**缺点**：
- 实现极其复杂
- 仍然需要 SetThreadContext 或 APC 启动第一阶段
- 原子表的容量限制

---

#### 17. ExtraWindowBytes

**原理**：每个窗口有额外字节（ExtraBytes），SetWindowLongPtr/GetWindowLongPtr 可以读写这些字节。利用窗口额外字节存储 shellcode 指针。

```
1. 找到目标进程拥有的窗口
2. SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR)remoteShellcodeAddr)
3. 通过某种方式触发窗口过程执行 shellcode
```

**优点**：不需要 CreateRemoteThread 或 WriteProcessMemory（如果 shellcode 已经存在）。
**缺点**：
- 需要目标进程有窗口
- 需要窗口过程配合
- 容量小，只能存指针

---

#### 18. 断点注入（Breakpoint Injection）

**原理**：利用硬件调试寄存器（DR0-DR3）设置断点。当断点命中时，系统产生异常。VEH（Vectored Exception Handler）捕获异常并执行 shellcode。

```
注入器:
  1. 远程线程设置 VEH → AddVectoredExceptionHandler
  2. 设置硬件断点 → SetThreadContext(DR0 = function_addr, DR7 = enable)
  3. 等待目标线程触发断点

目标进程:
  4. 线程执行到断点地址 → EXCEPTION_SINGLE_STEP
  5. VEH 捕获异常
  6. VEH 修改上下文 → 执行 shellcode
  7. 恢复上下文继续执行
```

**优点**：
- 即使 EDR 监控了所有注入 API，断点注入通过异常处理工作
- 不调用 CreateRemoteThread、VirtualAllocEx、WriteProcessMemory
- 硬件断点不能被软件篡改

**缺点**：
- 实现极其复杂
- 只有 4 个硬件断点寄存器（DR0-DR3）
- 调试寄存器本身可被检测

### 10.3 检测难度对比矩阵

```
                               EDR 监控点
                    ┌───────────────────────────────────────────────┐
                    │ Create-   │ Virtual-  │ Write-  │ Load-  │   │
                    │ RemoteThr │ AllocEx   │ Process │ Library│   │
                    │           │           │ Mem     │        │   │
────────────────────┼───────────┼───────────┼─────────┼────────┼───┤
CreateRemoteThread  │ ● 触发    │ ●         │ ●      │ ●      │  低
NtCreateThreadEx    │ ● 触发    │ ●         │ ●      │ ●      │  中
RtlCreateUserThread │ ● 触发    │ ●         │ ●      │ ●      │  中
SetWindowsHookEx    │ ○         │ ○         │ ○      │ ●      │  中
QueueUserAPC        │ ○         │ ●         │ ●      │ ●      │  中
SetThreadContext    │ ○         │ ●         │ ●      │ ○      │  中高
AppInit_DLLs        │ ○         │ ○         │ ○      │ ●      │  低
DLL Hijacking       │ ○         │ ○         │ ○      │ ●      │  低
COM 劫持            │ ○         │ ○         │ ○      │ ●      │  中
PE 注入             │ ●         │ ●         │ ●      │ ○      │  高
反射式 DLL          │ ●         │ ●         │ ●      │ ○      │  高
Process Hollowing   │ ○ (自己)  │ ●         │ ●      │ ○      │  中
AtomBombing         │ ○         │ ○ (目标)  │ ○      │ ●      │  极高
断点注入            │ ○         │ ○         │ ○      │ ○      │  极高
                    └───────────────────────────────────────────────┘
  ● = 会被监控    ○ = 绕过监控
```

### 10.4 本项目为什么选方法 1

| 因素 | 评估 |
|------|------|
| **教学价值** | 代码最短、逻辑最清晰，适合从 0 到 1 理解注入原理 |
| **稳定性** | 系统 API，行为可预测，调试容易 |
| **通用性** | 所有 Windows 版本 100% 支持 |
| **备选方案** | 只需替换 CreateRemoteThread 为 NtCreateThreadEx 即可升级到方法 2 |

本 Demo 的目的是**教学**，不是**渗透**。如果需要实际对抗 EDR，应当组合方法 14（反射式 DLL）+ 方法 3（RtlCreateUserThread）+ 方法 16（AtomBombing 第一阶段）。
