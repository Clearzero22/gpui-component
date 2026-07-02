# Inline Hook 隐藏进程 Demo — 注入任务管理器

Hook `NtQuerySystemInformation`，注入 `taskmgr.exe` 实现从任务管理器隐藏进程。

## 架构

```
HideProc.exe (注入器)
    │
    ├── CreateRemoteThread(LoadLibraryA, "stealth.dll")
    │       └── taskmgr.exe 加载 stealth.dll
    │               └── DllMain → InstallHook()
    │                       └── Hook 了 taskmgr.exe 的 NtQuerySystemInformation
    │
    ├── 用户确认后
    │
    └── CreateRemoteThread(FreeLibrary, hModule)
            └── DllMain(DLL_PROCESS_DETACH) → UninstallHook()
                    └── 恢复 ntdll.dll 原始字节
```

## 文件

| 文件 | 说明 |
|------|------|
| `HideProc.cpp` | 注入器 + 任务管理器发现 + 自提权 |
| `stealth.cpp` | Inline Hook DLL（DllMain 自动安装/卸载） |
| `CMakeLists.txt` | CMake 构建 |

## 编译

```cmd
cmake -B build64 -A x64 && cmake --build build64 --config Release
```

> 必须 Release + 静态 CRT（`/MT`），Debug CRT 在目标进程中不可用。

## 运行

1. 打开 `notepad.exe`
2. 打开任务管理器（或让程序自动启动）
3. 以管理员运行 `build64\Release\HideProc.exe`（自动提权）

### 预期行为

| 阶段 | 任务管理器中的 notepad.exe |
|------|--------------------------|
| 注入前 | ✅ 可见 |
| 注入后 | ❌ 消失（按 F5 刷新） |
| 卸载后 | ✅ 恢复 |

## 关键设计决策

| 问题 | 方案 |
|------|------|
| 注入目标不是 notepad.exe | 注入 taskmgr.exe，Hook 只影响它自己 |
| `LoadLibrary` 返回值截断 | 用 `EnumProcessModules` 遍历模块找 HMODULE |
| 缺少管理员权限 | `ShellExecuteW("runas")` 自动提权重启 |
| Debug CRT 找不到 | 静态 CRT `/MT`，无运行时依赖 |
| taskmgr 可能拒绝远程线程 | 先注入 `Sleep(100)` 诊断线程验证 |

## 原理

- `E9 <4字节偏移>` JMP 替换 `NtQuerySystemInformation` 前 5 字节
- Hook 函数调用原始函数 → 遍历 `SYSTEM_PROCESS_INFORMATION` 链表 → 摘除 `notepad.exe` → 返回
- 调用原始函数时临时恢复字节，调用完后重新 Hook（防递归）
- `FlushInstructionCache` 保证多核正确性

## 局限性

- 只影响 taskmgr.exe 的视图，`tasklist.exe`、Process Explorer、WMI 等不受影响
- 需要管理员权限（VirtualProtect 修改 ntdll 代码页）
- 不适用于 PPL（Protected Process Light）进程
- 单线程演示，非线程安全
