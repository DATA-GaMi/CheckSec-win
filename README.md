# checksec-win

一个使用 **C# / .NET Framework** 编写的 Windows 平台 `checksec` 风格工具，用来检查目标 `exe` / `dll` / `sys` 的常见编译期安全缓解项，并补充签名与节区层面的基础分诊信息。

## 已实现检测项

- ASLR (`DYNAMIC_BASE`)
- DEP / NX (`NX_COMPAT`)
- High Entropy VA (`HIGH_ENTROPY_VA`)
- Control Flow Guard (`GUARD_CF` + `GuardFlags`)
- SafeSEH（x86）
- ForceIntegrity
- AppContainer
- GS Cookie（基于 `Load Config -> SecurityCookie` 的线索判断）
- Authenticode 签名状态
- 节区权限（R/W/X）与熵值
- DLL 专属轻量检查：Exports / TLS / Delay Imports / Relocations
- SYS 专属轻量检查：Native Subsystem / INIT / PAGE* / Relocations
- 红旗项汇总（如无有效签名、RWX 节区、高熵节区、CFG 未启用）

## 适用范围

当前版本聚焦于：

- 输入：单个 Windows PE 文件（`exe` / `dll` / `sys`）
- 输出：控制台表格化结果或 `--json`
- 目标平台：Windows
- 技术栈：`.NET Framework 4.8`

## 使用方式

```powershell
checksec-win.exe C:\Windows\System32\notepad.exe
checksec-win.exe C:\Windows\System32\kernel32.dll
checksec-win.exe C:\Windows\System32\drivers\acpi.sys
checksec-win.exe --json C:\Windows\System32\notepad.exe
```

示例输出：

```text
Target      : C:\Windows\System32\notepad.exe
Image Kind  : EXE
File Type   : PE32+
Machine     : x64
Managed CLR : No
Signed      : SignedPresent

Feature            Status     Details
--------------------------------------------------------------------
ASLR               Enabled    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
DEP / NX           Enabled    IMAGE_DLLCHARACTERISTICS_NX_COMPAT
HighEntropyVA      Enabled    PE32+ 且启用 HIGH_ENTROPY_VA
CFG                Enabled    GuardFlags=0x00000500
SafeSEH            N/A        x64 不使用 SafeSEH
ForceIntegrity     Disabled   缺少 FORCE_INTEGRITY
AppContainer       Disabled   缺少 APPCONTAINER 标志
GS Cookie          Enabled    SecurityCookie=0x...
```

## 项目结构

- `CheckSec.NetFx.csproj`：`.NET Framework` 项目文件
- `Program.cs`：命令行入口与输出
- `PeImageAnalyzer.cs`：PE/Load Config 解析与安全特性判断
- `SecurityFeatureStatus.cs`：状态模型

## 当前说明

- 为了避免在部分系统文件上出现卡顿，当前版本已移除导入表遍历与风险 API 检测。
- 节区熵分析使用限量采样而不是整段全读，当前单节最多采样 `64 KB`，用来降低畸形样本导致的内存失控风险。
- `dll/sys` 的专属检查项只使用 PE 头、目录项和节区名等轻量信息，不做高开销恢复。
