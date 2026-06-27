# KFSecurity — iOS 设备环境风险检测 SDK

[![Platform](https://img.shields.io/badge/iOS-15.0+-blue?logo=apple)](https://developer.apple.com/ios)
[![SPM](https://img.shields.io/badge/SPM-compatible-brightgreen)](https://swift.org/package-manager)

**KFSecurity** 识别越狱、云手机、Hook 注入、调试器、Root 权限与 App 篡改。多层架构：App Store 安全 `Standard`、企业 `Enterprise`、全量审计 `Advanced`。

> [English](README.md)

---

## 产品线

| Product | 说明 | 上架安全 |
|---------|------|:------:|
| `KFSecurityCore` | 协议层 + 核心类型，纯接口 | ✅ 是 |
| `KFSecurityStandard` | Standard 实现，仅 Apple 公开 API | ✅ 是 |
| `KFSecurityEnterprise` | 企业包，含 dyld/getmntinfo 等 | ❌ 否 |
| `KFSecurityAdvanced` | 全量，含 ptrace/RWX/调试寄存器 | ❌ 否 |
| `KFSecurity` | 便捷入口 (Core + Standard) | ✅ 是 |

---

## 快速开始

### 1. 添加依赖

```swift
// Package.swift
dependencies: [
    .package(url: "https://github.com/kernelflux/kfsecurity.git", from: "1.0.0"),
],
targets: [
    .target(name: "MyApp", dependencies: [
        .product(name: "KFSecurity", package: "kfsecurity"),
    ]),
]
```

### 2. 执行检测

```swift
import KFSecurity

let provider = StandardSecurityProvider()
let verdict = await provider.makeEngine().evaluate()

if verdict.isRisky {
    print("风险等级: \(verdict.level)  评分: \(verdict.score)")
    print("触发类别: \(verdict.triggeredCategories.map(\.description))")
} else {
    print("环境安全")
}
```

---

## 按场景选择依赖

| 构建类型 | Package.swift 依赖 | 代码中使用 |
|---------|-------------------|-----------|
| App Store | `KFSecurity` | `StandardSecurityProvider()` |
| 企业包 | `KFSecurityEnterprise` | `EnterpriseSecurityProvider()` |
| 审计工具 | `KFSecurityAdvanced` | `AdvancedSecurityProvider()` |

---

## 架构

```
Sources/
├── KFSecurityCore/              ← 协议 + 核心类型（零依赖）
│   ├── Core/CoreTypes.swift         SecurityVerdict, RiskLevel, RiskSignal
│   └── Protocols/                   7 个检测器协议 + SecurityProvider + SecurityEngine
│       ├── DetectorProtocols.swift
│       └── SecurityProvider.swift
├── KFSecurityStandard/          ← 仅公开 API
├── KFSecurityEnterprise/        ← +dyld/getmntinfo/getifaddrs
├── KFSecurityAdvanced/          ← +ptrace/RWX/调试寄存器
└── KFSecurity/                  ← 便捷入口 (Core + Standard)
```

---

## 设计理念

**协议化检测器模型。** 每种风险维度（越狱、Hook 注入、调试器等）是独立的 `Sendable` 协议，编译期安全且可独立测试。检测逻辑按类别隔离——新增检查不会触及现有代码。

**分层安全模型。** 三层实现（Standard → Enterprise → Advanced）在模块级别强制执行，而非运行时标记。App Store 构建只链接 `KFSecurityStandard`（仅公开 API）。高级检测（ptrace、调试寄存器、RWX 内存）位于独立模块，消费者需显式选择。

**异步优先设计。** 所有检测器异步返回 `[RiskSignal]`，支持并发执行。引擎按类别加权聚合信号，生成 0–100 分的 `SecurityVerdict` 和粒度的 `RiskLevel`。

**可插拔 Provider 模式。** `SecurityProvider` 是协议而非具体类。Consumer 可实现独立检测器协议，或继承 `DefaultSecurityProvider` 仅覆盖需要的检测器。

---

## 检测器协议

所有检测协议采用 `-or` 名词风格：

```swift
public protocol JailbreakDetector: Sendable {
    func detect() async -> [RiskSignal]
}
public protocol HookInjectionDetector: Sendable {
    func detect() async -> [RiskSignal]
}
public protocol CloudPhoneDetector: Sendable {
    func detect() async -> [RiskSignal]
}
public protocol DebuggerDetector: Sendable {
    func detect() async -> [RiskSignal]
}
public protocol AppIntegrityDetector: Sendable {
    func detect() async -> [RiskSignal]
}
public protocol RootAccessDetector: Sendable {
    func detect() async -> [RiskSignal]
}
public protocol EnvironmentDetector: Sendable {
    func detect() async -> [RiskSignal]
}
```

---

## 核心类型

```swift
public protocol SecurityProvider: Sendable {
    func jailbreakDetector() -> JailbreakDetector
    // ... 共 7 个检测器工厂方法
    func makeEngine() -> SecurityEngine
}

public protocol SecurityEngine: Sendable {
    func evaluate(configuration: SecurityConfiguration) async -> SecurityVerdict
    func evaluate(categories: Set<RiskCategory>, configuration: SecurityConfiguration) async -> SecurityVerdict
}

public enum RiskLevel: Int, Comparable, Codable, Sendable {
    case none = 0, low = 1, medium = 2, high = 3, critical = 4
}
```

---

## 风险评分

0–100 分制：

| 范围 | RiskLevel | 措施 |
|------|-----------|------|
| 0–1 | `.none` | 正常放行 |
| 1–30 | `.low` | 记录审计 |
| 30–55 | `.medium` | 展示警告 |
| 55–80 | `.high` | 限制功能 |
| 80–100 | `.critical` | 阻断访问 |

---

## 检测能力矩阵

| 检测项 | Standard | Enterprise | Advanced |
|-------|:--------:|:----------:|:--------:|
| 越狱文件路径 | ✅ | ✅ | ✅ |
| /Applications/ 目录 | ✅ | ✅ | ✅ |
| 沙箱写入 | ✅ | ✅ | ✅ |
| 符号链接完整性 | ✅ | ✅ | ✅ |
| dyld 库扫描 | ❌ | ✅ | ✅ |
| URL Scheme | ❌ | ✅ | ✅ |
| DYLD 环境变量 | ❌ | ❌ | ✅ |
| dyld 符号一致性 | ❌ | ❌ | ✅ |
| NSClassFromString | ✅ | ✅ | ✅ |
| dlsym 符号检测 | ❌ | ✅ | ✅ |
| 函数前导码完整性 | ❌ | ❌ | ✅ |
| RWX 匿名内存 | ❌ | ❌ | ✅ |
| Frida Socket | ❌ | ❌ | ✅ |
| GPU 名称 (Metal) | ✅ | ✅ | ✅ |
| 主机名分析 | ✅ | ✅ | ✅ |
| 硬件型号 | ✅ | ✅ | ✅ |
| 挂载点 (getmntinfo) | ❌ | ✅ | ✅ |
| 网络接口 (getifaddrs) | ❌ | ✅ | ✅ |
| CPU 核数异常 | ❌ | ❌ | ✅ |
| Haptic Engine | ✅ | ✅ | ✅ |
| ProMotion 刷新率 | ✅ | ✅ | ✅ |
| sysctl P_TRACED | ✅ | ✅ | ✅ |
| 进程列表扫描 | ❌ | ✅ | ✅ |
| ptrace (dlsym) | ❌ | ❌ | ✅ |
| 异常端口劫持 | ❌ | ❌ | ✅ |
| ARM64 调试寄存器 | ❌ | ❌ | ✅ |
| Provisioning Profile | ✅ | ✅ | ✅ |
| 代码签名验证 | ✅ | ✅ | ✅ |
| Mach-O Header 完整性 | ❌ | ❌ | ✅ |
| Root 标记文件 | ✅ | ✅ | ✅ |
| preboot RootHide | ❌ | ❌ | ✅ |
| /Applications/ 可写 | ❌ | ❌ | ✅ |
| 内核版本检查 | ✅ | ✅ | ✅ |
| 父进程检测 | ❌ | ❌ | ✅ |
| 模拟器检测 | ✅ | ✅ | ✅ |

---

## 自定义实现

```swift
import KFSecurityCore

class MyProvider: DefaultSecurityProvider {
    override func jailbreakDetector() -> JailbreakDetector {
        MyCustomJailbreakDetector()
    }
}

let verdict = await MyProvider().makeEngine().evaluate()
```

---

## KFService 集成

通过 Module 注册到 DI 容器：

```swift
import KFService
import KFSecurity

struct SecurityModule: KFModule {
    func register() {
        KFServiceManager.register(SecurityProvider.self) {
            StandardSecurityProvider()
        }
    }
}

// 后续使用：
let provider = KFServiceManager.resolve(SecurityProvider.self)
```

---

## 系统要求

- iOS 15.0+
- Swift 5.9+ (Xcode 15+)
- SPM

---

## 源码结构

```
Sources/
├── KFSecurityCore/              ← 零依赖协议层
│   ├── Core/
│   │   └── CoreTypes.swift          RiskLevel, RiskCategory, RiskSignal, SecurityVerdict
│   └── Protocols/
│       ├── DetectorProtocols.swift  7 个检测器协议
│       └── SecurityProvider.swift   SecurityProvider + SecurityEngine + DefaultSecurityProvider
├── KFSecurityStandard/          ← App Store 安全（仅公开 API）
│   ├── StandardSecurityProvider.swift
│   └── Detectors/
│       └── StandardDetectors.swift
├── KFSecurityEnterprise/        ← 企业包（dyld/getmntinfo/getifaddrs）
│   ├── EnterpriseSecurityProvider.swift
│   └── Detectors/
│       └── EnterpriseDetectors.swift
├── KFSecurityAdvanced/          ← 全量（ptrace/RWX/调试寄存器）
│   └── Detectors/
│       └── AdvancedDetectors.swift
└── KFSecurity/                  ← 便捷重导出 (Core + Standard)
    └── KFSecurity.swift
```

---

## License

[MIT](LICENSE) © KernelFlux
