# KFSecurity — iOS Device Risk Detection SDK

[![Platform](https://img.shields.io/badge/iOS-15.0+-blue?logo=apple)](https://developer.apple.com/ios)
[![SPM](https://img.shields.io/badge/SPM-compatible-brightgreen)](https://swift.org/package-manager)

**KFSecurity** detects jailbreak, cloud phone, hook injection, debugger, root access, and app tampering on iOS devices. Multi-tier architecture: App Store-safe `Standard`, Enterprise `Enterprise`, and full-spectrum `Advanced`.

## Products

| Product | Description | App Store |
|---------|-------------|:---------:|
| `KFSecurityCore` | Protocols + core types, pure interfaces | Yes |
| `KFSecurityStandard` | Standard implementation, public APIs only | Yes |
| `KFSecurityEnterprise` | Enterprise impl., dyld/getmntinfo/getifaddrs | No |
| `KFSecurityAdvanced` | Advanced impl., ptrace/RWX/debug registers | No |
| `KFSecurity` | Umbrella (Core + Standard) | Yes |

## Quick Start

### 1. Add dependency

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

### 2. Register via KFService (v3)

```swift
import KFService
import KFSecurityStandard

// In App init
ServiceContainer.shared.install(KFSecurityAssembly())

// In App.task
try await Engine.run(modules: [
    KFSecurityStartupModule(),
])
```

### 3. Run detection

```swift
let service = try ServiceContainer.shared.resolve(KFSecurityService.self)
let verdict = await service.evaluate(configuration: .strict)

if verdict.isRisky {
    print("Risk Level: \(verdict.level)   Score: \(verdict.score)")
    print("Triggers: \(verdict.triggeredCategories.map(\.description))")
} else {
    print("Environment is safe")
}
```

## Choose your tier

| Build Type | Package.swift Dependency | Code |
|-----------|-------------------------|------|
| App Store | `KFSecurity` | `StandardSecurityProvider()` |
| Enterprise | `KFSecurityEnterprise` | `EnterpriseSecurityProvider()` |
| Audit Tool | `KFSecurityAdvanced` | `AdvancedSecurityProvider()` |

## KFSecurityService Protocol (v3)

```swift
public protocol KFSecurityService: AnyObject {
    func initialize(config: SecurityConfiguration)
    func unInit()

    func evaluate(configuration: SecurityConfiguration) async -> SecurityVerdict
    func evaluate(categories: Set<RiskCategory>, configuration: SecurityConfiguration) async -> SecurityVerdict
}
```

## KFService Integration

| Type | Role |
|------|------|
| `KFSecurityAssembly` | Implements `ServiceAssembly` — registers `KFSecurityService` → `StandardKFSecurityService` |
| `KFSecurityStartupModule` | Implements `StartupModule` — provides `KFSecurityStartupTask` |

```swift
// Install (sync, in App init)
ServiceContainer.shared.install(KFSecurityAssembly())

// Override with custom impl — last write wins
ServiceContainer.shared.register(KFSecurityService.self) { MySecurityService() }

// Run (async, in App.task)
try await Engine.run(modules: [KFSecurityStartupModule()])
```

## Architecture

```
Sources/
├── KFSecurityCore/              ← Protocols + core types
│   ├── Core/CoreTypes.swift         SecurityVerdict, RiskLevel, RiskSignal
│   └── Protocols/                   7 detector protocols + SecurityProvider + KFSecurityService
│       ├── DetectorProtocols.swift
│       ├── SecurityProvider.swift
│       └── KFSecurityService.swift
├── KFSecurityStandard/          ← Public APIs only + assembly + startup module
│   ├── StandardKFSecurityService.swift
│   ├── KFSecurityAssembly.swift
│   ├── KFSecurityStartupModule.swift
│   └── Detectors/
├── KFSecurityEnterprise/        ← +dyld/getmntinfo/getifaddrs
├── KFSecurityAdvanced/          ← +ptrace/RWX/debug registers
└── KFSecurity/                  ← Umbrella (Core + Standard)
```

## Design Rationale

**Protocol-oriented detector model.** Each risk dimension (jailbreak, hook injection, debugger, etc.) is a separate `Sendable` protocol, enabling compile-time safety and independent testing. Detection logic is isolated per category — adding a new check never touches existing code.

**Tiered safety model.** Three implementation tiers (Standard → Enterprise → Advanced) are enforced at the module level, not via runtime flags. App Store builds link against `KFSecurityStandard` which uses only public Apple APIs.

**Async-first design.** All detectors return `[RiskSignal]` asynchronously, allowing checks to run concurrently. The engine aggregates signals across categories with weighted scoring, producing a single `SecurityVerdict` with numeric score (0–100) and granular `RiskLevel`.

**Pluggable provider pattern.** `SecurityProvider` is a protocol, not a concrete class. Consumers can compose custom detection strategies by implementing individual detector protocols or inheriting from `DefaultSecurityProvider`.

## Detector Protocols

```swift
public protocol JailbreakDetector: Sendable    { func detect() async -> [RiskSignal] }
public protocol HookInjectionDetector: Sendable { func detect() async -> [RiskSignal] }
public protocol CloudPhoneDetector: Sendable    { func detect() async -> [RiskSignal] }
public protocol DebuggerDetector: Sendable      { func detect() async -> [RiskSignal] }
public protocol AppIntegrityDetector: Sendable  { func detect() async -> [RiskSignal] }
public protocol RootAccessDetector: Sendable    { func detect() async -> [RiskSignal] }
public protocol EnvironmentDetector: Sendable   { func detect() async -> [RiskSignal] }
```

## Key Types

```swift
public protocol SecurityProvider: Sendable {
    func jailbreakDetector() -> JailbreakDetector
    func hookInjectionDetector() -> HookInjectionDetector
    func cloudPhoneDetector() -> CloudPhoneDetector
    func debuggerDetector() -> DebuggerDetector
    func appIntegrityDetector() -> AppIntegrityDetector
    func rootAccessDetector() -> RootAccessDetector
    func environmentDetector() -> EnvironmentDetector
    func makeEngine() -> SecurityEngine
}

public enum RiskLevel: Int, Comparable, Codable, Sendable {
    case none = 0, low = 1, medium = 2, high = 3, critical = 4
}
```

## Risk Scoring

| Range | RiskLevel | Action |
|-------|-----------|--------|
| 0–1 | `.none` | Proceed normally |
| 1–30 | `.low` | Log for audit |
| 30–55 | `.medium` | Show warning |
| 55–80 | `.high` | Restrict features |
| 80–100 | `.critical` | Block access |

## Detection Capabilities

| Check | Standard | Enterprise | Advanced |
|-------|:--------:|:----------:|:--------:|
| Jailbreak file paths | ✅ | ✅ | ✅ |
| /Applications/ scan | ✅ | ✅ | ✅ |
| Sandbox write test | ✅ | ✅ | ✅ |
| Symlink integrity | ✅ | ✅ | ✅ |
| dyld library scan | ❌ | ✅ | ✅ |
| URL Scheme detection | ❌ | ✅ | ✅ |
| DYLD env vars | ❌ | ❌ | ✅ |
| NSClassFromString | ✅ | ✅ | ✅ |
| dlsym hook detection | ❌ | ✅ | ✅ |
| Function prologue integrity | ❌ | ❌ | ✅ |
| Frida sockets | ❌ | ❌ | ✅ |
| GPU name (Metal) | ✅ | ✅ | ✅ |
| Hostname analysis | ✅ | ✅ | ✅ |
| Hardware model | ✅ | ✅ | ✅ |
| Mount points (getmntinfo) | ❌ | ✅ | ✅ |
| Network interfaces (getifaddrs) | ❌ | ✅ | ✅ |
| CPU count anomaly | ❌ | ❌ | ✅ |
| Haptic Engine capability | ✅ | ✅ | ✅ |
| ProMotion refresh rate | ✅ | ✅ | ✅ |
| sysctl P_TRACED | ✅ | ✅ | ✅ |
| Process list scan | ❌ | ✅ | ✅ |
| ptrace (dlsym) | ❌ | ❌ | ✅ |
| Exception port hijack | ❌ | ❌ | ✅ |
| ARM64 debug registers | ❌ | ❌ | ✅ |
| Provisioning profile | ✅ | ✅ | ✅ |
| Code signature validation | ✅ | ✅ | ✅ |
| Mach-O header integrity | ❌ | ❌ | ✅ |
| Root marker files | ✅ | ✅ | ✅ |
| preboot RootHide | ❌ | ❌ | ✅ |
| /Applications/ writable | ❌ | ❌ | ✅ |
| Kernel build check | ✅ | ✅ | ✅ |
| Parent process check | ❌ | ❌ | ✅ |
| Simulator detection | ✅ | ✅ | ✅ |

## Custom Implementation

```swift
import KFSecurityCore

class MyProvider: DefaultSecurityProvider {
    override func jailbreakDetector() -> JailbreakDetector {
        MyCustomJailbreakDetector()
    }
}
let service = StandardKFSecurityService(provider: MyProvider())
let verdict = await service.evaluate(configuration: .strict)
```

## Requirements

- iOS 15.0+
- Swift 5.9+ (Xcode 15+)
- SPM

## License

[MIT](LICENSE) © KernelFlux
