//
// Copyright (c) 2024 KFSecurity. All rights reserved.
//

import KFSecurityCore

/// 🟢 **App Store 上架合规** 安全服务提供商
///
/// 仅使用 Apple 公开 API，100% 满足 App Store Review Guidelines。
/// 宿主 App Store target 应依赖 `KernelFluxSecurityStandard` 而非其他实现层。
public struct StandardSecurityProvider: SecurityProvider {
    private let config: SecurityConfiguration
    public init(config: SecurityConfiguration = .strict) { self.config = config }

    public func jailbreakDetector() -> JailbreakDetector { StandardJailbreakDetector(config: config) }
    public func hookInjectionDetector() -> HookInjectionDetector { StandardHookInjectionDetector(config: config) }
    public func cloudPhoneDetector() -> CloudPhoneDetector { StandardCloudPhoneDetector(config: config) }
    public func debuggerDetector() -> DebuggerDetector { StandardDebuggerDetector() }
    public func appIntegrityDetector() -> AppIntegrityDetector { StandardAppIntegrityDetector(config: config) }
    public func rootAccessDetector() -> RootAccessDetector { StandardRootAccessDetector() }
    public func environmentDetector() -> EnvironmentDetector { StandardEnvironmentDetector() }
    public func makeEngine() -> SecurityEngine { DefaultEngine(provider: self) }
}
