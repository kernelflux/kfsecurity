//
// Copyright (c) 2024 KFSecurity. All rights reserved.
//

import KFSecurityCore

/// 🟡 **企业包分发** 安全服务提供商
///
/// 在 Standard 能力基础上追加 dyld 扫描、URL Scheme、挂载点、网络接口、进程列表、dlsym 符号检测。
/// 使用 `_dyld_get_image_count`、`getmntinfo`、`getifaddrs` 等边界 API。
///
/// ⚠️ **不可用于 App Store 上架**。上架请使用 `StandardSecurityProvider`。
public struct EnterpriseSecurityProvider: SecurityProvider {
    private let config: SecurityConfiguration
    public init(config: SecurityConfiguration = .default) { self.config = config }

    public func jailbreakDetector() -> JailbreakDetector { EnterpriseJailbreakDetector(config: config) }
    public func hookInjectionDetector() -> HookInjectionDetector { EnterpriseHookInjectionDetector(config: config) }
    public func cloudPhoneDetector() -> CloudPhoneDetector { EnterpriseCloudPhoneDetector(config: config) }
    public func debuggerDetector() -> DebuggerDetector { EnterpriseDebuggerDetector() }
    public func appIntegrityDetector() -> AppIntegrityDetector { EnterpriseAppIntegrityDetector(config: config) }
    public func rootAccessDetector() -> RootAccessDetector { EnterpriseRootAccessDetector() }
    public func environmentDetector() -> EnvironmentDetector { EnterpriseEnvironmentDetector() }
    public func makeEngine() -> SecurityEngine { DefaultEngine(provider: self) }
}
