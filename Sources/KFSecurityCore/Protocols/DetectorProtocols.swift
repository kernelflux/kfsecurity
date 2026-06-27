//
// Copyright (c) 2024 KFSecurity. All rights reserved.
//

import Foundation

// MARK: - 检测器协议（-or 名词风格）

/// 越狱检测器
public protocol JailbreakDetector: Sendable {
    func detect() async -> [RiskSignal]
}

/// Hook 注入检测器
public protocol HookInjectionDetector: Sendable {
    func detect() async -> [RiskSignal]
}

/// 云手机 / 模拟器检测器
public protocol CloudPhoneDetector: Sendable {
    func detect() async -> [RiskSignal]
}

/// 调试器检测器
public protocol DebuggerDetector: Sendable {
    func detect() async -> [RiskSignal]
}

/// App 完整性检测器
public protocol AppIntegrityDetector: Sendable {
    func detect() async -> [RiskSignal]
}

/// Root 权限检测器
public protocol RootAccessDetector: Sendable {
    func detect() async -> [RiskSignal]
}

/// 环境异常检测器
public protocol EnvironmentDetector: Sendable {
    func detect() async -> [RiskSignal]
}
