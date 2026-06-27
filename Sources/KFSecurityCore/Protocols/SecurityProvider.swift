//
// Copyright (c) 2024 KFSecurity. All rights reserved.
//

import Foundation

// MARK: - 安全引擎

/// 聚合安全检测引擎 — 协调各检测维度，输出综合判定
public protocol SecurityEngine: Sendable {
    /// 全量检测
    /// - Parameter configuration: 检测配置
    func evaluate(configuration: SecurityConfiguration) async -> SecurityVerdict

    /// 指定类别的检测
    /// - Parameters:
    ///   - categories: 风险类别集合
    ///   - configuration: 检测配置
    func evaluate(
        categories: Set<RiskCategory>,
        configuration: SecurityConfiguration
    ) async -> SecurityVerdict
}

// MARK: - 安全服务提供商

/// 安全检测服务提供商 — 按上架策略选择不同实现
///
/// - `StandardSecurityProvider`   — App Store 合规（仅公开 API）
/// - `EnterpriseSecurityProvider` — 企业包（含边界 API）
/// - `AdvancedSecurityProvider`   — 全量检测（仅内部审计）
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

// MARK: - 自定义实现基类

/// 继承此基类并覆盖需要的检测器，实现自定义逻辑。
/// 未覆盖的方法返回空检测结果（无风险）。
open class DefaultSecurityProvider: SecurityProvider {
    public init() {}

    open func jailbreakDetector() -> JailbreakDetector { EmptyDetector() }
    open func hookInjectionDetector() -> HookInjectionDetector { EmptyDetector() }
    open func cloudPhoneDetector() -> CloudPhoneDetector { EmptyDetector() }
    open func debuggerDetector() -> DebuggerDetector { EmptyDetector() }
    open func appIntegrityDetector() -> AppIntegrityDetector { EmptyDetector() }
    open func rootAccessDetector() -> RootAccessDetector { EmptyDetector() }
    open func environmentDetector() -> EnvironmentDetector { EmptyDetector() }
    open func makeEngine() -> SecurityEngine { DefaultEngine(provider: self) }
}

// MARK: - 内部空检测器

internal struct EmptyDetector:
    JailbreakDetector, HookInjectionDetector, CloudPhoneDetector,
    DebuggerDetector, AppIntegrityDetector, RootAccessDetector, EnvironmentDetector
{
    func detect() async -> [RiskSignal] { [] }
}

// MARK: - 默认引擎

public struct DefaultEngine: SecurityEngine {
    private let provider: SecurityProvider

    public init(provider: SecurityProvider) {
        self.provider = provider
    }

    public func evaluate(configuration: SecurityConfiguration) async -> SecurityVerdict {
        await evaluate(categories: Set([
            .jailbreak, .hookInjection, .cloudPhone,
            .debugger, .appIntegrity, .rootAccess, .environment,
        ]), configuration: configuration)
    }

    public func evaluate(
        categories: Set<RiskCategory>,
        configuration: SecurityConfiguration
    ) async -> SecurityVerdict {
        let p = provider
        var allSignals: [RiskSignal] = []

        await withTaskGroup(of: [RiskSignal].self) { group in
            if categories.contains(.jailbreak)   { group.addTask { await p.jailbreakDetector().detect() } }
            if categories.contains(.hookInjection) { group.addTask { await p.hookInjectionDetector().detect() } }
            if categories.contains(.cloudPhone)  { group.addTask { await p.cloudPhoneDetector().detect() } }
            if categories.contains(.debugger)    { group.addTask { await p.debuggerDetector().detect() } }
            if categories.contains(.appIntegrity) { group.addTask { await p.appIntegrityDetector().detect() } }
            if categories.contains(.rootAccess)  { group.addTask { await p.rootAccessDetector().detect() } }
            if categories.contains(.environment) { group.addTask { await p.environmentDetector().detect() } }
            for await signals in group { allSignals.append(contentsOf: signals) }
        }

        return computeVerdict(signals: allSignals, config: configuration)
    }

    private func computeVerdict(signals: [RiskSignal], config: SecurityConfiguration) -> SecurityVerdict {
        let triggered = Set(signals.filter(\.state.isDetected).map(\.category))
        guard !signals.isEmpty else { return .clean }

        let total = signals.reduce(0.0) { acc, s in
            switch s.state {
            case .hard(let d): return acc + (d ? s.confidence * 100 : 0)
            case .soft(let c): return acc + c * 100
            case .unavailable: return acc
            }
        }
        let normalized = min(total / Double(signals.count), 100)
        let level = RiskLevel.from(score: normalized)

        return SecurityVerdict(
            level: level,
            score: normalized,
            signals: signals,
            triggeredCategories: triggered,
            summary: triggered.isEmpty
                ? "No risks detected"
                : "Risks in: \(triggered.map(\.description).sorted().joined(separator: ",")) (score:\(Int(normalized)))"
        )
    }
}
