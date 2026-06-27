//
// Copyright (c) 2024 KFSecurity. All rights reserved.
//

import Foundation

// MARK: - 风险等级

/// 设备环境风险等级
public enum RiskLevel: Int, Comparable, Codable, Sendable {
    /// 无风险
    case none = 0
    /// 低风险
    case low = 1
    /// 中风险
    case medium = 2
    /// 高风险
    case high = 3
    /// 严重风险
    case critical = 4

    public static func < (lhs: RiskLevel, rhs: RiskLevel) -> Bool {
        lhs.rawValue < rhs.rawValue
    }

    /// 从 0–100 评分映射到风险等级
    /// - Parameter score: 聚合风险评分
    /// - Returns: 对应等级
    public static func from(score: Double) -> RiskLevel {
        switch score {
        case ..<1:    return .none
        case ..<30:   return .low
        case ..<55:   return .medium
        case ..<80:   return .high
        default:      return .critical
        }
    }
}

// MARK: - 检测类别

/// 风险检测类别
public struct RiskCategory: Hashable, Codable, Sendable {
    public let rawValue: String

    private init(_ rawValue: String) { self.rawValue = rawValue }

    public static let jailbreak     = RiskCategory("jailbreak")
    public static let hookInjection = RiskCategory("hook_injection")
    public static let cloudPhone    = RiskCategory("cloud_phone")
    public static let debugger      = RiskCategory("debugger")
    public static let appIntegrity  = RiskCategory("app_integrity")
    public static let rootAccess    = RiskCategory("root_access")
    public static let environment   = RiskCategory("environment")
    public static let tampering     = RiskCategory("tampering")

    public var description: String { rawValue }
}

// MARK: - 信号状态

/// 检测信号的置信度状态
public enum SignalState: Codable, Sendable {
    /// 确凿判定
    case hard(detected: Bool)
    /// 概率性判定
    case soft(confidence: Double)
    /// 检测不可用
    case unavailable

    public var isDetected: Bool {
        switch self {
        case .hard(let d): return d
        case .soft(let c): return c > 0.5
        case .unavailable: return false
        }
    }
}

// MARK: - 检测信号

/// 单条风险检测信号
public struct RiskSignal: Identifiable, Codable, Sendable {
    public let id: String
    public let category: RiskCategory
    public let state: SignalState
    public let confidence: Double
    public let details: [String: String]
    public let timestamp: Date

    public init(
        id: String,
        category: RiskCategory,
        state: SignalState,
        details: [String: String] = [:],
        timestamp: Date = Date()
    ) {
        self.id = id
        self.category = category
        self.state = state
        self.confidence = {
            switch state {
            case .hard(let d): return d ? 1.0 : 0.0
            case .soft(let c): return min(max(c, 0), 1)
            case .unavailable: return 0.0
            }
        }()
        self.details = details
        self.timestamp = timestamp
    }
}

// MARK: - 单项检测结果

/// 单个检测项的结果快照
public struct DetectionItemResult: Codable, Sendable {
    public let isRisky: Bool
    public let detectionMethod: String
    public let evidence: [String: String]

    public init(isRisky: Bool, detectionMethod: String, evidence: [String: String] = [:]) {
        self.isRisky = isRisky
        self.detectionMethod = detectionMethod
        self.evidence = evidence
    }
}

// MARK: - 综合判定

/// 设备环境安全判定结果
public struct SecurityVerdict: Codable, Sendable {
    public let level: RiskLevel
    public let score: Double
    public let signals: [RiskSignal]
    public let triggeredCategories: Set<RiskCategory>
    public let summary: String

    /// 是否存在风险
    public var isRisky: Bool { level >= .medium }

    /// 指定类别是否检出风险
    public func isDetected(for category: RiskCategory) -> Bool {
        triggeredCategories.contains(category)
    }

    /// 获取指定类别的所有信号
    public func signals(for category: RiskCategory) -> [RiskSignal] {
        signals.filter { $0.category == category }
    }

    public init(
        level: RiskLevel,
        score: Double,
        signals: [RiskSignal],
        triggeredCategories: Set<RiskCategory>,
        summary: String
    ) {
        self.level = level
        self.score = min(max(score, 0), 100)
        self.signals = signals
        self.triggeredCategories = triggeredCategories
        self.summary = summary
    }

    /// 空判定（无风险）
    public static let clean = SecurityVerdict(
        level: .none, score: 0,
        signals: [], triggeredCategories: [],
        summary: "No risks detected"
    )
}

// MARK: - 检测配置

/// 安全检测策略配置
public struct SecurityConfiguration: Codable, Sendable {
    public var highRiskThreshold: Double
    public var mediumRiskThreshold: Double
    public var timeoutInterval: TimeInterval
    public var collectDetailedEvidence: Bool

    public static let `default` = SecurityConfiguration(
        highRiskThreshold: 55, mediumRiskThreshold: 30,
        timeoutInterval: 5.0, collectDetailedEvidence: true
    )

    /// 严格模式 — App Store 发布
    public static let strict = SecurityConfiguration(
        highRiskThreshold: 60, mediumRiskThreshold: 35,
        timeoutInterval: 3.0, collectDetailedEvidence: false
    )

    /// 宽松模式 — 企业排查
    public static let relaxed = SecurityConfiguration(
        highRiskThreshold: 40, mediumRiskThreshold: 20,
        timeoutInterval: 8.0, collectDetailedEvidence: true
    )

    public init(
        highRiskThreshold: Double = 55,
        mediumRiskThreshold: Double = 30,
        timeoutInterval: TimeInterval = 5.0,
        collectDetailedEvidence: Bool = true
    ) {
        self.highRiskThreshold = highRiskThreshold
        self.mediumRiskThreshold = mediumRiskThreshold
        self.timeoutInterval = timeoutInterval
        self.collectDetailedEvidence = collectDetailedEvidence
    }
}
