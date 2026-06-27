//
// Copyright (c) 2024 KFSecurity. All rights reserved.
//

import Testing
@testable import KFSecurityCore

// MARK: - Core Types

@Test("RiskLevel from score")
func riskLevelFromScore() {
    #expect(RiskLevel.from(score: -1) == .none)
    #expect(RiskLevel.from(score: 0) == .none)
    #expect(RiskLevel.from(score: 15) == .low)
    #expect(RiskLevel.from(score: 30) == .medium)
    #expect(RiskLevel.from(score: 55) == .high)
    #expect(RiskLevel.from(score: 80) == .critical)
    #expect(RiskLevel.from(score: 100) == .critical)
}

@Test("RiskLevel comparison")
func riskLevelComparison() {
    #expect(RiskLevel.none < .low)
    #expect(RiskLevel.low < .medium)
    #expect(RiskLevel.medium < .high)
    #expect(RiskLevel.high < .critical)
}

@Test("RiskSignal hard state")
func riskSignalHard() {
    let d = RiskSignal(id: "t", category: .jailbreak, state: .hard(detected: true))
    #expect(d.state.isDetected)
    #expect(d.confidence == 1.0)
    let n = RiskSignal(id: "t2", category: .jailbreak, state: .hard(detected: false))
    #expect(!n.state.isDetected)
    #expect(n.confidence == 0.0)
}

@Test("RiskSignal soft state")
func riskSignalSoft() {
    let h = RiskSignal(id: "t", category: .cloudPhone, state: .soft(confidence: 0.85))
    #expect(h.state.isDetected)
    #expect(h.confidence == 0.85)
    let l = RiskSignal(id: "t2", category: .cloudPhone, state: .soft(confidence: 0.3))
    #expect(!l.state.isDetected)
    #expect(l.confidence == 0.3)
}

@Test("RiskSignal unavailable state")
func riskSignalUnavailable() {
    let u = RiskSignal(id: "t", category: .debugger, state: .unavailable)
    #expect(!u.state.isDetected)
    #expect(u.confidence == 0.0)
}

@Test("SecurityVerdict clean")
func verdictClean() {
    let v = SecurityVerdict.clean
    #expect(v.level == .none)
    #expect(v.score == 0)
    #expect(!v.isRisky)
    #expect(v.triggeredCategories.isEmpty)
}

@Test("SecurityVerdict category filtering")
func verdictCategoryFilter() {
    let signals = [
        RiskSignal(id: "1", category: .jailbreak, state: .hard(detected: true)),
        RiskSignal(id: "2", category: .cloudPhone, state: .hard(detected: true)),
        RiskSignal(id: "3", category: .debugger, state: .hard(detected: false)),
    ]
    let v = SecurityVerdict(level: .medium, score: 50, signals: signals,
                            triggeredCategories: [.jailbreak, .cloudPhone],
                            summary: "Test")
    #expect(v.isDetected(for: .jailbreak))
    #expect(v.isDetected(for: .cloudPhone))
    #expect(!v.isDetected(for: .debugger))
    #expect(v.signals(for: .jailbreak).count == 1)
}

@Test("RiskCategory values")
func riskCategoryValues() {
    #expect(RiskCategory.jailbreak.description == "jailbreak")
    #expect(RiskCategory.hookInjection.description == "hook_injection")
    #expect(RiskCategory.cloudPhone.description == "cloud_phone")
    #expect(RiskCategory.debugger.description == "debugger")
    #expect(RiskCategory.appIntegrity.description == "app_integrity")
    #expect(RiskCategory.rootAccess.description == "root_access")
    #expect(RiskCategory.environment.description == "environment")
}

@Test("SecurityConfiguration presets")
func securityConfigPresets() {
    #expect(SecurityConfiguration.default.highRiskThreshold == 55)
    #expect(SecurityConfiguration.default.mediumRiskThreshold == 30)
    #expect(SecurityConfiguration.strict.highRiskThreshold == 60)
    #expect(SecurityConfiguration.relaxed.highRiskThreshold == 40)
}

@Test("DetectionItemResult")
func detectionItemResult() {
    let r = DetectionItemResult(isRisky: true, detectionMethod: "file_check", evidence: ["path":"/etc/apt"])
    #expect(r.isRisky)
    #expect(r.detectionMethod == "file_check")
    #expect(r.evidence["path"] == "/etc/apt")
}

// MARK: - Default Provider & Engine

@Test("DefaultSecurityProvider returns empty detectors")
func defaultProviderEmpty() async {
    let p = DefaultSecurityProvider()
    let s = await p.jailbreakDetector().detect()
    #expect(s.isEmpty)
}

@Test("DefaultEngine returns clean verdict")
func defaultEngineClean() async {
    let p = DefaultSecurityProvider()
    let engine = p.makeEngine()
    let v = await engine.evaluate(configuration: .default)
    #expect(!v.isRisky)
    #expect(v.level == .none)
}

// MARK: - Standard Provider

@Test("StandardSecurityProvider creates engine")
func standardProviderEngine() async {
    let p = StandardSecurityProvider()
    let engine = p.makeEngine()
    let v = await engine.evaluate(configuration: .strict)
    // In simulator, some checks may be unavailable; verdict should still be well-formed
    #expect(v.score >= 0 && v.score <= 100)
}
