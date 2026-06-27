//
// Copyright (c) 2024 KFSecurity. All rights reserved.
//

import Foundation
#if canImport(UIKit)
import UIKit
#endif
#if canImport(Metal)
import Metal
#endif
#if canImport(CoreHaptics)
import CoreHaptics
#endif
import KFSecurityCore

// ============================================================================
// Standard 实现 — 仅使用 Apple 公开 API，100% 上架合规
// ============================================================================

// MARK: - 越狱检测器

public struct StandardJailbreakDetector: JailbreakDetector {
    private let config: SecurityConfiguration
    public init(config: SecurityConfiguration = .strict) { self.config = config }

    public func detect() async -> [RiskSignal] {
        var signals: [RiskSignal] = []
        signals.append(checkJailbreakFiles())
        signals.append(scanApplicationsDirectory())
        signals.append(checkWritablePath())
        signals.append(checkSymlinkIntegrity())
        if config.collectDetailedEvidence { signals.append(checkSystemFileReadability()) }
        return signals
    }

    private static let jailbreakPaths = [
        "/Applications/Cydia.app", "/Applications/Sileo.app",
        "/Applications/Zebra.app", "/Applications/Filza.app",
        "/Applications/checkra1n.app", "/Applications/unc0ver.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/var/jb", "/etc/apt", "/etc/apt/sources.list",
        "/usr/sbin/sshd", "/usr/bin/ssh", "/bin/bash",
    ]

    private func checkJailbreakFiles() -> RiskSignal {
        let fm = FileManager.default
        let hits = Self.jailbreakPaths.filter { fm.fileExists(atPath: $0) }
        return RiskSignal(id: "jb_file_check", category: .jailbreak,
                          state: .hard(detected: !hits.isEmpty),
                          details: hits.isEmpty ? [:] : ["paths": hits.joined(separator: ",")])
    }

    private static let jbAppKeywords = ["cydia","sileo","zebra","filza","checkra1n","unc0ver","taurine","odyssey"]

    private func scanApplicationsDirectory() -> RiskSignal {
        let apps = "/Applications/"
        guard FileManager.default.fileExists(atPath: apps),
              let contents = try? FileManager.default.contentsOfDirectory(atPath: apps) else {
            return RiskSignal(id: "jb_apps_dir", category: .jailbreak, state: .soft(confidence: 0.1),
                              details: ["note": "unavailable"])
        }
        let hits = contents.filter { app in Self.jbAppKeywords.contains { app.lowercased().contains($0) } }
        return RiskSignal(id: "jb_apps_dir_scan", category: .jailbreak,
                          state: .hard(detected: !hits.isEmpty),
                          details: hits.isEmpty ? [:] : ["suspicious_apps": hits.joined(separator: ",")])
    }

    private func checkWritablePath() -> RiskSignal {
        let path = "/private/jb_test_\(UUID().uuidString)"
        do {
            try "t".write(toFile: path, atomically: true, encoding: .utf8)
            try FileManager.default.removeItem(atPath: path)
            return RiskSignal(id: "jb_sandbox_escape", category: .jailbreak,
                              state: .hard(detected: true), details: ["method": "write_to_private"])
        } catch {
            return RiskSignal(id: "jb_sandbox_escape", category: .jailbreak, state: .hard(detected: false))
        }
    }

    private static let symlinks: [(String,String)] = [("/etc","/private/etc"),("/var","/private/var"),("/tmp","/private/tmp")]

    private func checkSymlinkIntegrity() -> RiskSignal {
        var broken: [String] = []
        for (link, exp) in Self.symlinks {
            if let r = try? FileManager.default.destinationOfSymbolicLink(atPath: link), r != exp {
                broken.append("\(link)→\(r)≠\(exp)")
            }
        }
        return RiskSignal(id: "jb_symlink_integrity", category: .jailbreak,
                          state: .soft(confidence: broken.isEmpty ? 0 : 0.7),
                          details: broken.isEmpty ? [:] : ["broken": broken.joined(separator: ";")])
    }

    private static let sysFiles = ["/etc/fstab","/etc/hosts","/private/etc/fstab","/private/etc/hosts"]

    private func checkSystemFileReadability() -> RiskSignal {
        let r = Self.sysFiles.filter { FileManager.default.fileExists(atPath: $0) }
        return RiskSignal(id: "jb_sysfile_readability", category: .jailbreak,
                          state: .soft(confidence: r.isEmpty ? 0 : Double(r.count)/Double(Self.sysFiles.count)),
                          details: r.isEmpty ? [:] : ["readable": r.joined(separator: ",")])
    }
}

// MARK: - Hook 注入检测器

public struct StandardHookInjectionDetector: HookInjectionDetector {
    private let config: SecurityConfiguration
    public init(config: SecurityConfiguration = .strict) { self.config = config }

    public func detect() async -> [RiskSignal] {
        [checkSuspiciousClasses()]
    }

    private static let classList: [(String,String)] = [
        ("FLEXManager","FLEX"), ("FridaServer","Frida"), ("FridaGadget","Frida"),
        ("CydiaObject","Cydia"), ("SSLKillSwitch","SSLKillSwitch"),
        ("SubstrateLoader","Substrate"), ("RocketBootstrap","RocketBootstrap"),
        ("RootHideManager","RootHide"), ("Liberty","Liberty"),
    ]

    private func checkSuspiciousClasses() -> RiskSignal {
        let hits = Self.classList.filter { NSClassFromString($0.0) != nil }
        return RiskSignal(id: "hook_suspicious_classes", category: .hookInjection,
                          state: .hard(detected: !hits.isEmpty),
                          details: hits.isEmpty ? [:] : ["classes": hits.map(\.0).joined(separator: ",")])
    }
}

// MARK: - 云手机检测器

public struct StandardCloudPhoneDetector: CloudPhoneDetector {
    private let config: SecurityConfiguration
    public init(config: SecurityConfiguration = .strict) { self.config = config }

    public func detect() async -> [RiskSignal] {
        var signals: [RiskSignal] = []
        signals.append(checkGPUName())
        signals.append(checkHostname())
        signals.append(checkHardwareModel())
        signals.append(contentsOf: checkHardwareCapabilities())
        #if targetEnvironment(simulator)
        signals.append(RiskSignal(id: "cp_simulator", category: .cloudPhone,
                                  state: .hard(detected: true), details: ["method": "targetEnvironment"]))
        #endif
        return signals
    }

    private static let virtualGPU = ["apple paravirtual device","apple paravirt","llvmpipe","llvm"]

    private func checkGPUName() -> RiskSignal {
        #if canImport(Metal)
        guard let device = MTLCreateSystemDefaultDevice() else {
            return RiskSignal(id: "cp_gpu", category: .cloudPhone, state: .soft(confidence: 0.6), details: ["reason":"metal_unavailable"])
        }
        let lower = device.name.lowercased()
        let vir = Self.virtualGPU.contains { lower.contains($0) }
        let real = lower.contains("apple a") || lower.contains("apple m") || lower.contains("apple gpu")
        return RiskSignal(id: "cp_gpu", category: .cloudPhone,
                          state: vir ? .hard(detected: true) : (real ? .hard(detected: false) : .soft(confidence: 0.45)),
                          details: ["gpu_name": device.name])
        #else
        return RiskSignal(id: "cp_gpu", category: .cloudPhone, state: .unavailable)
        #endif
    }

    private static let suspiciousHosts = ["cloudphone","phonecloud","vphone","redfinger","armcloud","nowgg","bignox","remotefarm"]

    private func checkHostname() -> RiskSignal {
        let host = ProcessInfo.processInfo.hostName.lowercased()
        let hit = Self.suspiciousHosts.first { host.contains($0) }
        return RiskSignal(id: "cp_hostname", category: .cloudPhone,
                          state: .soft(confidence: hit != nil ? 0.82 : 0),
                          details: hit.map { ["hostname": ProcessInfo.processInfo.hostName, "keyword": $0] } ?? [:])
    }

    private static let vPhone = ["iphone99","vresearch","paravirtual"]

    private func checkHardwareModel() -> RiskSignal {
        var uts = utsname(); uname(&uts)
        let machine = withUnsafePointer(to: &uts.machine) {
            $0.withMemoryRebound(to: CChar.self, capacity: Int(_SYS_NAMELEN)) { String(cString: $0) }
        }
        let isVP = Self.vPhone.contains { machine.lowercased().contains($0) }
        return RiskSignal(id: "cp_hardware_model", category: .cloudPhone,
                          state: .hard(detected: isVP),
                          details: isVP ? ["machine": machine] : [:])
    }

    private func checkHardwareCapabilities() -> [RiskSignal] {
        var s: [RiskSignal] = []
        var uts = utsname(); uname(&uts)
        let machine = withUnsafePointer(to: &uts.machine) {
            $0.withMemoryRebound(to: CChar.self, capacity: Int(_SYS_NAMELEN)) { String(cString: $0) }
        }
        #if canImport(CoreHaptics)
        if isIPhone7OrNewer(machine) {
            let caps = CHHapticEngine.capabilitiesForHardware()
            if !caps.supportsHaptics {
                s.append(RiskSignal(id: "cp_haptic_mismatch", category: .cloudPhone, state: .soft(confidence: 0.85),
                                    details: ["machine": machine, "reason":"iphone7+_expected_haptics"]))
            }
        }
        #endif
        #if canImport(UIKit)
        let pro: Set<String> = ["iphone15,2","iphone15,3","iphone16,1","iphone16,2","iphone17,1","iphone17,2"]
        if pro.contains(machine.lowercased()) {
            let fps = UIScreen.main.maximumFramesPerSecond
            if fps <= 60 {
                s.append(RiskSignal(id: "cp_refresh_rate_mismatch", category: .cloudPhone, state: .soft(confidence: 0.8),
                                    details: ["machine": machine, "maxFPS":"\(fps)", "expected":"120"]))
            }
        }
        #endif
        return s
    }

    private func isIPhone7OrNewer(_ m: String) -> Bool {
        let l = m.lowercased()
        guard l.hasPrefix("iphone"), let comma = l.firstIndex(of: ",") else { return false }
        return Int(String(l[l.index(l.startIndex, offsetBy: "iphone".count)..<comma])).map { $0 >= 9 } ?? false
    }
}

// MARK: - 调试器检测器

public struct StandardDebuggerDetector: DebuggerDetector {
    public init() {}

    public func detect() async -> [RiskSignal] {
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var size = MemoryLayout<kinfo_proc>.stride
        guard sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0) == 0 else {
            return [RiskSignal(id: "dbg_sysctl_ptraced", category: .debugger, state: .unavailable)]
        }
        let traced = (info.kp_proc.p_flag & P_TRACED) != 0
        return [RiskSignal(id: "dbg_sysctl_ptraced", category: .debugger, state: .hard(detected: traced))]
    }
}

// MARK: - App 完整性检测器

public struct StandardAppIntegrityDetector: AppIntegrityDetector {
    private let config: SecurityConfiguration
    public init(config: SecurityConfiguration = .strict) { self.config = config }

    public func detect() async -> [RiskSignal] {
        var s: [RiskSignal] = []
        s.append(checkProvisioningProfile())
        s.append(checkCodeSignature())
        return s
    }

    private func checkProvisioningProfile() -> RiskSignal {
        let has = (Bundle.main.path(forResource: "embedded", ofType: "mobileprovision")
            .map { FileManager.default.fileExists(atPath: $0) }) ?? false
        return RiskSignal(id: "integrity_provisioning_profile", category: .appIntegrity,
                          state: .hard(detected: has),
                          details: has ? ["note":"embedded.mobileprovision_present_(dev/enterprise)"] : [:])
    }

    #if os(macOS)
    private func checkCodeSignature() -> RiskSignal {
        let url = Bundle.main.bundleURL as CFURL
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url, [], &code) == errSecSuccess, let code else {
            return RiskSignal(id: "integrity_code_signature", category: .appIntegrity, state: .unavailable,
                              details: ["reason":"sec_static_code_create_failed"])
        }
        let valid = SecStaticCodeCheckValidity(code, [], nil) == errSecSuccess
        return RiskSignal(id: "integrity_code_signature", category: .appIntegrity,
                          state: .hard(detected: !valid),
                          details: valid ? [:] : ["note":"code_signature_invalid"])
    }
    #else
    private func checkCodeSignature() -> RiskSignal {
        RiskSignal(id: "integrity_code_signature", category: .appIntegrity, state: .unavailable)
    }
    #endif
}

// MARK: - Root 权限检测器

public struct StandardRootAccessDetector: RootAccessDetector {
    public init() {}

    public func detect() async -> [RiskSignal] {
        let markers = ["/var/mobile/.roothide","/var/mobile/.installed_roothide",
                       "/var/mobile/.procursus_strapped","/var/jb/.procursus_strapped"]
        let hits = markers.filter { FileManager.default.fileExists(atPath: $0) }
        return [RiskSignal(id: "root_indicators", category: .rootAccess,
                           state: .hard(detected: !hits.isEmpty),
                           details: hits.isEmpty ? [:] : ["markers": hits.joined(separator: ",")])]
    }
}

// MARK: - 环境检测器

public struct StandardEnvironmentDetector: EnvironmentDetector {
    public init() {}

    public func detect() async -> [RiskSignal] {
        var s: [RiskSignal] = []
        #if targetEnvironment(simulator)
        s.append(RiskSignal(id: "env_simulator", category: .environment, state: .hard(detected: true), details: ["method":"targetEnvironment"]))
        #endif
        var uts = utsname(); uname(&uts)
        let release = withUnsafePointer(to: &uts.release) {
            $0.withMemoryRebound(to: CChar.self, capacity: Int(_SYS_NAMELEN)) { String(cString: $0) }
        }
        let pattern = try? NSRegularExpression(pattern: #"^\d{2}\.\d+\.\d+$"#)
        let match = pattern?.firstMatch(in: release, range: NSRange(location: 0, length: release.utf16.count))
        s.append(RiskSignal(id: "env_kernel_build", category: .environment,
                            state: .soft(confidence: match == nil ? 0.55 : 0),
                            details: match == nil ? ["release": release, "note":"unexpected_kernel_version"] : [:]))
        return s
    }
}
