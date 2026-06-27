// Copyright (c) 2024 KFSecurity. All rights reserved.

import Foundation
import MachO
#if canImport(UIKit)
import UIKit
#endif
import KFSecurityCore

// MARK: - Enterprise 实现版本 — 完全自包含，不依赖 AppStore/Full 层
//
// 检测方法：AppStore 层能力 + dyld 扫描 + URL Scheme + 挂载点 + 网络接口 + 进程列表 + dlsym 符号

// ============================================================================
// 越狱检测
// ============================================================================

public struct EnterpriseJailbreakDetector: JailbreakDetector {
    private let config: SecurityConfiguration

    public init(config: SecurityConfiguration = .default) {
        self.config = config
    }

    public func detect() async -> [RiskSignal] {
        var signals: [RiskSignal] = []

        // 越狱文件路径
        signals.append(checkJailbreakFiles())
        // /Applications/ 目录扫描
        signals.append(scanApplicationsDirectory())
        // 沙箱写入
        signals.append(checkWritablePath())
        // 符号链接完整性
        signals.append(checkSymlinkIntegrity())
        // dyld 库扫描
        signals.append(checkDyldLibraries())
        // URL Scheme
        if config.collectDetailedEvidence {
            signals.append(checkURLSchemes())
        }
        // 系统配置可读性
        if config.collectDetailedEvidence {
            signals.append(checkSystemFileReadability())
        }

        return signals
    }

    private static let jailbreakPaths: [String] = [
        "/Applications/Cydia.app", "/Applications/Sileo.app",
        "/Applications/Zebra.app", "/Applications/Filza.app",
        "/Applications/checkra1n.app", "/Applications/unc0ver.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/Library/MobileSubstrate/DynamicLibraries",
        "/var/jb", "/var/jb/usr/bin/ssh",
        "/var/jb/usr/lib/ElleKit.dylib",
        "/etc/apt", "/etc/apt/sources.list",
        "/usr/sbin/sshd", "/usr/bin/ssh", "/bin/bash",
        "/usr/lib/libsubstrate.dylib", "/usr/lib/libsubstitute.dylib",
        "/usr/lib/ElleKit.dylib", "/usr/lib/libhooker.dylib",
        "/var/mobile/.roothide", "/var/mobile/.installed_roothide",
    ]

    private func checkJailbreakFiles() -> RiskSignal {
        let fm = FileManager.default
        let detected = Self.jailbreakPaths.contains { fm.fileExists(atPath: $0) }
        let hits = Self.jailbreakPaths.filter { fm.fileExists(atPath: $0) }
        return RiskSignal(id: "jb_file_check", category: .jailbreak,
                          state: .hard(detected: detected),
                          details: hits.isEmpty ? [:] : ["paths": hits.joined(separator: ",")])
    }

    private static let jailbreakAppKeywords = ["cydia","sileo","zebra","filza","checkra1n","unc0ver","taurine","odyssey"]

    private func scanApplicationsDirectory() -> RiskSignal {
        let appsDir = "/Applications/"
        guard FileManager.default.fileExists(atPath: appsDir) else {
            return RiskSignal(id: "jb_apps_dir", category: .jailbreak, state: .soft(confidence: 0.1),
                              details: ["note": "applications_dir_missing"])
        }
        let hits = (try? FileManager.default.contentsOfDirectory(atPath: appsDir))?
            .filter { app in Self.jailbreakAppKeywords.contains { app.lowercased().contains($0) } } ?? []
        return RiskSignal(id: "jb_apps_dir_scan", category: .jailbreak,
                          state: .hard(detected: !hits.isEmpty),
                          details: hits.isEmpty ? [:] : ["suspicious_apps": hits.joined(separator: ",")])
    }

    private func checkWritablePath() -> RiskSignal {
        let testPath = "/private/jb_test_\(UUID().uuidString)"
        let fm = FileManager.default
        do {
            try "test".write(toFile: testPath, atomically: true, encoding: .utf8)
            try fm.removeItem(atPath: testPath)
            return RiskSignal(id: "jb_sandbox_escape", category: .jailbreak,
                              state: .hard(detected: true), details: ["method": "write_to_private"])
        } catch {
            return RiskSignal(id: "jb_sandbox_escape", category: .jailbreak, state: .hard(detected: false))
        }
    }

    private static let symlinks: [(String, String)] = [
        ("/etc", "/private/etc"), ("/var", "/private/var"), ("/tmp", "/private/tmp"),
    ]

    private func checkSymlinkIntegrity() -> RiskSignal {
        var broken: [String] = []
        for (link, expected) in Self.symlinks {
            if let resolved = try? FileManager.default.destinationOfSymbolicLink(atPath: link), resolved != expected {
                broken.append("\(link)→\(resolved)≠\(expected)")
            }
        }
        return RiskSignal(id: "jb_symlink_integrity", category: .jailbreak,
                          state: .soft(confidence: broken.isEmpty ? 0 : 0.7),
                          details: broken.isEmpty ? [:] : ["broken": broken.joined(separator: ";")])
    }

    private static let suspiciousDylibs = [
        "SubstrateLoader.dylib", "SSLKillSwitch2.dylib", "SSLKillSwitch.dylib",
        "MobileSubstrate.dylib", "TweakInject.dylib", "CydiaSubstrate",
        "FridaGadget", "frida-agent", "libcycript",
        "libsubstrate.dylib", "libsubstitute.dylib", "ElleKit.dylib", "libhooker.dylib",
    ]

    private func checkDyldLibraries() -> RiskSignal {
        let count = _dyld_image_count()
        var hits: [String] = []
        for i in 0..<count {
            guard let name = _dyld_get_image_name(i) else { continue }
            let imageName = String(cString: name).lowercased()
            for dylib in Self.suspiciousDylibs {
                if imageName.contains(dylib.lowercased()) { hits.append(dylib); break }
            }
        }
        return RiskSignal(id: "jb_dyld_scan", category: .jailbreak,
                          state: .hard(detected: !hits.isEmpty),
                          details: hits.isEmpty ? [:] : ["libraries": Array(Set(hits)).sorted().joined(separator: ",")])
    }

    private static let jailbreakSchemes: [(String, String)] = [
        ("cydia://", "Cydia"), ("sileo://", "Sileo"),
        ("zbra://", "Zebra"), ("filza://", "Filza"),
    ]

    private func checkURLSchemes() -> RiskSignal {
        #if canImport(UIKit)
        let detected = Self.jailbreakSchemes.filter { scheme, _ in
            guard let url = URL(string: scheme) else { return false }
            return UIApplication.shared.canOpenURL(url)
        }
        return RiskSignal(id: "jb_url_scheme", category: .jailbreak,
                          state: .hard(detected: !detected.isEmpty),
                          details: detected.isEmpty ? [:] : ["schemes": detected.map(\.0).joined(separator: ",")])
        #else
        return RiskSignal(id: "jb_url_scheme", category: .jailbreak, state: .unavailable)
        #endif
    }

    private static let systemFiles = ["/etc/fstab","/etc/hosts","/etc/apt/sources.list","/private/etc/fstab","/private/etc/hosts"]

    private func checkSystemFileReadability() -> RiskSignal {
        let readable = Self.systemFiles.filter { FileManager.default.fileExists(atPath: $0) }
        return RiskSignal(id: "jb_sysfile_readability", category: .jailbreak,
                          state: .soft(confidence: readable.isEmpty ? 0 : Double(readable.count)/Double(Self.systemFiles.count)),
                          details: readable.isEmpty ? [:] : ["readable": readable.joined(separator: ",")])
    }
}

// ============================================================================
// Hook 注入检测
// ============================================================================

public struct EnterpriseHookInjectionDetector: HookInjectionDetector {
    private let config: SecurityConfiguration

    public init(config: SecurityConfiguration = .default) {
        self.config = config
    }

    public func detect() async -> [RiskSignal] {
        var signals: [RiskSignal] = []

        signals.append(checkSuspiciousClasses())
        signals.append(checkLoadedImages())
        signals.append(checkHookFrameworkSymbols())

        return signals
    }

    private static let suspiciousClasses: [(String, String)] = [
        ("FLEXManager","FLEX"), ("FridaServer","Frida"), ("FridaGadget","Frida"),
        ("CydiaObject","Cydia/Substrate"), ("SSLKillSwitch","SSLKillSwitch"),
        ("SubstrateLoader","Substrate"), ("RocketBootstrap","RocketBootstrap"),
        ("RootHideManager","RootHide"), ("Liberty","Liberty"),
    ]

    private func checkSuspiciousClasses() -> RiskSignal {
        let detected = Self.suspiciousClasses.filter { NSClassFromString($0.0) != nil }
        return RiskSignal(id: "hook_suspicious_classes", category: .hookInjection,
                          state: .hard(detected: !detected.isEmpty),
                          details: detected.isEmpty ? [:] : ["classes": detected.map(\.0).joined(separator: ",")])
    }

    private static let suspiciousImageTokens = ["frida","gadget","substrate","substitute","libhooker","ellekit","tweak","hook","roothide","cycript"]

    private func checkLoadedImages() -> RiskSignal {
        let count = _dyld_image_count()
        var hits: [String] = []
        for i in 0..<count {
            guard let name = _dyld_get_image_name(i) else { continue }
            let lower = String(cString: name).lowercased()
            if Self.suspiciousImageTokens.contains(where: { lower.contains($0) }) {
                hits.append(String(cString: name))
            }
        }
        let unique = Array(Set(hits)).sorted().prefix(10)
        return RiskSignal(id: "hook_loaded_images", category: .hookInjection,
                          state: .hard(detected: !unique.isEmpty),
                          details: unique.isEmpty ? [:] : ["images": unique.joined(separator: ",")])
    }

    private func checkHookFrameworkSymbols() -> RiskSignal {
        let hookSymbols = ["MSHookFunction","MSHookMessageEx","MSFindSymbol","substrate_hook","ZzHookFunction"]
        var hits: [String] = []
        for sym in hookSymbols {
            if let ptr = dlsym(UnsafeMutableRawPointer(bitPattern: -1), sym) {
                var info = Dl_info()
                if dladdr(ptr, &info) != 0 {
                    let image = String(cString: info.dli_fname).lowercased()
                    if !image.contains("/usr/lib/system/") && !image.contains("/System/") {
                        hits.append("\(sym)@\(image)")
                    }
                }
            }
        }
        return RiskSignal(id: "hook_framework_symbols", category: .hookInjection,
                          state: .hard(detected: !hits.isEmpty),
                          details: hits.isEmpty ? [:] : ["symbols": hits.joined(separator: ",")])
    }
}

// ============================================================================
// 云手机检测
// ============================================================================

public struct EnterpriseCloudPhoneDetector: CloudPhoneDetector {
    private let config: SecurityConfiguration

    public init(config: SecurityConfiguration = .default) {
        self.config = config
    }

    public func detect() async -> [RiskSignal] {
        var signals: [RiskSignal] = []

        signals.append(checkGPUName())
        signals.append(checkHostname())
        signals.append(checkHardwareModel())
        signals.append(contentsOf: checkHardwareCapabilities())
        signals.append(contentsOf: checkMountPoints())
        signals.append(contentsOf: checkNetworkInterfaces())
        #if targetEnvironment(simulator)
        signals.append(RiskSignal(id: "cp_simulator", category: .cloudPhone,
                                  state: .hard(detected: true), details: ["method": "targetEnvironment"]))
        #endif

        return signals
    }

    private static let virtualGPUKeywords = ["apple paravirtual device","apple paravirt","llvmpipe","llvm"]

    private func checkGPUName() -> RiskSignal {
        #if canImport(Metal)
        guard let device = MTLCreateSystemDefaultDevice() else {
            return RiskSignal(id: "cp_gpu", category: .cloudPhone, state: .soft(confidence: 0.6),
                              details: ["reason": "metal_unavailable"])
        }
        let lower = device.name.lowercased()
        let virtual = Self.virtualGPUKeywords.contains { lower.contains($0) }
        let realApple = lower.contains("apple a") || lower.contains("apple m") || lower.contains("apple gpu")
        return RiskSignal(id: "cp_gpu", category: .cloudPhone,
                          state: virtual ? .hard(detected: true) : (realApple ? .hard(detected: false) : .soft(confidence: 0.45)),
                          details: ["gpu_name": device.name])
        #else
        return RiskSignal(id: "cp_gpu", category: .cloudPhone, state: .unavailable)
        #endif
    }

    private static let suspiciousHostnames = ["cloudphone","phonecloud","vphone","redfinger","armcloud","nowgg","bignox","remotefarm"]

    private func checkHostname() -> RiskSignal {
        let hostname = ProcessInfo.processInfo.hostName.lowercased()
        let hit = Self.suspiciousHostnames.first { hostname.contains($0) }
        return RiskSignal(id: "cp_hostname", category: .cloudPhone,
                          state: .soft(confidence: hit != nil ? 0.82 : 0),
                          details: hit.map { ["hostname": ProcessInfo.processInfo.hostName, "keyword": $0] } ?? [:])
    }

    private static let vphonePatterns = ["iphone99","vresearch","paravirtual"]

    private func checkHardwareModel() -> RiskSignal {
        var uts = utsname()
        uname(&uts)
        let machine = withUnsafePointer(to: &uts.machine) {
            $0.withMemoryRebound(to: CChar.self, capacity: Int(_SYS_NAMELEN)) { String(cString: $0) }
        }
        let isVPhone = Self.vphonePatterns.contains { machine.lowercased().contains($0) }
        return RiskSignal(id: "cp_hardware_model", category: .cloudPhone,
                          state: .hard(detected: isVPhone),
                          details: isVPhone ? ["machine": machine] : [:])
    }

    private func checkHardwareCapabilities() -> [RiskSignal] {
        var signals: [RiskSignal] = []
        var uts = utsname()
        uname(&uts)
        let machine = withUnsafePointer(to: &uts.machine) {
            $0.withMemoryRebound(to: CChar.self, capacity: Int(_SYS_NAMELEN)) { String(cString: $0) }
        }

        #if canImport(CoreHaptics)
        if isIPhone7OrNewer(machine) {
            let caps = CHHapticEngine.capabilitiesForHardware()
            if !caps.supportsHaptics {
                signals.append(RiskSignal(id: "cp_haptic_mismatch", category: .cloudPhone,
                                          state: .soft(confidence: 0.85),
                                          details: ["machine": machine, "reason": "iphone7_plus_expected_haptics"]))
            }
        }
        #endif

        #if canImport(UIKit)
        let pro120Hz: Set<String> = ["iphone15,2","iphone15,3","iphone16,1","iphone16,2","iphone17,1","iphone17,2"]
        if pro120Hz.contains(machine.lowercased()) {
            let maxFPS = UIScreen.main.maximumFramesPerSecond
            if maxFPS <= 60 {
                signals.append(RiskSignal(id: "cp_refresh_rate_mismatch", category: .cloudPhone,
                                          state: .soft(confidence: 0.8),
                                          details: ["machine": machine, "maxFPS": "\(maxFPS)", "expected": "120"]))
            }
        }
        #endif

        return signals
    }

    private func isIPhone7OrNewer(_ machine: String) -> Bool {
        let lower = machine.lowercased()
        guard lower.hasPrefix("iphone"), let commaIdx = lower.firstIndex(of: ",") else { return false }
        let majorStr = String(lower[lower.index(lower.startIndex, offsetBy: "iphone".count)..<commaIdx])
        return Int(majorStr).map { $0 >= 9 } ?? false
    }

    private static let virtualFSTypes = ["virtfs","9p","virtiofs","fuse","overlay","aufs","vboxsf","vmhgfs"]

    private func checkMountPoints() -> [RiskSignal] {
        var mntbuf: UnsafeMutablePointer<statfs>?
        let count = getmntinfo(&mntbuf, MNT_NOWAIT)
        guard count > 0, let buf = mntbuf else {
            return [RiskSignal(id: "cp_mount", category: .cloudPhone, state: .unavailable, details: ["reason":"getmntinfo_failed"])]
        }
        var hasAPFS = false, hasRoot = false
        var virtualFS: String?
        for i in 0..<Int(count) {
            let stat = buf[i]
            let fsType = withUnsafePointer(to: stat.f_fstypename) {
                $0.withMemoryRebound(to: CChar.self, capacity: MemoryLayout.size(ofValue: stat.f_fstypename)) { String(cString: $0) }
            }
            let mnt = withUnsafePointer(to: stat.f_mntonname) {
                $0.withMemoryRebound(to: CChar.self, capacity: MemoryLayout.size(ofValue: stat.f_mntonname)) { String(cString: $0) }
            }
            if fsType.lowercased() == "apfs" { hasAPFS = true }
            if mnt == "/" { hasRoot = true }
            if virtualFS == nil {
                virtualFS = Self.virtualFSTypes.first { fsType.lowercased().contains($0) }
            }
        }
        var signals: [RiskSignal] = []
        if let vfs = virtualFS {
            signals.append(RiskSignal(id: "cp_mount_virtual_fs", category: .cloudPhone, state: .soft(confidence: 0.85), details: ["fstype": vfs]))
        }
        if !hasAPFS || !hasRoot {
            var missing: [String] = []
            if !hasAPFS { missing.append("APFS") }
            if !hasRoot { missing.append("/") }
            signals.append(RiskSignal(id: "cp_mount_required_missing", category: .cloudPhone, state: .soft(confidence: 0.6), details: ["missing": missing.joined(separator: ",")]))
        }
        if count < 2 || count > 30 {
            signals.append(RiskSignal(id: "cp_mount_count_anomaly", category: .cloudPhone, state: .soft(confidence: 0.5), details: ["count": "\(count)"]))
        }
        return signals
    }

    private func checkNetworkInterfaces() -> [RiskSignal] {
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let first = ifaddr else {
            return [RiskSignal(id: "cp_network", category: .cloudPhone, state: .unavailable, details: ["reason":"getifaddrs_failed"])]
        }
        defer { freeifaddrs(ifaddr) }
        var names: [String] = []
        var cursor = first
        while true {
            names.append(String(cString: cursor.pointee.ifa_name))
            guard let next = cursor.pointee.ifa_next else { break }
            cursor = next
        }
        let unique = Array(Set(names)).sorted()
        var hits: [String] = []
        let virtualKW = ["bridge","tap","tun","veth","docker"]
        let virtualHits = unique.filter { n in
            let l = n.lowercased()
            return virtualKW.contains { kw in kw == "tun" ? (l.contains("tun") && !l.contains("utun")) : l.contains(kw) }
        }
        if !virtualHits.isEmpty { hits.append("virtual:\(virtualHits.joined(separator: ","))") }
        let hyperKW = ["vnet","qemu","kvm","xen","virtio","cvd","crosvm"]
        let hyperHits = unique.filter { n in hyperKW.contains { n.lowercased().contains($0) } }
        if !hyperHits.isEmpty { hits.append("hypervisor:\(hyperHits.joined(separator: ","))") }
        if unique.count > 10 { hits.append("count_anomaly:\(unique.count)") }
        return hits.isEmpty ? [] : [RiskSignal(id: "cp_network", category: .cloudPhone, state: .soft(confidence: 0.55),
                                                details: ["anomalies": hits.joined(separator: ";"), "interface_count": "\(unique.count)"])]
    }
}

// ============================================================================
// 调试器检测
// ============================================================================

public struct EnterpriseDebuggerDetector: DebuggerDetector {
    public init() {}

    public func detect() async -> [RiskSignal] {
        var signals: [RiskSignal] = []

        signals.append(checkSysctlPTraced())
        signals.append(checkSuspiciousProcesses())

        return signals
    }

    private func checkSysctlPTraced() -> RiskSignal {
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var size = MemoryLayout<kinfo_proc>.stride
        guard sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0) == 0 else {
            return RiskSignal(id: "dbg_sysctl_ptraced", category: .debugger, state: .unavailable)
        }
        let traced = (info.kp_proc.p_flag & P_TRACED) != 0
        return RiskSignal(id: "dbg_sysctl_ptraced", category: .debugger, state: .hard(detected: traced))
    }

    private static let suspiciousProcessNames: Set<String> = ["debugserver","lldb","gdb","frida-server","cycript","substrate","substituted"]

    private func checkSuspiciousProcesses() -> RiskSignal {
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]
        var size: size_t = 0
        sysctl(&mib, u_int(mib.count - 1), nil, &size, nil, 0)
        let count = size / MemoryLayout<kinfo_proc>.stride
        guard count > 0 else { return RiskSignal(id: "dbg_suspicious_processes", category: .debugger, state: .unavailable) }
        var procs = [kinfo_proc](repeating: kinfo_proc(), count: count)
        sysctl(&mib, u_int(mib.count - 1), &procs, &size, nil, 0)
        let hits = procs.compactMap { p -> String? in
            let name = withUnsafePointer(to: p.kp_proc.p_comm) {
                $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXCOMLEN)) { String(cString: $0) }
            }
            return Self.suspiciousProcessNames.contains { name.lowercased().contains($0) } ? name : nil
        }
        return RiskSignal(id: "dbg_suspicious_processes", category: .debugger,
                          state: .hard(detected: !hits.isEmpty),
                          details: hits.isEmpty ? [:] : ["processes": hits.joined(separator: ",")])
    }
}

// ============================================================================
// App 完整性检测 — 全部自包含，与 AppStore 层完全隔离
// ============================================================================

public struct EnterpriseAppIntegrityDetector: AppIntegrityDetector {
    private let config: SecurityConfiguration

    public init(config: SecurityConfiguration = .default) {
        self.config = config
    }

    public func detect() async -> [RiskSignal] {
        var signals: [RiskSignal] = []

        signals.append(checkProvisioningProfile())
        signals.append(checkCodeSignature())
        if config.collectDetailedEvidence {
            signals.append(checkBundleIntegrity())
        }

        return signals
    }

    private func checkProvisioningProfile() -> RiskSignal {
        let has = (Bundle.main.path(forResource: "embedded", ofType: "mobileprovision").map { FileManager.default.fileExists(atPath: $0) }) ?? false
        return RiskSignal(id: "integrity_provisioning_profile", category: .appIntegrity,
                          state: .hard(detected: has),
                          details: has ? ["note": "embedded.mobileprovision_present_(dev/enterprise)"] : [:])
    }

    #if os(macOS)
    private func checkCodeSignature() -> RiskSignal {
        let url = Bundle.main.bundleURL as CFURL
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url, [], &code) == errSecSuccess, let code else {
            return RiskSignal(id: "integrity_code_signature", category: .appIntegrity, state: .unavailable,
                              details: ["reason": "sec_static_code_create_failed"])
        }
        let valid = SecStaticCodeCheckValidity(code, [], nil) == errSecSuccess
        return RiskSignal(id: "integrity_code_signature", category: .appIntegrity,
                          state: .hard(detected: !valid),
                          details: valid ? [:] : ["note": "code_signature_invalid"])
    }
    #else
    private func checkCodeSignature() -> RiskSignal {
        RiskSignal(id: "integrity_code_signature", category: .appIntegrity, state: .unavailable)
    }
    #endif

    private func checkBundleIntegrity() -> RiskSignal {
        let bundleID = Bundle.main.bundleIdentifier ?? ""
        let displayName = Bundle.main.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String ?? ""
        let suspicious = bundleID.isEmpty && displayName.isEmpty
        return RiskSignal(id: "integrity_bundle", category: .appIntegrity,
                          state: .soft(confidence: suspicious ? 0.5 : 0),
                          details: suspicious ? ["note": "suspicious_bundle_metadata"] : [:])
    }
}

// ============================================================================
// Root 权限检测
// ============================================================================

public struct EnterpriseRootAccessDetector: RootAccessDetector {
    public init() {}

    public func detect() async -> [RiskSignal] {
        let hits = Self.rootMarkers.filter { FileManager.default.fileExists(atPath: $0) }
        return [RiskSignal(id: "root_indicators", category: .rootAccess,
                           state: .hard(detected: !hits.isEmpty),
                           details: hits.isEmpty ? [:] : ["markers": hits.joined(separator: ",")])]
    }

    private static let rootMarkers = [
        "/var/mobile/.roothide", "/var/mobile/.installed_roothide",
        "/var/mobile/.procursus_strapped", "/var/jb/.procursus_strapped",
    ]
}

// ============================================================================
// 环境异常检测
// ============================================================================

public struct EnterpriseEnvironmentDetector: EnvironmentDetector {
    public init() {}

    public func detect() async -> [RiskSignal] {
        var signals: [RiskSignal] = []

        #if targetEnvironment(simulator)
        signals.append(RiskSignal(id: "env_simulator", category: .environment,
                                  state: .hard(detected: true), details: ["method": "targetEnvironment"]))
        #endif
        signals.append(checkKernelBuild())

        return signals
    }

    private func checkKernelBuild() -> RiskSignal {
        var info = utsname()
        uname(&info)
        let release = withUnsafePointer(to: &info.release) {
            $0.withMemoryRebound(to: CChar.self, capacity: Int(_SYS_NAMELEN)) { String(cString: $0) }
        }
        let pattern = try? NSRegularExpression(pattern: #"^\d{2}\.\d+\.\d+$"#)
        let match = pattern?.firstMatch(in: release, range: NSRange(location: 0, length: release.utf16.count))
        return RiskSignal(id: "env_kernel_build", category: .environment,
                          state: .soft(confidence: match == nil ? 0.55 : 0),
                          details: match == nil ? ["release": release, "note": "unexpected_kernel_version"] : [:])
    }
}
