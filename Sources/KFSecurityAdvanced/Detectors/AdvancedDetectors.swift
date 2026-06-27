// Copyright (c) 2024 KFSecurity. All rights reserved.

import Foundation
#if canImport(MachO)
import MachO
#endif
#if canImport(UIKit)
import UIKit
#endif
import KFSecurityCore

// MARK: - Advanced 实现版本 — 全量检测，完全自包含
//
// 不依赖 Standard 或 Enterprise 层的任何类型。
// 每个检测器独立实现完整检测逻辑，只依赖 KernelFluxSecurityCore。

// ============================================================================
// 越狱检测
// ============================================================================

public struct AdvancedJailbreakDetector: JailbreakDetector {
    private let config: SecurityConfiguration

    public init(config: SecurityConfiguration = .default) {
        self.config = config
    }

    public func detect() async -> [RiskSignal] {
        var signals: [RiskSignal] = []

        // 1. 越狱文件路径
        signals.append(checkJailbreakFiles())
        // 2. /Applications/ 目录扫描
        signals.append(scanApplicationsDirectory())
        // 3. 沙箱写入检测
        signals.append(checkWritablePath())
        // 4. 符号链接完整性
        signals.append(checkSymlinkIntegrity())
        // 5. dyld 库扫描
        signals.append(checkDyldLibraries())
        // 6. URL Scheme 检测
        if config.collectDetailedEvidence {
            signals.append(checkURLSchemes())
        }
        // 7. 环境变量检测
        signals.append(checkEnvironmentVariables())
        // 8. dyld 符号完整性
        signals.append(checkDyldSymbolIntegrity())
        // 9. 系统配置文件可读性
        if config.collectDetailedEvidence {
            signals.append(checkSystemFileReadability())
        }

        return signals
    }

    // MARK: 文件路径

    private static let jailbreakPaths: [String] = [
        "/Applications/Cydia.app", "/Applications/Sileo.app",
        "/Applications/Zebra.app", "/Applications/Filza.app",
        "/Applications/checkra1n.app", "/Applications/unc0ver.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/var/jb", "/var/jb/usr/bin/ssh",
        "/var/jb/usr/lib/ElleKit.dylib",
        "/etc/apt", "/etc/apt/sources.list",
        "/usr/sbin/sshd", "/usr/bin/ssh", "/bin/bash",
        "/usr/lib/libsubstrate.dylib", "/usr/lib/libsubstitute.dylib",
        "/usr/lib/ElleKit.dylib", "/usr/lib/libhooker.dylib",
        "/var/mobile/.roothide", "/var/mobile/.installed_roothide",
        "/var/mobile/.procursus_strapped",
    ]

    private func checkJailbreakFiles() -> RiskSignal {
        let fm = FileManager.default
        let detected = Self.jailbreakPaths.contains { fm.fileExists(atPath: $0) }
        let hits = Self.jailbreakPaths.filter { fm.fileExists(atPath: $0) }
        return RiskSignal(id: "jb_file_check", category: .jailbreak,
                          state: .hard(detected: detected),
                          details: hits.isEmpty ? [:] : ["paths": hits.joined(separator: ",")])
    }

    // MARK: 应用目录扫描

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

    // MARK: 沙箱写入

    private func checkWritablePath() -> RiskSignal {
        let testPath = "/private/jb_test_\(UUID().uuidString)"
        let fm = FileManager.default
        do {
            try "test".write(toFile: testPath, atomically: true, encoding: .utf8)
            try fm.removeItem(atPath: testPath)
            return RiskSignal(id: "jb_sandbox_escape", category: .jailbreak,
                              state: .hard(detected: true), details: ["method": "write_to_private"])
        } catch {
            return RiskSignal(id: "jb_sandbox_escape", category: .jailbreak,
                              state: .hard(detected: false))
        }
    }

    // MARK: 符号链接完整性

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

    // MARK: dyld 扫描

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

    // MARK: URL Scheme

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

    // MARK: 环境变量

    private static let suspiciousEnvVars = [
        "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "DYLD_FALLBACK_LIBRARY_PATH",
        "DYLD_PRINT_LIBRARIES", "DYLD_PRINT_SEGMENTS", "DYLD_PRINT_INITIALIZERS",
        "DYLD_NO_PIE", "DYLD_DISABLE_PREFETCH",
    ]

    private func checkEnvironmentVariables() -> RiskSignal {
        let detected = Self.suspiciousEnvVars.filter { getenv($0) != nil }
        return RiskSignal(id: "jb_env_vars", category: .jailbreak,
                          state: .hard(detected: !detected.isEmpty),
                          details: detected.isEmpty ? [:] : ["vars": detected.joined(separator: ",")])
    }

    // MARK: dyld 符号完整性

    private func checkDyldSymbolIntegrity() -> RiskSignal {
        let criticalSymbols = [("open","/usr/lib/system/"),("stat","/usr/lib/system/"),
                               ("dlopen","/usr/lib/system/"),("sysctl","/usr/lib/system/")]
        var anomalies: [String] = []
        for (name, expected) in criticalSymbols {
            if let ptr = dlsym(UnsafeMutableRawPointer(bitPattern: -2), name) {
                var info = Dl_info()
                if dladdr(ptr, &info) != 0 {
                    let image = String(cString: info.dli_fname).lowercased()
                    if !image.contains(expected) && !image.contains("/usr/lib/libSystem") {
                        anomalies.append("\(name)@\(image)")
                    }
                }
            }
        }
        return RiskSignal(id: "jb_dyld_symbol_integrity", category: .jailbreak,
                          state: .soft(confidence: anomalies.isEmpty ? 0 : 0.85),
                          details: anomalies.isEmpty ? [:] : ["anomalies": anomalies.joined(separator: ";")])
    }

    // MARK: 系统文件可读性

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

public struct AdvancedHookInjectionDetector: HookInjectionDetector {
    private let config: SecurityConfiguration

    public init(config: SecurityConfiguration = .default) {
        self.config = config
    }

    public func detect() async -> [RiskSignal] {
        var signals: [RiskSignal] = []

        // NSClassFromString 检测
        signals.append(checkSuspiciousClasses())
        // 加载镜像扫描
        signals.append(checkLoadedImages())
        // dlsym 符号检测
        signals.append(checkHookFrameworkSymbols())
        // 函数前导码完整性
        signals.append(contentsOf: checkFunctionPrologueIntegrity())
        // RWX 匿名内存
        signals.append(checkRWXMemoryRegions())
        // Frida Socket
        signals.append(checkFridaSockets())

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

    // MARK: 函数前导码完整性

    private static let functionsToCheck = [
        ("objc_msgSend","/usr/lib/libobjc"), ("open","/usr/lib/system"),
        ("stat","/usr/lib/system"), ("dlopen","/usr/lib/system"),
    ]

    private func checkFunctionPrologueIntegrity() -> [RiskSignal] {
        var signals: [RiskSignal] = []
        for (sym, expectedImage) in Self.functionsToCheck {
            guard let ptr = dlsym(UnsafeMutableRawPointer(bitPattern: -2), sym) else { continue }
            var info = Dl_info()
            guard dladdr(ptr, &info) != 0 else { continue }
            let image = String(cString: info.dli_fname).lowercased()
            let trusted = image.contains(expectedImage.lowercased()) || image.contains("/usr/lib/libSystem") || image.contains("/System/Library")
            if !trusted {
                signals.append(RiskSignal(id: "hook_func_prologue", category: .hookInjection,
                                          state: .hard(detected: true),
                                          details: ["symbol": sym, "resolved_image": image]))
                continue
            }
            // BRK/TRAP 检测
            let first4 = UnsafeRawPointer(ptr).load(as: UInt32.self)
            if (first4 & 0xFFE00000) == 0xD4200000 {
                signals.append(RiskSignal(id: "hook_brk_trap", category: .hookInjection,
                                          state: .hard(detected: true),
                                          details: ["symbol": sym, "reason": "brk_trap_at_entry"]))
            }
        }
        return signals
    }

    // MARK: RWX 内存

    private func checkRWXMemoryRegions() -> RiskSignal {
        var address: vm_address_t = 0
        var size: vm_size_t = 0
        var depth: UInt32 = 32
        var count = 0
        var rwxCount = 0

        var info = vm_region_submap_info_64()
        repeat {
            var infoCount = mach_msg_type_number_t(MemoryLayout<vm_region_submap_info_64>.size / MemoryLayout<UInt32>.stride)
            let kr = withUnsafeMutablePointer(to: &info) {
                vm_region_recurse_64(mach_task_self_, &address, &size, &depth, $0, &infoCount)
            }
            guard kr == KERN_SUCCESS else { break }
            let prot = info.protection
            if (prot & (VM_PROT_READ|VM_PROT_WRITE|VM_PROT_EXEC)) == (VM_PROT_READ|VM_PROT_WRITE|VM_PROT_EXEC) && info.is_submap == 0 {
                rwxCount += 1
            }
            address += size
            count += 1
        } while count < 50 && address < vm_address_t(bitPattern: -1)

        let suspicious = rwxCount > 2
        return RiskSignal(id: "hook_rwx_regions", category: .hookInjection,
                          state: .soft(confidence: suspicious ? min(Double(rwxCount)/5.0, 0.95) : 0),
                          details: suspicious ? ["count": "\(rwxCount)"] : [:])
    }

    // MARK: Frida Socket

    private func checkFridaSockets() -> RiskSignal {
        guard let tmpContents = try? FileManager.default.contentsOfDirectory(atPath: "/tmp/") else {
            return RiskSignal(id: "hook_frida_sockets", category: .hookInjection, state: .unavailable)
        }
        let found = tmpContents.filter { $0.lowercased().contains("frida") }
        return RiskSignal(id: "hook_frida_sockets", category: .hookInjection,
                          state: .hard(detected: !found.isEmpty),
                          details: found.isEmpty ? [:] : ["sockets": found.map { "/tmp/\($0)" }.joined(separator: ",")])
    }
}

// ============================================================================
// 云手机检测
// ============================================================================

public struct AdvancedCloudPhoneDetector: CloudPhoneDetector {
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
        signals.append(checkCPUInfo())
        #if targetEnvironment(simulator)
        signals.append(RiskSignal(id: "cp_simulator", category: .cloudPhone,
                                  state: .hard(detected: true), details: ["method": "targetEnvironment"]))
        #endif

        return signals
    }

    // MARK: GPU

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

    // MARK: 主机名

    private static let suspiciousHostnames = ["cloudphone","phonecloud","vphone","redfinger","armcloud","nowgg","bignox","remotefarm"]

    private func checkHostname() -> RiskSignal {
        let hostname = ProcessInfo.processInfo.hostName.lowercased()
        let hit = Self.suspiciousHostnames.first { hostname.contains($0) }
        return RiskSignal(id: "cp_hostname", category: .cloudPhone,
                          state: .soft(confidence: hit != nil ? 0.82 : 0),
                          details: hit.map { ["hostname": ProcessInfo.processInfo.hostName, "keyword": $0] } ?? [:])
    }

    // MARK: 硬件型号

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

    // MARK: 硬件能力

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

    // MARK: 挂载点

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
        return signals
    }

    // MARK: 网络接口

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

    // MARK: CPU

    private func checkCPUInfo() -> RiskSignal {
        var ncpu: Int32 = 0
        var size = MemoryLayout<Int32>.stride
        guard sysctlbyname("hw.ncpu", &ncpu, &size, nil, 0) == 0 else {
            return RiskSignal(id: "cp_cpu", category: .cloudPhone, state: .unavailable)
        }
        let anomalous = ncpu > 12 || ncpu < 1
        return RiskSignal(id: "cp_cpu_count", category: .cloudPhone,
                          state: .soft(confidence: anomalous ? 0.6 : 0),
                          details: anomalous ? ["ncpu": "\(ncpu)"] : [:])
    }
}

// ============================================================================
// 调试器检测
// ============================================================================

public struct AdvancedDebuggerDetector: DebuggerDetector {
    public init() {}

    public func detect() async -> [RiskSignal] {
        var signals: [RiskSignal] = []

        // sysctl P_TRACED
        signals.append(checkSysctlPTraced())
        // 进程列表扫描
        signals.append(checkSuspiciousProcesses())
        // ptrace (dlsym)
        signals.append(checkPtrace())
        // 异常端口
        signals.append(checkExceptionPorts())
        // 调试寄存器
        signals.append(checkDebugRegisters())

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
        return RiskSignal(id: "dbg_sysctl_ptraced", category: .debugger,
                          state: .hard(detected: traced))
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
                          details: hits.isEmpty ? [:] : ["names": Array(Set(hits)).sorted().joined(separator: ",")])
    }

    private typealias PtraceFunc = @convention(c) (Int32, pid_t, UnsafeMutableRawPointer?, Int32) -> Int32

    private func checkPtrace() -> RiskSignal {
        #if !targetEnvironment(simulator)
        guard let handle = dlopen("/usr/lib/system/libsystem_kernel.dylib", RTLD_NOLOAD) else {
            return RiskSignal(id: "dbg_ptrace", category: .debugger, state: .unavailable)
        }
        defer { dlclose(handle) }
        guard let sym = dlsym(handle, "ptrace") else {
            return RiskSignal(id: "dbg_ptrace", category: .debugger, state: .unavailable)
        }
        let fn = unsafeBitCast(sym, to: PtraceFunc.self)
        let result = fn(31, 0, nil, 0) // PT_DENY_ATTACH
        if result == -1 && errno != 0 {
            return RiskSignal(id: "dbg_ptrace", category: .debugger, state: .hard(detected: true),
                              details: ["method": "ptrace_deny_attach_failed", "errno": "\(errno)"])
        }
        return RiskSignal(id: "dbg_ptrace", category: .debugger, state: .hard(detected: false))
        #else
        return RiskSignal(id: "dbg_ptrace", category: .debugger, state: .unavailable)
        #endif
    }

    private typealias TaskGetExceptionPortsFunc = @convention(c) (mach_port_t, exception_mask_t, UnsafeMutablePointer<exception_mask_t>?, UnsafeMutablePointer<mach_port_t>?, UnsafeMutablePointer<exception_behavior_t>?, UnsafeMutablePointer<exception_flavor_t>?) -> kern_return_t

    private func checkExceptionPorts() -> RiskSignal {
        guard let handle = dlopen("/usr/lib/system/libsystem_kernel.dylib", RTLD_NOLOAD) else {
            return RiskSignal(id: "dbg_exception_ports", category: .debugger, state: .unavailable)
        }
        defer { dlclose(handle) }
        guard let sym = dlsym(handle, "task_get_exception_ports") else {
            return RiskSignal(id: "dbg_exception_ports", category: .debugger, state: .unavailable)
        }
        let fn = unsafeBitCast(sym, to: TaskGetExceptionPortsFunc.self)
        var ports: [String: String] = [:]
        let types: [(String, exception_mask_t)] = [
            ("EXC_BAD_ACCESS", exception_mask_t(1 << EXC_BAD_ACCESS)),
            ("EXC_BAD_INSTRUCTION", exception_mask_t(1 << EXC_BAD_INSTRUCTION)),
            ("EXC_ARITHMETIC", exception_mask_t(1 << EXC_ARITHMETIC)),
            ("EXC_SOFTWARE", exception_mask_t(1 << EXC_SOFTWARE)),
            ("EXC_BREAKPOINT", exception_mask_t(1 << EXC_BREAKPOINT)),
        ]
        for (name, mask) in types {
            var handler: mach_port_t = 0
            var outMask: exception_mask_t = 0
            let kr = fn(mach_task_self_, mask, &outMask, &handler, nil, nil)
            if kr == KERN_SUCCESS && handler != 0 && handler != mach_task_self_ {
                ports[name] = "handler=\(handler)"
            }
        }
        return RiskSignal(id: "dbg_exception_ports", category: .debugger,
                          state: .soft(confidence: ports.isEmpty ? 0 : 0.7),
                          details: ports.isEmpty ? [:] : ["ports": ports.map { "\($0.key):\($0.value)" }.joined(separator: ",")])
    }

    private typealias ThreadGetStateFunc = @convention(c) (thread_act_t, UInt32, UnsafeMutableRawPointer, UnsafeMutablePointer<mach_msg_type_number_t>) -> kern_return_t

    private struct ARMDebugState64 {
        var bvr: (UInt64,UInt64,UInt64,UInt64,UInt64,UInt64,UInt64,UInt64) = (0,0,0,0,0,0,0,0)
        var bcr: (UInt64,UInt64,UInt64,UInt64,UInt64,UInt64,UInt64,UInt64) = (0,0,0,0,0,0,0,0)
        var wvr: (UInt64,UInt64) = (0,0)
        var wcr: (UInt64,UInt64) = (0,0)
        var mdscr: UInt64 = 0
    }

    private func checkDebugRegisters() -> RiskSignal {
        #if arch(arm64)
        guard let handle = dlopen("/usr/lib/system/libsystem_kernel.dylib", RTLD_NOLOAD) else {
            return RiskSignal(id: "dbg_debug_registers", category: .debugger, state: .unavailable)
        }
        defer { dlclose(handle) }
        guard let sym = dlsym(handle, "thread_get_state") else {
            return RiskSignal(id: "dbg_debug_registers", category: .debugger, state: .unavailable)
        }
        let fn = unsafeBitCast(sym, to: ThreadGetStateFunc.self)
        let ARM_DEBUG_STATE64: UInt32 = 14
        var state = ARMDebugState64()
        var stateCount = mach_msg_type_number_t(MemoryLayout<ARMDebugState64>.size / MemoryLayout<UInt32>.stride)
        let kr = withUnsafeMutablePointer(to: &state) { fn(mach_thread_self(), ARM_DEBUG_STATE64, $0, &stateCount) }
        if kr == KERN_SUCCESS {
            let hasBPs = state.bvr.0 != 0 || state.bvr.1 != 0 || state.bvr.2 != 0 || state.bvr.3 != 0 || state.bvr.4 != 0 || state.bvr.5 != 0
            let hasWPs = state.wvr.0 != 0 || state.wvr.1 != 0
            let isDebugged = hasBPs || hasWPs
            return RiskSignal(id: "dbg_debug_registers", category: .debugger,
                              state: .hard(detected: isDebugged),
                              details: isDebugged ? ["bvr_set": "\(hasBPs)", "wvr_set": "\(hasWPs)"] : [:])
        }
        #endif
        return RiskSignal(id: "dbg_debug_registers", category: .debugger, state: .soft(confidence: 0))
    }
}

// ============================================================================
// App 完整性检测
// ============================================================================

public struct AdvancedAppIntegrityDetector: AppIntegrityDetector {
    private let config: SecurityConfiguration

    public init(config: SecurityConfiguration = .default) {
        self.config = config
    }

    public func detect() async -> [RiskSignal] {
        var signals: [RiskSignal] = []

        signals.append(checkProvisioningProfile())
        signals.append(checkCodeSignature())
        signals.append(checkMachOIntegrity())
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

    private func checkMachOIntegrity() -> RiskSignal {
        guard let execPath = Bundle.main.executableURL?.path else {
            return RiskSignal(id: "integrity_macho", category: .appIntegrity, state: .unavailable)
        }
        guard let handle = try? FileHandle(forReadingFrom: URL(fileURLWithPath: execPath)) else {
            return RiskSignal(id: "integrity_macho", category: .appIntegrity, state: .unavailable)
        }
        defer { try? handle.close() }
        guard let data = try? handle.read(upToCount: MemoryLayout<mach_header_64>.stride) else {
            return RiskSignal(id: "integrity_macho", category: .appIntegrity, state: .unavailable)
        }
        let header = data.withUnsafeBytes { $0.load(as: mach_header_64.self) }
        let tampered = header.magic != MH_MAGIC_64 || header.cputype != CPU_TYPE_ARM64
        return RiskSignal(id: "integrity_macho", category: .appIntegrity,
                          state: .hard(detected: tampered),
                          details: tampered ? ["magic": String(format:"0x%X", header.magic), "cputype": "\(header.cputype)"] : [:])
    }

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

public struct AdvancedRootAccessDetector: RootAccessDetector {
    public init() {}

    public func detect() async -> [RiskSignal] {
        var signals: [RiskSignal] = []

        signals.append(checkRootMarkers())
        signals.append(checkPrebootRootHide())
        signals.append(checkApplicationsWritable())

        return signals
    }

    private static let rootMarkers = [
        "/var/mobile/.roothide", "/var/mobile/.installed_roothide",
        "/var/mobile/.procursus_strapped", "/var/jb/.procursus_strapped",
    ]

    private func checkRootMarkers() -> RiskSignal {
        let hits = Self.rootMarkers.filter { FileManager.default.fileExists(atPath: $0) }
        return RiskSignal(id: "root_indicators", category: .rootAccess,
                          state: .hard(detected: !hits.isEmpty),
                          details: hits.isEmpty ? [:] : ["markers": hits.joined(separator: ",")])
    }

    private func checkPrebootRootHide() -> RiskSignal {
        let preboot = "/private/preboot/"
        guard let contents = try? FileManager.default.contentsOfDirectory(atPath: preboot) else {
            return RiskSignal(id: "root_preboot", category: .rootAccess, state: .unavailable)
        }
        let hiders = contents.filter { entry in
            let lower = entry.lowercased()
            guard lower.contains("procursus") || lower.contains("roothide") || lower.contains("jb") else { return false }
            let full = preboot + entry
            guard let sub = try? FileManager.default.contentsOfDirectory(atPath: full) else { return false }
            let joined = sub.map { $0.lowercased() }.joined(separator: ",")
            return joined.contains("usr") || joined.contains("bin") || joined.contains("library") || joined.contains("etc")
        }
        return RiskSignal(id: "root_preboot", category: .rootAccess,
                          state: .hard(detected: !hiders.isEmpty),
                          details: hiders.isEmpty ? [:] : ["entries": hiders.joined(separator: ",")])
    }

    private func checkApplicationsWritable() -> RiskSignal {
        let testPath = "/Applications/.root_test_\(UUID().uuidString)"
        do {
            try "test".write(toFile: testPath, atomically: true, encoding: .utf8)
            try FileManager.default.removeItem(atPath: testPath)
            return RiskSignal(id: "root_apps_writable", category: .rootAccess,
                              state: .hard(detected: true), details: ["method": "write_to_applications"])
        } catch {
            return RiskSignal(id: "root_apps_writable", category: .rootAccess, state: .hard(detected: false))
        }
    }
}

// ============================================================================
// 环境异常检测
// ============================================================================

public struct AdvancedEnvironmentDetector: EnvironmentDetector {
    public init() {}

    public func detect() async -> [RiskSignal] {
        var signals: [RiskSignal] = []

        #if targetEnvironment(simulator)
        signals.append(RiskSignal(id: "env_simulator", category: .environment,
                                  state: .hard(detected: true), details: ["method": "targetEnvironment"]))
        #endif
        signals.append(checkKernelBuild())
        signals.append(checkAllDyldEnv())
        signals.append(checkParentProcess())

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

    private static let allDyldEnvVars = [
        "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "DYLD_FALLBACK_LIBRARY_PATH",
        "DYLD_PRINT_LIBRARIES", "DYLD_PRINT_SEGMENTS", "DYLD_PRINT_INITIALIZERS",
        "DYLD_NO_PIE", "DYLD_DISABLE_PREFETCH", "DYLD_ROOT_PATH", "DYLD_FRAMEWORK_PATH",
    ]

    private func checkAllDyldEnv() -> RiskSignal {
        let detected = Self.allDyldEnvVars.filter { getenv($0) != nil }
        return RiskSignal(id: "env_dyld_vars", category: .environment,
                          state: .hard(detected: !detected.isEmpty),
                          details: detected.isEmpty ? [:] : ["vars": detected.joined(separator: ",")])
    }

    private func checkParentProcess() -> RiskSignal {
        let parentPID = getppid()
        guard parentPID > 1 else { return RiskSignal(id: "env_parent_process", category: .environment, state: .hard(detected: false)) }
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, parentPID]
        var proc = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        guard sysctl(&mib, UInt32(mib.count), &proc, &size, nil, 0) == 0 else {
            return RiskSignal(id: "env_parent_process", category: .environment, state: .unavailable)
        }
        let name = withUnsafePointer(to: proc.kp_proc.p_comm) {
            $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXCOMLEN)) { String(cString: $0) }
        }.lowercased()
        let suspicious = ["debugserver","lldb","gdb","frida","cycript","ssh","sshd"]
        let hit = suspicious.contains { name.contains($0) }
        return RiskSignal(id: "env_parent_process", category: .environment,
                          state: .hard(detected: hit),
                          details: hit ? ["parent_name": name, "parent_pid": "\(parentPID)"] : [:])
    }
}

// ============================================================================
// Advanced 安全服务提供商
// ============================================================================

/// **Advanced 版本** 安全服务提供商 — 完全自包含，不依赖 Standard/Enterprise 层
///
/// 包含所有检测技术：
/// - 越狱：文件路径、dyld 扫描、URL Scheme、环境变量、dyld symbol 一致性
/// - Hook：NSClassFromString、dyld 镜像、dlsym 符号、函数前导码完整性、
///         RWX 匿名内存扫描、Frida Socket 检测
/// - 云手机：GPU、主机名、硬件型号、Haptic/ProMotion、挂载点、网络接口、CPU
/// - 调试器：sysctl P_TRACED、进程列表、ptrace(dlsym)、异常端口、调试寄存器
/// - 完整性：Provisioning Profile、代码签名、Mach-O header、Bundle 元数据
/// - Root：标记文件、preboot RootHide、/Applications/ 写入
/// - 环境：模拟器、内核版本、DYLD 环境变量、父进程检测
///
/// ⚠️ 仅供 **内部安全审计 / 反作弊** 场景使用，
/// **不可用于 App Store 上架**（使用大量私有 API）。
public struct AdvancedSecurityProvider: SecurityProvider {
    private let config: SecurityConfiguration

    public init(config: SecurityConfiguration = .relaxed) {
        self.config = config
    }

    public func jailbreakDetector() -> JailbreakDetector {
        AdvancedJailbreakDetector(config: config)
    }

    public func hookInjectionDetector() -> HookInjectionDetector {
        AdvancedHookInjectionDetector(config: config)
    }

    public func cloudPhoneDetector() -> CloudPhoneDetector {
        AdvancedCloudPhoneDetector(config: config)
    }

    public func debuggerDetector() -> DebuggerDetector {
        AdvancedDebuggerDetector()
    }

    public func appIntegrityDetector() -> AppIntegrityDetector {
        AdvancedAppIntegrityDetector(config: config)
    }

    public func rootAccessDetector() -> RootAccessDetector {
        AdvancedRootAccessDetector()
    }

    public func environmentDetector() -> EnvironmentDetector {
        AdvancedEnvironmentDetector()
    }

    public func makeEngine() -> SecurityEngine {
        DefaultEngine(provider: self)
    }
}
