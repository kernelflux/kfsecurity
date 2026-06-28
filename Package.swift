// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "KFSecurity",
    platforms: [
        .iOS(.v16),
        .macOS(.v13),
    ],
    products: [
        .library(name: "KFSecurityCore",      targets: ["KFSecurityCore"]),
        .library(name: "KFSecurityStandard",   targets: ["KFSecurityStandard"]),
        .library(name: "KFSecurityEnterprise", targets: ["KFSecurityEnterprise"]),
        .library(name: "KFSecurityAdvanced",   targets: ["KFSecurityAdvanced"]),
        .library(name: "KFSecurity",           targets: ["KFSecurity"]),
    ],
    dependencies: [
        .package(url: "https://github.com/kernelflux/kfservice.git", from: "1.0.0"),
    ],
    targets: [
        .target(name: "KFSecurityCore",
                path: "Sources/KFSecurityCore",
                swiftSettings: swiftSettings),
        .target(name: "KFSecurityStandard",
                dependencies: ["KFSecurityCore", .product(name: "KFService", package: "KFService")],
                path: "Sources/KFSecurityStandard",
                swiftSettings: swiftSettings),
        .target(name: "KFSecurityEnterprise",
                dependencies: ["KFSecurityCore"],
                path: "Sources/KFSecurityEnterprise",
                swiftSettings: swiftSettings),
        .target(name: "KFSecurityAdvanced",
                dependencies: ["KFSecurityCore"],
                path: "Sources/KFSecurityAdvanced",
                swiftSettings: swiftSettings),
        .target(name: "KFSecurity",
                dependencies: ["KFSecurityCore", "KFSecurityStandard"],
                path: "Sources/KFSecurity",
                swiftSettings: swiftSettings),
        .testTarget(name: "KFSecurityTests",
                    dependencies: ["KFSecurityCore", "KFSecurityStandard",
                                   "KFSecurityEnterprise", "KFSecurityAdvanced"],
                    path: "Tests/KFSecurityTests",
                    swiftSettings: swiftSettings),
    ]
)

private var swiftSettings: [SwiftSetting] { [.enableUpcomingFeature("StrictConcurrency")] }
