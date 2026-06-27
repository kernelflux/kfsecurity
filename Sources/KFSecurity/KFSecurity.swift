//
// Copyright (c) 2024 KFSecurity. All rights reserved.
//

/// KFSecurity — 设备环境风险检测 SDK
///
/// 默认安全集合：`KFSecurityCore` + `KFSecurityStandard`
/// App Store 构建不含 Enterprise / Advanced 层的私有 API 代码。
///
/// ```swift
/// import KFSecurity
///
/// let provider = StandardSecurityProvider()
/// let verdict = await provider.makeEngine().evaluate()
/// ```
///
/// Enterprise / Advanced 需在 Package.swift 中显式添加：
/// ```
/// .product(name: "KFSecurityEnterprise", package: "KFSecurity"),
/// .product(name: "KFSecurityAdvanced",   package: "KFSecurity"),
/// ```
