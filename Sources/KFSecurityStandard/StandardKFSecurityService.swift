import KFSecurityCore

/// Standard (App Store compliant) KFSecurityService implementation.
public final class StandardKFSecurityService: KFSecurityService {
    private var provider: SecurityProvider?

    public init() {}

    public func initialize(config: SecurityConfiguration) {
        provider = StandardSecurityProvider(config: config)
    }

    public func unInit() {
        provider = nil
    }

    public func evaluate(configuration: SecurityConfiguration) async -> SecurityVerdict {
        await provider?.makeEngine().evaluate(configuration: configuration) ?? .clean
    }

    public func evaluate(categories: Set<RiskCategory>, configuration: SecurityConfiguration) async -> SecurityVerdict {
        await provider?.makeEngine().evaluate(categories: categories, configuration: configuration) ?? .clean
    }
}
