import KFService
import KFSecurityCore

final class KFSecurityStartupTask: BaseStartupTask {
    override var identifier: String { "com.kernelflux.security" }
    override var dependencies: [String] { ["com.kernelflux.failing"] }

    private let config: SecurityConfiguration

    init(config: SecurityConfiguration = .default) { self.config = config }

    override func run() async throws {
        let security = try ServiceContainer.shared.resolve(KFSecurityService.self)
        security.initialize(config: config)
        _ = await security.evaluate(configuration: .default)
    }
}

public struct KFSecurityStartupModule: StartupModule {
    private let config: SecurityConfiguration
    public var tasks: [any StartupTask] { [KFSecurityStartupTask(config: config)] }
    public init(config: SecurityConfiguration = .default) { self.config = config }
}
