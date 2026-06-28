import KFService
import KFSecurityCore

public struct KFSecurityAssembly: ServiceAssembly {
    public init() {}
    public func assemble(container: ServiceContainer) {
        container.register(KFSecurityService.self) { StandardKFSecurityService() }
    }
}
