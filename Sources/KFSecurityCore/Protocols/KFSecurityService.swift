import Foundation

/// Security evaluation service protocol — wraps a SecurityProvider with lifecycle management.
/// Enables DI registration, mock injection, and the unified startup model.
public protocol KFSecurityService: AnyObject {
    /// Initialize the security service with the given configuration.
    func initialize(config: SecurityConfiguration)

    /// Tear down the service and release resources.
    func unInit()

    /// Run all security detectors and return the verdict.
    func evaluate(configuration: SecurityConfiguration) async -> SecurityVerdict

    /// Run detectors for the given risk categories only.
    func evaluate(categories: Set<RiskCategory>, configuration: SecurityConfiguration) async -> SecurityVerdict
}
