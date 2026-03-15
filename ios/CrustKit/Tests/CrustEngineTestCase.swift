@testable import CrustKit
import XCTest

/// Shared base class for CrustKit tests.
/// Creates a CrustEngine, initializes it, and tears it down per test.
class CrustEngineTestCase: XCTestCase {
    var engine: CrustEngine!

    override func setUpWithError() throws {
        try super.setUpWithError()
        engine = CrustEngine()
        try engine.initialize()
    }

    override func tearDown() {
        engine.shutdown()
        engine = nil
        // Reset static state modified by tests
        CrustURLProtocol.engine = nil
        CrustURLProtocol.interceptedHosts = ["api.anthropic.com", "api.openai.com"]
        super.tearDown()
    }
}
