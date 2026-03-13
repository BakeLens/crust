import XCTest
@testable import CrustKit

final class CrustKitTests: XCTestCase {

    var engine: CrustEngine!

    override func setUp() {
        super.setUp()
        engine = CrustEngine()
    }

    override func tearDown() {
        engine.shutdown()
        engine = nil
        super.tearDown()
    }

    // MARK: - Initialization

    func testInitWithBuiltinRules() throws {
        try engine.initialize()
        XCTAssertGreaterThan(engine.ruleCount, 0, "should load builtin rules")
    }

    func testInitWithYAML() throws {
        let yaml = """
        rules:
          - name: test-block-secrets
            message: Secret file access blocked
            actions: [read, write]
            block: "/etc/shadow"
        """
        try engine.initialize(yaml: yaml)
        XCTAssertGreaterThan(engine.ruleCount, 0)
    }

    func testAddRulesYAML() throws {
        try engine.initialize()
        let before = engine.ruleCount

        let yaml = """
        rules:
          - name: extra-rule
            message: Extra rule
            actions: [write]
            block: "/tmp/blocked/**"
        """
        try engine.addRules(yaml: yaml)
        XCTAssertGreaterThan(engine.ruleCount, before)
    }

    // MARK: - Evaluation

    func testAllowedToolCall() throws {
        try engine.initialize()

        let result = engine.evaluate(
            toolName: "read_file",
            arguments: ["path": "/tmp/test.txt"]
        )
        XCTAssertFalse(result.matched, "reading /tmp/test.txt should be allowed")
    }

    func testBlockedToolCall() throws {
        try engine.initialize()

        let result = engine.evaluate(
            toolName: "write_file",
            arguments: ["file_path": "/etc/crontab", "content": "* * * * * evil"]
        )
        XCTAssertTrue(result.matched, "writing to /etc/crontab should be blocked")
        XCTAssertNotNil(result.ruleName)
        XCTAssertNotNil(result.message)
    }

    func testEvaluateWithJSONString() throws {
        try engine.initialize()

        let result = engine.evaluate(
            toolName: "read_file",
            argumentsJSON: #"{"path":"/tmp/safe.txt"}"#
        )
        XCTAssertFalse(result.matched)
    }

    // MARK: - Response interception

    func testInterceptResponseAllowed() throws {
        try engine.initialize()

        let body = """
        {"content":[{"type":"tool_use","id":"t1","name":"read_file","input":{"path":"/tmp/test.txt"}}]}
        """
        let result = engine.interceptResponse(body: body)
        XCTAssertNotNil(result)
        XCTAssertTrue(result!.blocked.isEmpty, "benign tool call should not be blocked")
        XCTAssertEqual(result!.allowed.count, 1)
        XCTAssertEqual(result!.allowed.first?.toolName, "read_file")
    }

    func testInterceptResponseBlocked() throws {
        try engine.initialize()

        let body = """
        {"content":[{"type":"tool_use","id":"t1","name":"write_file","input":{"file_path":"/etc/crontab","content":"evil"}}]}
        """
        let result = engine.interceptResponse(body: body)
        XCTAssertNotNil(result)
        XCTAssertFalse(result!.blocked.isEmpty, "malicious tool call should be blocked")
    }

    // MARK: - Validation

    func testValidateYAMLValid() throws {
        try engine.initialize()

        let yaml = """
        rules:
          - name: valid-rule
            message: test
            actions: [read]
            block: "/secret/**"
        """
        XCTAssertNil(engine.validateYAML(yaml))
    }

    func testValidateYAMLInvalid() throws {
        try engine.initialize()

        let invalid = "not: valid: yaml: ["
        XCTAssertNotNil(engine.validateYAML(invalid))
    }

    // MARK: - Version

    func testVersion() throws {
        let version = engine.version
        XCTAssertFalse(version.isEmpty, "version should not be empty")
    }

    // MARK: - Lifecycle

    func testShutdownAndReinit() throws {
        try engine.initialize()
        XCTAssertGreaterThan(engine.ruleCount, 0)

        engine.shutdown()
        XCTAssertEqual(engine.ruleCount, 0)

        try engine.initialize()
        XCTAssertGreaterThan(engine.ruleCount, 0)
    }

    func testDoubleShutdown() {
        engine.shutdown()
        engine.shutdown()  // should not crash
    }
}
