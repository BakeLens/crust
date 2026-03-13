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

    // MARK: - Mobile Virtual Path Rules

    func testMobilePIIBlocked() throws {
        try engine.initialize()

        let tools: [(String, [String: String])] = [
            ("read_contacts", [:]),
            ("access_photos", [:]),
            ("read_calendar", [:]),
            ("get_location", [:]),
            ("read_health_data", [:]),
        ]

        for (tool, args) in tools {
            let result = engine.evaluate(toolName: tool, arguments: args)
            XCTAssertTrue(result.matched, "\(tool) should be blocked by protect-mobile-pii")
        }
    }

    func testMobileKeychainBlocked() throws {
        try engine.initialize()

        let result = engine.evaluate(
            toolName: "keychain_get",
            arguments: ["key": "api_token"]
        )
        XCTAssertTrue(result.matched, "keychain_get should be blocked by protect-os-keychains")
    }

    func testMobileClipboardReadBlocked() throws {
        try engine.initialize()

        let readResult = engine.evaluate(toolName: "read_clipboard", arguments: [:])
        XCTAssertTrue(readResult.matched, "read_clipboard should be blocked")

        let writeResult = engine.evaluate(toolName: "write_clipboard", arguments: [:])
        XCTAssertFalse(writeResult.matched, "write_clipboard should be allowed")
    }

    func testMobileURLSchemeBlocked() throws {
        try engine.initialize()

        // tel: should be blocked
        let telResult = engine.evaluate(
            toolName: "open_url",
            arguments: ["url": "tel:+1234567890"]
        )
        XCTAssertTrue(telResult.matched, "tel: URL should be blocked")

        // sms: should be blocked
        let smsResult = engine.evaluate(
            toolName: "open_url",
            arguments: ["url": "sms:+1234567890"]
        )
        XCTAssertTrue(smsResult.matched, "sms: URL should be blocked")

        // https: should be allowed
        let httpsResult = engine.evaluate(
            toolName: "open_url",
            arguments: ["url": "https://example.com"]
        )
        XCTAssertFalse(httpsResult.matched, "https: URL should be allowed")
    }

    func testMobilePersistenceBlocked() throws {
        try engine.initialize()

        let result = engine.evaluate(
            toolName: "schedule_task",
            arguments: ["task_id": "sync_data"]
        )
        XCTAssertTrue(result.matched, "schedule_task should be blocked by protect-persistence")
    }

    func testMobileInterceptResponseBlocked() throws {
        try engine.initialize()

        let body = """
        {"content":[{"type":"tool_use","id":"m1","name":"read_contacts","input":{}}]}
        """
        let result = engine.interceptResponse(body: body)
        XCTAssertNotNil(result)
        XCTAssertFalse(result!.blocked.isEmpty, "read_contacts should be blocked in interception")
    }
}
