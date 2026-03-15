@testable import CrustKit
import XCTest

final class CrustKitTests: CrustEngineTestCase {
    // MARK: - Initialization

    func testInitWithBuiltinRules() {
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

    func testAllowedToolCall() {
        let result = engine.evaluate(
            toolName: "read_file",
            arguments: ["path": "/tmp/test.txt"]
        )
        XCTAssertFalse(result.matched, "reading /tmp/test.txt should be allowed")
    }

    func testBlockedToolCall() {
        let result = engine.evaluate(
            toolName: "write_file",
            arguments: ["file_path": "/etc/crontab", "content": "* * * * * evil"]
        )
        XCTAssertTrue(result.matched, "writing to /etc/crontab should be blocked")
        XCTAssertNotNil(result.ruleName)
        XCTAssertNotNil(result.message)
    }

    func testEvaluateWithJSONString() {
        let result = engine.evaluate(
            toolName: "read_file",
            argumentsJSON: #"{"path":"/tmp/safe.txt"}"#
        )
        XCTAssertFalse(result.matched)
    }

    // MARK: - Response interception

    func testInterceptResponseAllowed() throws {
        let body = """
        {"content":[{"type":"tool_use","id":"t1","name":"read_file","input":{"path":"/tmp/test.txt"}}]}
        """
        let result = engine.interceptResponse(body: body)
        XCTAssertNotNil(result)
        XCTAssertTrue(try XCTUnwrap(result?.blocked.isEmpty), "benign tool call should not be blocked")
        XCTAssertEqual(result?.allowed.count, 1)
        XCTAssertEqual(result?.allowed.first?.toolName, "read_file")
    }

    func testInterceptResponseBlocked() throws {
        let body = """
        {"content":[{"type":"tool_use","id":"t1","name":"write_file","input":{"file_path":"/etc/crontab","content":"evil"}}]}
        """
        let result = engine.interceptResponse(body: body)
        XCTAssertNotNil(result)
        XCTAssertFalse(try XCTUnwrap(result?.blocked.isEmpty), "malicious tool call should be blocked")
    }

    // MARK: - Validation

    func testValidateYAMLValid() {
        let yaml = """
        rules:
          - name: valid-rule
            message: test
            actions: [read]
            block: "/secret/**"
        """
        XCTAssertNil(engine.validateYAML(yaml))
    }

    func testValidateYAMLInvalid() {
        let invalid = "not: valid: yaml: ["
        XCTAssertNotNil(engine.validateYAML(invalid))
    }

    // MARK: - Version

    func testVersion() {
        let version = engine.version
        XCTAssertFalse(version.isEmpty, "version should not be empty")
    }

    // MARK: - Lifecycle

    func testShutdownAndReinit() throws {
        XCTAssertGreaterThan(engine.ruleCount, 0)

        engine.shutdown()
        XCTAssertEqual(engine.ruleCount, 0)

        try engine.initialize()
        XCTAssertGreaterThan(engine.ruleCount, 0)
    }

    func testDoubleShutdown() {
        engine.shutdown()
        engine.shutdown() // should not crash
    }

    // MARK: - Mobile Virtual Path Rules

    func testMobilePIIBlocked() {
        let tools: [(String, [String: String])] = [
            ("read_contacts", [:]),
            ("access_photos", [:]),
            ("read_calendar", [:]),
            ("get_location", [:]),
            ("read_health_data", [:]),
            ("capture_photo", [:]),
            ("record_video", [:]),
            ("record_audio", [:]),
            ("read_call_log", [:]),
            ("read_sms", [:]),
        ]

        for (tool, args) in tools {
            let result = engine.evaluate(toolName: tool, arguments: args)
            XCTAssertTrue(result.matched, "\(tool) should be blocked by mobile PII rules")
        }
    }

    func testMobileHardwareBlocked() {
        let tools: [String] = [
            "scan_bluetooth",
            "bluetooth_connect",
            "read_nfc",
            "write_nfc",
        ]

        for tool in tools {
            let result = engine.evaluate(toolName: tool, arguments: [:])
            XCTAssertTrue(result.matched, "\(tool) should be blocked by protect-mobile-hardware")
        }
    }

    func testMobileBiometricBlocked() {
        let tools: [String] = [
            "authenticate_biometric",
            "face_id",
            "touch_id",
        ]

        for tool in tools {
            let result = engine.evaluate(toolName: tool, arguments: [:])
            XCTAssertTrue(result.matched, "\(tool) should be blocked by protect-mobile-biometric")
        }
    }

    func testMobilePurchaseBlocked() {
        let result = engine.evaluate(
            toolName: "purchase_item",
            arguments: ["product_id": "premium_monthly"]
        )
        XCTAssertTrue(result.matched, "purchase_item should be blocked by protect-mobile-purchases")

        let result2 = engine.evaluate(toolName: "in_app_purchase", arguments: [:])
        XCTAssertTrue(result2.matched, "in_app_purchase should be blocked")
    }

    func testMobileKeychainBlocked() {
        let result = engine.evaluate(
            toolName: "keychain_get",
            arguments: ["key": "api_token"]
        )
        XCTAssertTrue(result.matched, "keychain_get should be blocked by protect-os-keychains")
    }

    func testMobileClipboardReadBlocked() {
        let readResult = engine.evaluate(toolName: "read_clipboard", arguments: [:])
        XCTAssertTrue(readResult.matched, "read_clipboard should be blocked")

        let writeResult = engine.evaluate(toolName: "write_clipboard", arguments: [:])
        XCTAssertFalse(writeResult.matched, "write_clipboard should be allowed")
    }

    func testMobileURLSchemeBlocked() {
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

    func testMobilePersistenceBlocked() {
        let result = engine.evaluate(
            toolName: "schedule_task",
            arguments: ["task_id": "sync_data"]
        )
        XCTAssertTrue(result.matched, "schedule_task should be blocked by protect-persistence")
    }

    func testMobileInterceptResponseBlocked() throws {
        let body = """
        {"content":[{"type":"tool_use","id":"m1","name":"read_contacts","input":{}}]}
        """
        let result = engine.interceptResponse(body: body)
        XCTAssertNotNil(result)
        XCTAssertFalse(try XCTUnwrap(result?.blocked.isEmpty), "read_contacts should be blocked in interception")
    }

    // MARK: - Local Proxy

    func testStartStopProxy() throws {
        try engine.startProxy(port: 0, upstreamURL: "https://api.anthropic.com")
        XCTAssertNotNil(engine.proxyAddress, "proxy should be running")
        XCTAssertNotNil(engine.proxyBaseURL, "should have a base URL")
        XCTAssertTrue(try XCTUnwrap(engine.proxyBaseURL?.absoluteString.hasPrefix("http://127.0.0.1:")))

        engine.stopProxy()
        XCTAssertNil(engine.proxyAddress, "proxy should be stopped")
    }

    func testProxyDoubleStartFails() throws {
        try engine.startProxy(port: 0, upstreamURL: "https://api.anthropic.com")
        defer { engine.stopProxy() }

        // Second start should throw.
        XCTAssertThrowsError(
            try engine.startProxy(port: 0, upstreamURL: "https://api.openai.com")
        )
    }

    func testStopProxyWhenNotRunning() {
        // Should not crash.
        engine.stopProxy()
        engine.stopProxy()
    }

    func testProxyAddressWhenNotRunning() {
        XCTAssertNil(engine.proxyAddress)
        XCTAssertNil(engine.proxyBaseURL)
    }

    func testStreamInterceptionSupported() {
        XCTAssertTrue(engine.streamInterceptionSupported)
    }

    // MARK: - Async API

    func testEvaluateAsync() async {
        let result = await engine.evaluateAsync(
            toolName: "read_file",
            arguments: ["path": "/tmp/test.txt"]
        )
        XCTAssertFalse(result.matched, "reading /tmp/test.txt should be allowed")
    }

    func testEvaluateAsyncBlocked() async {
        let result = await engine.evaluateAsync(
            toolName: "write_file",
            arguments: ["file_path": "/etc/crontab", "content": "evil"]
        )
        XCTAssertTrue(result.matched, "writing to /etc/crontab should be blocked")
        XCTAssertNotNil(result.ruleName)
    }

    func testEvaluateAsyncWithJSON() async {
        let result = await engine.evaluateAsync(
            toolName: "read_file",
            argumentsJSON: #"{"path":"/tmp/safe.txt"}"#
        )
        XCTAssertFalse(result.matched)
    }

    func testInterceptResponseAsync() async throws {
        let body = """
        {"content":[{"type":"tool_use","id":"t1","name":"write_file","input":{"file_path":"/etc/crontab","content":"evil"}}]}
        """
        let result = await engine.interceptResponseAsync(body: body)
        XCTAssertNotNil(result)
        XCTAssertFalse(try XCTUnwrap(result?.blocked.isEmpty), "malicious tool call should be blocked")
    }

    func testValidateYAMLAsync() async {
        let valid = """
        rules:
          - name: async-test
            message: test
            actions: [read]
            block: "/tmp/**"
        """
        let result = await engine.validateYAMLAsync(valid)
        XCTAssertNil(result, "valid YAML should return nil")

        let invalid = "not: valid: yaml: ["
        let errorMsg = await engine.validateYAMLAsync(invalid)
        XCTAssertNotNil(errorMsg, "invalid YAML should return error")
    }

    // MARK: - Content Scanning

    func testScanContentClean() {
        let result = engine.scanContent("Hello, this is a normal message.")
        XCTAssertFalse(result.matched, "clean content should not match")
    }

    func testScanContentSecret() {
        // nosemgrep: generic.secrets.security.detected-github-token.detected-github-token -- fake token for DLP test
        let result = engine.scanContent("Here is a token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij12")
        XCTAssertTrue(result.matched, "GitHub token should be detected")
        XCTAssertNotNil(result.patternName)
        XCTAssertNotNil(result.message)
    }

    func testScanContentVCard() {
        let result = engine.scanContent("BEGIN:VCARD\nVERSION:3.0\nFN:John Doe\nEND:VCARD")
        XCTAssertTrue(result.matched, "vCard should be detected")
    }

    func testScanContentAsync() async {
        // nosemgrep: generic.secrets.security.detected-github-token.detected-github-token -- fake token for DLP test
        let result = await engine.scanContentAsync("Here is a token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij12")
        XCTAssertTrue(result.matched, "GitHub token should be detected async")
    }

    func testScanOutbound() {
        let result = engine.scanOutbound("My API key is ghp_TestSecretTokenForDLP00000000000000scan")
        XCTAssertTrue(result.matched, "API key in outbound message should be detected")
    }

    // MARK: - URL Validation

    func testValidateURLTelBlocked() {
        let result = engine.validateURL("tel:+1234567890")
        XCTAssertTrue(result.blocked, "tel: URL should be blocked")
        XCTAssertEqual(result.scheme, "tel")
    }

    func testValidateURLHttpsAllowed() {
        let result = engine.validateURL("https://example.com")
        XCTAssertFalse(result.blocked, "https: URL should be allowed")
        XCTAssertEqual(result.scheme, "https")
    }

    func testValidateURLSmsBlocked() {
        let result = engine.validateURL("sms:+1234567890")
        XCTAssertTrue(result.blocked, "sms: URL should be blocked")
    }

    func testValidateURLAsync() async {
        let result = await engine.validateURLAsync("tel:+1234567890")
        XCTAssertTrue(result.blocked, "tel: URL should be blocked async")
    }

    // MARK: - CrustURLProtocol

    func testURLProtocolCanInitMatchesConfiguredHosts() throws {
        CrustURLProtocol.engine = engine
        CrustURLProtocol.interceptedHosts = ["api.anthropic.com", "api.openai.com"]

        // Should match configured hosts.
        let anthropicReq = try URLRequest(url: XCTUnwrap(URL(string: "https://api.anthropic.com/v1/messages")))
        XCTAssertTrue(CrustURLProtocol.canInit(with: anthropicReq))

        let openaiReq = try URLRequest(url: XCTUnwrap(URL(string: "https://api.openai.com/v1/chat/completions")))
        XCTAssertTrue(CrustURLProtocol.canInit(with: openaiReq))

        // Should not match other hosts.
        let otherReq = try URLRequest(url: XCTUnwrap(URL(string: "https://example.com/api")))
        XCTAssertFalse(CrustURLProtocol.canInit(with: otherReq))
    }

    func testURLProtocolSkipsWithoutEngine() throws {
        CrustURLProtocol.engine = nil

        let req = try URLRequest(url: XCTUnwrap(URL(string: "https://api.anthropic.com/v1/messages")))
        XCTAssertFalse(CrustURLProtocol.canInit(with: req), "should skip without engine")
    }

    func testURLProtocolDetectsAPIType() throws {
        // The detectAPIType is private, so we test indirectly via canInit
        // and the interceptedHosts configuration.
        CrustURLProtocol.engine = engine
        CrustURLProtocol.interceptedHosts = ["api.anthropic.com"]

        let req = try URLRequest(url: XCTUnwrap(URL(string: "https://api.anthropic.com/v1/messages")))
        XCTAssertTrue(CrustURLProtocol.canInit(with: req))
    }

    func testURLProtocolCrustProtectedConfig() {
        let config = URLSessionConfiguration.crustProtected
        XCTAssertNotNil(config.protocolClasses)
        XCTAssertTrue(
            config.protocolClasses?.contains(where: { $0 == CrustURLProtocol.self }) ?? false,
            "crustProtected config should include CrustURLProtocol"
        )
    }

    func testURLProtocolRegisterOnConfig() {
        let config = URLSessionConfiguration.default
        let beforeCount = config.protocolClasses?.count ?? 0

        config.registerCrustProtocol()

        XCTAssertEqual(config.protocolClasses?.count, beforeCount + 1)
        XCTAssertTrue(
            config.protocolClasses?.first == CrustURLProtocol.self,
            "CrustURLProtocol should be first in the chain"
        )
    }
}
