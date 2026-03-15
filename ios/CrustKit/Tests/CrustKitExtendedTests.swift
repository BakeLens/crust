@testable import CrustKit
import XCTest

// MARK: - Extended tests for OpenAI formats, DLP, error paths, thread safety

final class CrustKitExtendedTests: CrustEngineTestCase {
    // MARK: - OpenAI Response Interception

    func testInterceptResponseOpenAI() throws {
        let args = #"{\"file_path\":\"/etc/crontab\",\"content\":\"evil\"}"#
        let body = """
        {"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"c1",\
        "type":"function","function":{"name":"write_file","arguments":"\(args)"}}]}}]}
        """
        let result = engine.interceptResponse(body: body, apiType: .openai)
        XCTAssertNotNil(result)
        XCTAssertFalse(
            try XCTUnwrap(result?.blocked.isEmpty),
            "malicious tool call should be blocked in OpenAI format"
        )
    }

    func testInterceptResponseOpenAIAllowed() throws {
        let args = #"{\"path\":\"/tmp/test.txt\"}"#
        let body = """
        {"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"c1",\
        "type":"function","function":{"name":"read_file","arguments":"\(args)"}}]}}]}
        """
        let result = engine.interceptResponse(body: body, apiType: .openai)
        XCTAssertNotNil(result)
        XCTAssertTrue(
            try XCTUnwrap(result?.blocked.isEmpty),
            "benign OpenAI tool call should not be blocked"
        )
        XCTAssertEqual(result?.allowed.count, 1)
    }

    func testInterceptResponseOpenAIResponses() throws {
        let args = #"{\"file_path\":\"/etc/crontab\",\"content\":\"evil\"}"#
        let body = """
        {"output":[{"type":"function_call","id":"fc1",\
        "name":"write_file","arguments":"\(args)"}]}
        """
        let result = engine.interceptResponse(body: body, apiType: .openaiResponses)
        XCTAssertNotNil(result)
        XCTAssertFalse(
            try XCTUnwrap(result?.blocked.isEmpty),
            "malicious tool call should be blocked in OpenAI Responses format"
        )
    }

    // MARK: - DLP in Text Responses

    func testInterceptResponseDLPInTextBlock() throws {
        // nosemgrep: generic.secrets.security.detected-github-token.detected-github-token -- fake token for DLP test
        let token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij12"
        let body = """
        {"content":[{"type":"text","text":"Here is your token: \(token)"}]}
        """
        let result = engine.interceptResponse(body: body)
        XCTAssertNotNil(result, "DLP should intercept secrets in text blocks")
        let modified = try XCTUnwrap(result?.modifiedResponse)
        XCTAssertFalse(modified.contains("ghp_ABCDEFGH"), "secret should be redacted")
        XCTAssertTrue(modified.contains("REDACTED"), "should contain REDACTED marker")
    }

    func testInterceptResponseCleanTextBlock() throws {
        let body = """
        {"content":[{"type":"text","text":"Hello, how can I help you today?"}]}
        """
        let result = engine.interceptResponse(body: body)
        XCTAssertNotNil(result)
        XCTAssertTrue(
            try XCTUnwrap(result?.blocked.isEmpty),
            "clean text should not produce blocked calls"
        )
        let modified = try XCTUnwrap(result?.modifiedResponse)
        XCTAssertTrue(modified.contains("Hello, how can I help you today?"))
    }

    // MARK: - BlockMode.replace

    func testInterceptResponseReplaceMode() throws {
        let body = """
        {"content":[{"type":"tool_use","id":"t1","name":"write_file",\
        "input":{"file_path":"/etc/crontab","content":"evil"}}]}
        """
        let result = engine.interceptResponse(body: body, blockMode: .replace)
        XCTAssertNotNil(result)
        XCTAssertFalse(
            try XCTUnwrap(result?.blocked.isEmpty),
            "tool call should still be blocked in replace mode"
        )
        if let modified = result?.modifiedResponse {
            XCTAssertFalse(modified.isEmpty, "replace mode should produce a modified response")
        }
    }

    // MARK: - Error Paths

    func testEvaluateBeforeInitialize() {
        engine.shutdown() // reset to uninitialized state
        let result = engine.evaluate(
            toolName: "write_file",
            arguments: ["file_path": "/etc/crontab", "content": "evil"]
        )
        XCTAssertNotNil(result, "should return a result even without initialization")
    }

    func testInterceptResponseBeforeInitialize() {
        engine.shutdown()
        let body = """
        {"content":[{"type":"tool_use","id":"t1","name":"write_file",\
        "input":{"file_path":"/etc/crontab","content":"evil"}}]}
        """
        _ = engine.interceptResponse(body: body)
    }

    func testScanContentBeforeInitialize() {
        engine.shutdown()
        // nosemgrep: generic.secrets.security.detected-github-token.detected-github-token -- fake token for DLP test
        let result = engine.scanContent("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij12")
        XCTAssertNotNil(result)
    }

    func testValidateURLBeforeInitialize() {
        engine.shutdown()
        let result = engine.validateURL("tel:+1234567890")
        XCTAssertNotNil(result)
    }

    func testInterceptResponseMalformedJSON() {
        let result = engine.interceptResponse(body: "not json at all")
        if let result {
            XCTAssertTrue(result.blocked.isEmpty, "malformed JSON should not produce blocked calls")
        }
    }

    func testEvaluateEmptyToolName() {
        let result = engine.evaluate(toolName: "", arguments: [:])
        XCTAssertFalse(result.matched, "empty tool name should not match")
    }

    // MARK: - Async Variants

    func testScanOutboundAsync() async {
        // nosemgrep: generic.secrets.security.detected-github-token.detected-github-token -- fake token for DLP test
        let result = await engine.scanOutboundAsync(
            "My secret key: ghp_TestSecretTokenForDLP00000000000000scan"
        )
        XCTAssertTrue(result.matched, "API key should be detected in async outbound scan")
    }

    func testValidateURLAsyncAllowed() async {
        let result = await engine.validateURLAsync("https://example.com")
        XCTAssertFalse(result.blocked, "https URL should be allowed async")
        XCTAssertEqual(result.scheme, "https")
    }

    func testValidateURLAsyncMalformed() async {
        let result = await engine.validateURLAsync("not-a-url")
        XCTAssertNotNil(result)
    }

    func testValidateURLAsyncEmpty() async {
        let result = await engine.validateURLAsync("")
        XCTAssertNotNil(result)
    }

    // MARK: - Thread-safe Static Configuration

    func testURLProtocolStaticThreadSafety() {
        let iterations = 100
        let expectation = XCTestExpectation(description: "concurrent access")
        expectation.expectedFulfillmentCount = iterations * 2

        for i in 0 ..< iterations {
            DispatchQueue.global().async {
                CrustURLProtocol.engine = (i % 2 == 0) ? CrustEngine() : nil
                expectation.fulfill()
            }
            DispatchQueue.global().async {
                _ = CrustURLProtocol.engine
                expectation.fulfill()
            }
        }

        wait(for: [expectation], timeout: 5.0)
    }

    func testURLProtocolInterceptedHostsThreadSafety() {
        let iterations = 100
        let expectation = XCTestExpectation(description: "concurrent host access")
        expectation.expectedFulfillmentCount = iterations * 2

        for _ in 0 ..< iterations {
            DispatchQueue.global().async {
                CrustURLProtocol.interceptedHosts = ["api.anthropic.com"]
                expectation.fulfill()
            }
            DispatchQueue.global().async {
                _ = CrustURLProtocol.interceptedHosts
                expectation.fulfill()
            }
        }

        wait(for: [expectation], timeout: 5.0)
    }

    func testURLProtocolBlockModeThreadSafety() {
        let iterations = 100
        let expectation = XCTestExpectation(description: "concurrent block mode access")
        expectation.expectedFulfillmentCount = iterations * 2

        for i in 0 ..< iterations {
            DispatchQueue.global().async {
                CrustURLProtocol.blockMode = (i % 2 == 0) ? .remove : .replace
                expectation.fulfill()
            }
            DispatchQueue.global().async {
                _ = CrustURLProtocol.blockMode
                expectation.fulfill()
            }
        }

        wait(for: [expectation], timeout: 5.0)
    }

    // MARK: - Additional URL Scheme Tests

    func testValidateURLFacetimeBlocked() {
        let result = engine.validateURL("facetime:+1234567890")
        XCTAssertTrue(result.blocked, "facetime: URL should be blocked")
        XCTAssertEqual(result.scheme, "facetime")
    }

    func testValidateURLFacetimeAudioBlocked() {
        let result = engine.validateURL("facetime-audio:+1234567890")
        XCTAssertTrue(result.blocked, "facetime-audio: URL should be blocked")
    }

    func testValidateURLItmsServicesBlocked() {
        let result = engine.validateURL("itms-services://?action=download-manifest")
        XCTAssertTrue(result.blocked, "itms-services: URL should be blocked")
    }

    func testValidateURLAppSettingsBlocked() {
        let result = engine.validateURL("app-settings://")
        XCTAssertTrue(result.blocked, "app-settings: URL should be blocked")
    }

    func testValidateURLHttpAllowed() {
        let result = engine.validateURL("http://example.com")
        XCTAssertFalse(result.blocked, "http: URL should be allowed")
        XCTAssertEqual(result.scheme, "http")
    }

    // MARK: - Content Scanning Edge Cases

    func testScanContentEmpty() {
        let result = engine.scanContent("")
        XCTAssertFalse(result.matched, "empty content should not match")
    }

    func testScanContentBIP39Mnemonic() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon " +
            "abandon abandon abandon abandon abandon about"
        let result = engine.scanContent(mnemonic)
        XCTAssertTrue(result.matched, "BIP39 mnemonic should be detected")
    }

    func testScanContentPrivateKey() {
        let xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy" +
            "6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        let result = engine.scanContent(xprv)
        XCTAssertTrue(result.matched, "BIP32 extended private key should be detected")
    }

    // MARK: - Multiple Tool Calls Interception

    func testInterceptResponseMixedToolCalls() {
        let body = """
        {"content":[\
        {"type":"tool_use","id":"t1","name":"read_file",\
        "input":{"path":"/tmp/test.txt"}},\
        {"type":"tool_use","id":"t2","name":"write_file",\
        "input":{"file_path":"/etc/crontab","content":"evil"}},\
        {"type":"text","text":"Here are the results."}]}
        """
        let result = engine.interceptResponse(body: body)
        XCTAssertNotNil(result)
        XCTAssertEqual(result?.blocked.count, 1, "one tool call should be blocked")
        XCTAssertEqual(result?.allowed.count, 1, "one tool call should be allowed")
        XCTAssertEqual(result?.blocked.first?.toolName, "write_file")
        XCTAssertEqual(result?.allowed.first?.toolName, "read_file")
    }

    func testInterceptResponseAllToolsBlocked() throws {
        let body = """
        {"content":[\
        {"type":"tool_use","id":"t1","name":"write_file",\
        "input":{"file_path":"/etc/shadow","content":"evil"}},\
        {"type":"tool_use","id":"t2","name":"write_file",\
        "input":{"file_path":"/etc/crontab","content":"evil"}}]}
        """
        let result = engine.interceptResponse(body: body)
        XCTAssertNotNil(result)
        XCTAssertEqual(result?.blocked.count, 2, "both tool calls should be blocked")
        XCTAssertTrue(try XCTUnwrap(result?.allowed.isEmpty))
    }

    // MARK: - Clipboard (non-UIKit)

    func testScanClipboardOnNonUIKit() async {
        let result = await engine.scanClipboardAsync()
        #if canImport(UIKit) && !os(macOS)
        // On iOS this would work, can't test here.
        #else
            XCTAssertFalse(result.matched)
            XCTAssertEqual(result.error, "clipboard scanning requires UIKit")
        #endif
    }

    // MARK: - Bug verification tests

    /// FIXED: Google AI (generativelanguage.googleapis.com) removed from default
    /// interceptedHosts since we can't parse its response format yet.
    func testFixGoogleAINotInDefaultHosts() {
        let defaultHosts = CrustURLProtocol.interceptedHosts
        XCTAssertFalse(
            defaultHosts.contains("generativelanguage.googleapis.com"),
            "Google AI should not be in default interceptedHosts"
        )
        XCTAssertTrue(defaultHosts.contains("api.anthropic.com"))
        XCTAssertTrue(defaultHosts.contains("api.openai.com"))
    }

    /// BUG: CrustURLProtocol.canInit reads engine and interceptedHosts in two
    /// separate lock acquisitions. Between the two reads, configuration can change
    /// (TOCTOU race). This test documents the race window.
    func testBugCanInitTOCTOU() throws {
        CrustURLProtocol.engine = engine
        CrustURLProtocol.interceptedHosts = ["api.anthropic.com"]

        let url = try XCTUnwrap(URL(string: "https://api.anthropic.com/v1/messages"))
        let req = URLRequest(url: url)

        // Two separate lock acquisitions in canInit:
        // 1. guard engine != nil   (lock, read, unlock)
        // 2. interceptedHosts.contains(host)  (lock, read, unlock)
        // Between 1 and 2, another thread could set engine = nil.
        // The request would be intercepted, then startLoading would fail.
        // This is benign (startLoading has its own guard) but wasteful.
        XCTAssertTrue(CrustURLProtocol.canInit(with: req))
    }
}
