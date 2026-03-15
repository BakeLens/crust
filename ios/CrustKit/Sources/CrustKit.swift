// CrustKit — Swift wrapper around the gomobile-generated Libcrust framework.
//
// This provides a Swift-native API on top of the raw gomobile bindings,
// adding proper error handling, Codable types, and actor isolation.

import Foundation
import Libcrust // gomobile-generated framework
#if canImport(UIKit) && !os(macOS)
    import UIKit
#endif

// MARK: - Public types

/// Result of evaluating a tool call against Crust rules.
public struct EvaluationResult: Codable, Sendable {
    public let matched: Bool
    public let ruleName: String?
    public let severity: String?
    public let action: String?
    public let message: String?
    public let error: String?

    private enum CodingKeys: String, CodingKey {
        case matched
        case ruleName = "rule_name"
        case severity, action, message, error
    }
}

/// Result of intercepting an LLM API response.
public struct InterceptionResult: Codable, Sendable {
    public let modifiedResponse: String
    public let blocked: [BlockedCall]
    public let allowed: [AllowedCall]

    private enum CodingKeys: String, CodingKey {
        case modifiedResponse = "modified_response"
        case blocked, allowed
    }
}

public struct BlockedCall: Codable, Sendable {
    public let toolName: String
    public let rule: String
    public let message: String

    private enum CodingKeys: String, CodingKey {
        case toolName = "tool_name"
        case rule, message
    }
}

public struct AllowedCall: Codable, Sendable {
    public let toolName: String

    private enum CodingKeys: String, CodingKey {
        case toolName = "tool_name"
    }
}

/// API type for response interception.
public enum APIType: String, Sendable {
    case anthropic
    case openai
    case openaiResponses = "openai_responses"
}

/// How blocked tool calls are handled.
public enum BlockMode: String, Sendable {
    case remove
    case replace
}

/// Result of scanning content for secrets/PII.
public struct ContentScanResult: Codable, Sendable {
    public let matched: Bool
    public let patternName: String?
    public let message: String?
    public let severity: String?
    public let error: String?

    private enum CodingKeys: String, CodingKey {
        case matched
        case patternName = "pattern_name"
        case message, severity, error
    }
}

/// Result of validating a URL against scheme rules.
public struct URLValidationResult: Codable, Sendable {
    public let scheme: String
    public let blocked: Bool
    public let rule: String?
    public let message: String?
    public let error: String?
}

// MARK: - CrustEngine

/// Thread-safe wrapper around the Crust rule engine.
/// The underlying Go library handles its own synchronization.
public final class CrustEngine: Sendable {
    public init() {}

    /// Initialize with builtin rules and optional user rules directory.
    public func initialize(userRulesDir: String = "") throws {
        var error: NSError?
        LibcrustInit(userRulesDir, &error)
        if let error { throw error }
    }

    /// Initialize with builtin rules plus additional YAML rules.
    public func initialize(yaml: String) throws {
        var error: NSError?
        LibcrustInitWithYAML(yaml, &error)
        if let error { throw error }
    }

    /// Add rules from a YAML string (engine must be initialized).
    public func addRules(yaml: String) throws {
        var error: NSError?
        LibcrustAddRulesYAML(yaml, &error)
        if let error { throw error }
    }

    /// Evaluate a tool call against loaded rules.
    public func evaluate(toolName: String, arguments: [String: Any]) -> EvaluationResult {
        let argsJSON: String = if let data = try? JSONSerialization.data(withJSONObject: arguments),
                                  let json = String(data: data, encoding: .utf8)
        {
            json
        } else {
            "{}"
        }

        let resultJSON = LibcrustEvaluate(toolName, argsJSON)
        return decode(resultJSON) ?? EvaluationResult(
            matched: false, ruleName: nil, severity: nil,
            action: nil, message: nil, error: "decode failed"
        )
    }

    /// Evaluate with a pre-encoded JSON arguments string.
    public func evaluate(toolName: String, argumentsJSON: String) -> EvaluationResult {
        let resultJSON = LibcrustEvaluate(toolName, argumentsJSON)
        return decode(resultJSON) ?? EvaluationResult(
            matched: false, ruleName: nil, severity: nil,
            action: nil, message: nil, error: "decode failed"
        )
    }

    /// Intercept tool calls in an LLM API response.
    public func interceptResponse(
        body: String,
        apiType: APIType = .anthropic,
        blockMode: BlockMode = .remove
    ) -> InterceptionResult? {
        let resultJSON = LibcrustInterceptResponse(body, apiType.rawValue, blockMode.rawValue)
        return decode(resultJSON)
    }

    /// Number of loaded rules.
    public var ruleCount: Int {
        Int(LibcrustRuleCount())
    }

    /// Validate a YAML rules string. Returns nil on success, error message on failure.
    public func validateYAML(_ yaml: String) -> String? {
        let msg = LibcrustValidateYAML(yaml)
        return msg.isEmpty ? nil : msg
    }

    /// Library version string.
    public var version: String {
        LibcrustGetVersion()
    }

    /// Release engine resources.
    public func shutdown() {
        LibcrustShutdown()
    }

    // MARK: - Content Scanning

    /// Scan any text for secrets, PII, or sensitive data using the DLP engine.
    public func scanContent(_ content: String) -> ContentScanResult {
        let resultJSON = LibcrustScanContent(content)
        return decode(resultJSON) ?? ContentScanResult(
            matched: false, patternName: nil, message: nil,
            severity: nil, error: "decode failed"
        )
    }

    /// Scan outbound user→AI message for secrets before sending.
    /// Alias for `scanContent` — same DLP engine, clearer intent.
    public func scanOutbound(_ content: String) -> ContentScanResult {
        scanContent(content)
    }

    /// Validate a URL against mobile URL scheme rules.
    /// Returns whether the URL scheme is blocked (e.g. tel:, sms:).
    public func validateURL(_ rawURL: String) -> URLValidationResult {
        let resultJSON = LibcrustValidateURL(rawURL)
        return decode(resultJSON) ?? URLValidationResult(
            scheme: "", blocked: false, rule: nil,
            message: nil, error: "decode failed"
        )
    }

    /// Scan clipboard contents for secrets.
    /// Uses UIPasteboard on iOS; returns not-matched on non-iOS platforms.
    ///
    /// - Important: Must be called from the main thread (UIPasteboard requirement).
    ///   Use ``scanClipboardAsync()`` from background contexts.
    @MainActor
    public func scanClipboard() -> ContentScanResult {
        #if canImport(UIKit) && !os(macOS)
            guard let text = UIPasteboard.general.string, !text.isEmpty else {
                return ContentScanResult(
                    matched: false, patternName: nil, message: nil,
                    severity: nil, error: nil
                )
            }
            return scanContent(text)
        #else
            return ContentScanResult(
                matched: false, patternName: nil, message: nil,
                severity: nil, error: "clipboard scanning requires UIKit"
            )
        #endif
    }

    // MARK: - Local Proxy

    /// Start a local reverse proxy that intercepts AI API responses.
    ///
    /// The proxy listens on `127.0.0.1:<port>` and forwards requests to `upstreamURL`.
    /// Responses are filtered through the Crust rule engine before being returned.
    ///
    /// Configure your AI SDK's base URL to `http://127.0.0.1:<port>` to route
    /// traffic through Crust. For example:
    ///
    /// ```swift
    /// let engine = CrustEngine()
    /// try engine.initialize()
    /// try engine.startProxy(port: 8080, upstreamURL: "https://api.anthropic.com")
    /// // Set your AI SDK base URL to http://127.0.0.1:8080
    /// ```
    ///
    /// - Parameters:
    ///   - port: Local port to listen on (e.g. 8080). Use 0 for a system-assigned port.
    ///   - upstreamURL: The real AI API endpoint (e.g. "https://api.anthropic.com").
    ///   - apiKey: Optional API key injected into upstream requests.
    ///   - apiType: API format: `.anthropic`, `.openai`, or `.openaiResponses`.
    public func startProxy(
        port: Int = 0,
        upstreamURL: String,
        apiKey: String = "",
        apiType: APIType = .anthropic
    ) throws {
        var error: NSError?
        LibcrustStartProxy(port, upstreamURL, apiKey, apiType.rawValue, &error)
        if let error { throw error }
    }

    /// Stop the local proxy. Safe to call if not running.
    public func stopProxy() {
        LibcrustStopProxy()
    }

    /// The address the proxy is listening on (e.g. "127.0.0.1:8080"),
    /// or nil if the proxy is not running.
    public var proxyAddress: String? {
        let addr = LibcrustProxyAddress()
        return addr.isEmpty ? nil : addr
    }

    /// The full base URL for the proxy (e.g. "http://127.0.0.1:8080"),
    /// or nil if the proxy is not running.
    /// Pass this to your AI SDK as the base URL.
    public var proxyBaseURL: URL? {
        guard let addr = proxyAddress else { return nil }
        return URL(string: "http://\(addr)")
    }

    /// Whether streaming interception is supported.
    /// Returns true — streaming requests are transparently converted to
    /// non-streaming for full security evaluation by the proxy.
    public var streamInterceptionSupported: Bool {
        LibcrustStreamInterceptionSupported()
    }

    // MARK: - Async API

    /// Evaluate a tool call off the main thread.
    public func evaluateAsync(
        toolName: String,
        arguments: [String: Any]
    ) async -> EvaluationResult {
        await Task.detached { [self] in
            evaluate(toolName: toolName, arguments: arguments)
        }.value
    }

    /// Evaluate with a pre-encoded JSON arguments string, off the main thread.
    public func evaluateAsync(
        toolName: String,
        argumentsJSON: String
    ) async -> EvaluationResult {
        await Task.detached { [self] in
            evaluate(toolName: toolName, argumentsJSON: argumentsJSON)
        }.value
    }

    /// Intercept tool calls in an LLM API response, off the main thread.
    public func interceptResponseAsync(
        body: String,
        apiType: APIType = .anthropic,
        blockMode: BlockMode = .remove
    ) async -> InterceptionResult? {
        await Task.detached { [self] in
            interceptResponse(body: body, apiType: apiType, blockMode: blockMode)
        }.value
    }

    /// Validate a YAML rules string off the main thread.
    public func validateYAMLAsync(_ yaml: String) async -> String? {
        await Task.detached { [self] in
            validateYAML(yaml)
        }.value
    }

    /// Scan content for secrets off the main thread.
    public func scanContentAsync(_ content: String) async -> ContentScanResult {
        await Task.detached { [self] in
            scanContent(content)
        }.value
    }

    /// Scan outbound user→AI message off the main thread.
    public func scanOutboundAsync(_ content: String) async -> ContentScanResult {
        await Task.detached { [self] in
            scanOutbound(content)
        }.value
    }

    /// Validate a URL against scheme rules off the main thread.
    public func validateURLAsync(_ rawURL: String) async -> URLValidationResult {
        await Task.detached { [self] in
            validateURL(rawURL)
        }.value
    }

    /// Scan clipboard contents asynchronously.
    /// Reads the clipboard on the main thread, then scans on a background thread.
    public func scanClipboardAsync() async -> ContentScanResult {
        #if canImport(UIKit) && !os(macOS)
            // UIPasteboard must be accessed on the main thread.
            let text: String? = await MainActor.run {
                UIPasteboard.general.string
            }
            guard let text, !text.isEmpty else {
                return ContentScanResult(
                    matched: false, patternName: nil, message: nil,
                    severity: nil, error: nil
                )
            }
            return await scanContentAsync(text)
        #else
            return ContentScanResult(
                matched: false, patternName: nil, message: nil,
                severity: nil, error: "clipboard scanning requires UIKit"
            )
        #endif
    }

    // MARK: - Private

    private func decode<T: Decodable>(_ json: String) -> T? {
        guard let data = json.data(using: .utf8) else { return nil }
        return try? JSONDecoder().decode(T.self, from: data)
    }
}

// MARK: - CrustURLProtocol

/// A URLProtocol that automatically intercepts URLSession requests to AI API
/// endpoints and filters responses through the Crust rule engine.
///
/// This is a zero-config alternative to the local proxy — register it once
/// and all URLSession traffic to matched hosts is protected automatically.
///
/// Usage:
/// ```swift
/// let engine = CrustEngine()
/// try engine.initialize()
///
/// // Register the protocol (must be done before creating URLSessions).
/// CrustURLProtocol.engine = engine
/// CrustURLProtocol.interceptedHosts = [
///     "api.anthropic.com",
///     "api.openai.com",
/// ]
///
/// // Option A: Register globally for URLSession.shared
/// URLSessionConfiguration.registerCrustProtocol()
///
/// // Option B: Register on a specific session configuration
/// let config = URLSessionConfiguration.default
/// config.protocolClasses = [CrustURLProtocol.self] + (config.protocolClasses ?? [])
/// let session = URLSession(configuration: config)
///
/// // All requests through this session to intercepted hosts are now protected.
/// ```
///
/// Limitations:
/// - Only works for URLSession-based networking (not NWConnection, raw sockets, etc.)
/// - Streaming (SSE) responses are passed through without interception by URLProtocol;
///   use the local proxy (``startProxy``) for full streaming protection
/// - The protocol must be registered before creating the URLSession
public final class CrustURLProtocol: URLProtocol {
    // MARK: - Thread-safe static configuration

    private static let lock = NSLock()
    private static var _engine: CrustEngine?
    private static var _interceptedHosts: Set<String> = [
        "api.anthropic.com",
        "api.openai.com",
    ]
    private static var _blockMode: BlockMode = .remove

    /// The Crust engine used for rule evaluation. Must be set before use.
    public static var engine: CrustEngine? {
        get { lock.withLock { _engine } }
        set { lock.withLock { _engine = newValue } }
    }

    /// Hosts to intercept (e.g. ["api.anthropic.com", "api.openai.com"]).
    /// Requests to other hosts pass through unmodified.
    public static var interceptedHosts: Set<String> {
        get { lock.withLock { _interceptedHosts } }
        set { lock.withLock { _interceptedHosts = newValue } }
    }

    /// Block mode for intercepted responses.
    public static var blockMode: BlockMode {
        get { lock.withLock { _blockMode } }
        set { lock.withLock { _blockMode = newValue } }
    }

    /// Key used to mark requests we've already handled (prevent infinite recursion).
    private static let handledKey = "com.bakelens.crust.handled"

    /// Shared session for upstream requests (avoids per-request session leak).
    private static let upstreamSession: URLSession = {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [] // no custom protocols — prevents recursion
        return URLSession(configuration: config)
    }()

    private var dataTask: URLSessionDataTask?

    // MARK: - URLProtocol overrides

    override public class func canInit(with request: URLRequest) -> Bool {
        // Don't intercept if no engine configured.
        guard engine != nil else { return false }

        // Don't re-intercept requests we've already handled.
        guard URLProtocol.property(forKey: handledKey, in: request) == nil else {
            return false
        }

        // Only intercept requests to configured hosts.
        guard let host = request.url?.host else { return false }
        return interceptedHosts.contains(host)
    }

    override public class func canonicalRequest(for request: URLRequest) -> URLRequest {
        request
    }

    override public func startLoading() {
        guard let engine = CrustURLProtocol.engine else {
            let error = NSError(
                domain: "CrustKit",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "CrustEngine not configured"]
            )
            client?.urlProtocol(self, didFailWithError: error)
            return
        }

        // Mark the request as handled so we don't intercept it again.
        let mutableRequest = (request as NSURLRequest).mutableCopy() as! NSMutableURLRequest
        URLProtocol.setProperty(true, forKey: CrustURLProtocol.handledKey, in: mutableRequest)

        // Detect API type from URL.
        let apiType = Self.detectAPIType(from: request.url)

        // Check if this is a streaming request.
        let isStreaming = Self.isStreamingRequest(request)

        dataTask = Self.upstreamSession.dataTask(with: mutableRequest as URLRequest) { [weak self] data, response, error in
            guard let self else { return }

            if let error {
                client?.urlProtocol(self, didFailWithError: error)
                return
            }

            guard let httpResponse = response as? HTTPURLResponse,
                  let data
            else {
                let error = NSError(
                    domain: "CrustKit",
                    code: 2,
                    userInfo: [NSLocalizedDescriptionKey: "Invalid response from upstream"]
                )
                client?.urlProtocol(self, didFailWithError: error)
                return
            }

            // Intercept non-streaming successful responses.
            var responseData = data
            if !isStreaming, httpResponse.statusCode >= 200, httpResponse.statusCode < 300 {
                if let body = String(data: data, encoding: .utf8) {
                    let result = engine.interceptResponse(
                        body: body,
                        apiType: apiType,
                        blockMode: CrustURLProtocol.blockMode
                    )
                    if let result, !result.blocked.isEmpty {
                        responseData = result.modifiedResponse.data(using: .utf8) ?? data
                    }
                }
            }

            // Build a new response with potentially modified content length.
            let headers = Self.updatedHeaders(
                from: httpResponse,
                newContentLength: responseData.count
            )
            if let newResponse = HTTPURLResponse(
                url: httpResponse.url ?? request.url!,
                statusCode: httpResponse.statusCode,
                httpVersion: "HTTP/1.1",
                headerFields: headers
            ) {
                client?.urlProtocol(self, didReceive: newResponse, cacheStoragePolicy: .notAllowed)
            }

            client?.urlProtocol(self, didLoad: responseData)
            client?.urlProtocolDidFinishLoading(self)
        }

        dataTask?.resume()
    }

    override public func stopLoading() {
        dataTask?.cancel()
        dataTask = nil
    }

    // MARK: - Helpers

    /// NOTE: Keep in sync with detectAPITypeFromPath() in pkg/libcrust/proxy.go.
    private static func detectAPIType(from url: URL?) -> APIType {
        guard let path = url?.path else { return .openai }
        if path.contains("/v1/messages") || path.contains("/anthropic") {
            return .anthropic
        }
        if path.contains("/v1/responses") || path.hasSuffix("/responses") {
            return .openaiResponses
        }
        return .openai
    }

    private static func isStreamingRequest(_ request: URLRequest) -> Bool {
        guard let body = request.httpBody,
              let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any]
        else {
            return false
        }
        return json["stream"] as? Bool == true
    }

    private static func updatedHeaders(
        from response: HTTPURLResponse,
        newContentLength: Int
    ) -> [String: String] {
        var headers = [String: String]()
        for (key, value) in response.allHeaderFields {
            if let k = key as? String, let v = value as? String {
                headers[k] = v
            }
        }
        headers["Content-Length"] = String(newContentLength)
        // Remove transfer-encoding since we're sending the full body at once.
        headers.removeValue(forKey: "Transfer-Encoding")
        return headers
    }
}

// MARK: - URLSessionConfiguration convenience

public extension URLSessionConfiguration {
    /// Register CrustURLProtocol on this configuration.
    /// Call this before creating a URLSession with this configuration.
    func registerCrustProtocol() {
        protocolClasses = [CrustURLProtocol.self] + (protocolClasses ?? [])
    }

    /// Create a configuration with CrustURLProtocol already registered.
    static var crustProtected: URLSessionConfiguration {
        let config = URLSessionConfiguration.default
        config.registerCrustProtocol()
        return config
    }
}
