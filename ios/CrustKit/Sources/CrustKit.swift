// CrustKit — Swift wrapper around the gomobile-generated Libcrust framework.
//
// This provides a Swift-native API on top of the raw gomobile bindings,
// adding proper error handling, Codable types, and actor isolation.

import Foundation
import Libcrust  // gomobile-generated framework

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
        let argsJSON: String
        if let data = try? JSONSerialization.data(withJSONObject: arguments),
           let json = String(data: data, encoding: .utf8) {
            argsJSON = json
        } else {
            argsJSON = "{}"
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

    // MARK: - Private

    private func decode<T: Decodable>(_ json: String) -> T? {
        guard let data = json.data(using: .utf8) else { return nil }
        return try? JSONDecoder().decode(T.self, from: data)
    }
}
