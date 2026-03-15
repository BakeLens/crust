// CrustProxy Usage Examples
//
// Crust's local reverse proxy intercepts AI API responses on-device.
// Instead of packet-level interception (which requires TCP reassembly,
// TLS termination, and a Network Extension entitlement), the proxy
// runs as a plain HTTP server inside your app process.
//
// Architecture:
//
//   Your App (AI SDK)
//       │ base_url = http://127.0.0.1:8080
//       ▼
//   CrustProxy (in-process, port 8080)
//       │ intercepts tool calls in responses
//       ▼
//   https://api.anthropic.com (or OpenAI, etc.)

import Foundation

// MARK: - Basic Usage

/// Minimal integration — three lines to protect your app.
func basicExample() throws {
    let engine = CrustEngine()

    // 1. Initialize the rule engine (loads 30+ builtin security rules).
    try engine.initialize()

    // 2. Start the local proxy targeting Anthropic's API.
    try engine.startProxy(
        port: 8080,
        upstreamURL: "https://api.anthropic.com",
        apiKey: "sk-ant-...", // or leave empty to pass through from client
        apiType: .anthropic
    )

    // 3. Point your AI SDK at the proxy instead of the real API.
    //    e.g. AnthropicClient(baseURL: engine.proxyBaseURL!)
    print("Proxy running at \(engine.proxyBaseURL!)")

    // When done:
    engine.stopProxy()
    engine.shutdown()
}

// MARK: - With Custom Rules

/// Add project-specific rules on top of builtins.
func customRulesExample() throws {
    let engine = CrustEngine()
    try engine.initialize()

    // Block access to your app's private database.
    try engine.addRules(yaml: """
    rules:
      - name: protect-app-db
        message: "Blocked: AI agent cannot access app database"
        actions: [read, write, delete]
        block: "/var/mobile/Containers/Data/Application/*/Documents/*.sqlite"
    """)

    try engine.startProxy(port: 0, upstreamURL: "https://api.openai.com")

    // Port 0 = system-assigned. Read the actual address:
    print("Proxy running at \(engine.proxyAddress ?? "not running")")
}

// MARK: - OpenAI Integration

/// Works with any OpenAI-compatible API.
func openAIExample() throws {
    let engine = CrustEngine()
    try engine.initialize()

    try engine.startProxy(
        port: 8080,
        upstreamURL: "https://api.openai.com",
        apiKey: "sk-...",
        apiType: .openai
    )

    // Your OpenAI SDK request goes to http://127.0.0.1:8080/v1/chat/completions
    // Crust intercepts the response and blocks dangerous tool calls.
}

// MARK: - SwiftUI Integration

/*
 import SwiftUI

 @Observable
 final class AIManager {
     private let engine = CrustEngine()
     private(set) var isProtected = false
     private(set) var proxyURL: URL?

     func start(upstream: String, apiKey: String) throws {
         try engine.initialize()
         try engine.startProxy(
             port: 0,
             upstreamURL: upstream,
             apiKey: apiKey
         )
         proxyURL = engine.proxyBaseURL
         isProtected = true
     }

     func stop() {
         engine.stopProxy()
         engine.shutdown()
         isProtected = false
         proxyURL = nil
     }

     /// Check a tool call manually (for apps that don't use the proxy).
     func check(tool: String, args: [String: Any]) -> EvaluationResult {
         engine.evaluate(toolName: tool, arguments: args)
     }
 }

 struct ContentView: View {
     @State private var manager = AIManager()

     var body: some View {
         VStack {
             if manager.isProtected {
                 Label("Protected", systemImage: "shield.checkmark.fill")
                 Text(manager.proxyURL?.absoluteString ?? "")
                     .font(.caption)
             } else {
                 Button("Enable Protection") {
                     try? manager.start(
                         upstream: "https://api.anthropic.com",
                         apiKey: ""
                     )
                 }
             }
         }
     }
 }
 */

// MARK: - CrustURLProtocol (Zero-Config Alternative)

/// Use CrustURLProtocol when you don't want to run a local proxy.
/// It hooks into URLSession directly — no port, no base URL change.
func urlProtocolExample() throws {
    let engine = CrustEngine()
    try engine.initialize()

    // Configure once at app launch.
    CrustURLProtocol.engine = engine
    CrustURLProtocol.interceptedHosts = [
        "api.anthropic.com",
        "api.openai.com",
    ]

    // Option A: Protect a specific URLSession.
    let config = URLSessionConfiguration.crustProtected
    let session = URLSession(configuration: config)

    // Option B: Or register on an existing config.
    // let config = URLSessionConfiguration.default
    // config.registerCrustProtocol()

    // All requests through this session to matched hosts are now protected.
    // No base URL change needed — the SDK keeps using https://api.anthropic.com.
    _ = session
}

// MARK: - Async API

/// Use async variants to avoid blocking the main thread.
func asyncExample() async throws {
    let engine = CrustEngine()
    try engine.initialize()

    // Safe to call from @MainActor — the Go work runs on a background thread.
    let result = await engine.evaluateAsync(
        toolName: "write_file",
        arguments: ["file_path": "/etc/crontab", "content": "evil"]
    )

    if result.matched {
        print("Blocked: \(result.message ?? "unknown reason")")
    }

    // Intercept a full API response asynchronously.
    let body = """
    {"content":[{"type":"tool_use","id":"t1","name":"read_contacts","input":{}}]}
    """
    let interception = await engine.interceptResponseAsync(body: body)
    if let interception {
        print("Blocked \(interception.blocked.count) tool calls")
    }
}

// MARK: - Choosing Between Proxy and URLProtocol

//
// Use the local proxy (startProxy) when:
//   - Your AI SDK doesn't use URLSession (e.g. uses NWConnection, gRPC, etc.)
//   - You need to protect multiple processes or extensions
//   - You want explicit control over the proxy lifecycle
//
// Use CrustURLProtocol when:
//   - Your AI SDK uses URLSession (most Swift SDKs do)
//   - You want zero-config integration with no base URL changes
//   - You're adding Crust to an existing app with minimal changes
//
// Both approaches use the same rule engine and provide identical security.

// MARK: - Content Scanning

/// Scan AI text responses and user input for secrets/PII.
func contentScanningExample() throws {
    let engine = CrustEngine()
    try engine.initialize()

    // Scan an AI text response for leaked secrets.
    // nosemgrep: generic.secrets.security.detected-github-token.detected-github-token -- fake token for DLP test
    let aiResponse = "Here's your config: API_KEY=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij12"
    let scanResult = engine.scanContent(aiResponse)
    if scanResult.matched {
        print("Secret found in AI response: \(scanResult.message ?? "")")
        // Don't display this response to the user.
    }

    // Scan user input before sending to AI (outbound DLP).
    let userMessage = "Please use this key: ghp_TestSecretTokenForDLP00000000000000scan"
    let outboundResult = engine.scanOutbound(userMessage)
    if outboundResult.matched {
        print("Warning: your message contains a secret — \(outboundResult.message ?? "")")
        // Warn the user or block the message.
    }

    // Clipboard guard — check before pasting into AI chat.
    let clipResult = engine.scanClipboard()
    if clipResult.matched {
        print("Clipboard contains sensitive data: \(clipResult.message ?? "")")
    }
}

// MARK: - URL Validation

/// Validate URLs before opening them (e.g. links from AI responses).
func urlValidationExample() throws {
    let engine = CrustEngine()
    try engine.initialize()

    let urls = ["tel:+1234567890", "https://example.com", "sms:+1234567890"]

    for url in urls {
        let result = engine.validateURL(url)
        if result.blocked {
            print("Blocked URL: \(url) (rule: \(result.rule ?? ""), \(result.message ?? ""))")
        } else {
            print("Allowed URL: \(url)")
            // Safe to open with UIApplication.shared.open(...)
        }
    }
}

// MARK: - Network Extension (Alternative)

//
// If you need to intercept traffic from apps you don't control
// (e.g. an enterprise MDM scenario), you can still use the proxy
// inside a Network Extension. But instead of raw packet handling,
// use NETransparentProxyProvider which gives you TCP/UDP flows —
// much simpler than NEPacketTunnelProvider.
//
// For most apps where you control the AI SDK configuration,
// the in-process proxy or URLProtocol above is simpler, faster,
// and doesn't require special entitlements.
