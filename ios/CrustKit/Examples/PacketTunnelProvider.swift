// PacketTunnelProvider — Network Extension stub for Crust iOS.
//
// This NEPacketTunnelProvider intercepts HTTP traffic on-device and applies
// Crust rule evaluation to LLM API responses before they reach the app.
//
// Setup:
// 1. Add a "Network Extension" target to your Xcode project
// 2. Set the NEProviderClasses key in the extension's Info.plist
// 3. Configure a NETunnelProviderManager in the host app
//
// This is a scaffold — the actual packet parsing and response interception
// logic should be implemented based on your deployment architecture.

import NetworkExtension

class PacketTunnelProvider: NEPacketTunnelProvider {

    private let engine = CrustEngine()

    override func startTunnel(
        options: [String: NSObject]? = nil
    ) async throws {
        // Initialize Crust engine with builtin rules
        try engine.initialize()

        // Load custom rules from the app group container if available
        if let rulesYAML = loadCustomRules() {
            try engine.addRules(yaml: rulesYAML)
        }

        // Configure tunnel network settings
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")

        // Proxy only HTTPS traffic to known AI API endpoints
        let proxySettings = NEProxySettings()
        proxySettings.httpEnabled = true
        proxySettings.httpsEnabled = true
        proxySettings.matchDomains = [
            "api.anthropic.com",
            "api.openai.com",
            "generativelanguage.googleapis.com",
        ]
        settings.proxySettings = proxySettings

        try await setTunnelNetworkSettings(settings)

        // Start reading packets
        readPackets()
    }

    override func stopTunnel(
        with reason: NEProviderStopReason
    ) async {
        engine.shutdown()
    }

    // MARK: - Packet handling (scaffold)

    private func readPackets() {
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self else { return }
            for (i, packet) in packets.enumerated() {
                self.handlePacket(packet, protocol: protocols[i])
            }
            // Continue reading
            self.readPackets()
        }
    }

    private func handlePacket(_ packet: Data, protocol proto: NSNumber) {
        // TODO: Implement HTTP response parsing and Crust interception.
        //
        // High-level flow:
        // 1. Reassemble TCP stream from IP packets
        // 2. Parse HTTP response from AI API endpoints
        // 3. Extract response body
        // 4. Call engine.interceptResponse(body:apiType:blockMode:)
        // 5. If tool calls were blocked, rewrite the response
        // 6. Forward the (possibly modified) packet
        //
        // For production use, consider using a local HTTP proxy (e.g., NWListener)
        // instead of raw packet manipulation — it's significantly simpler.

        packetFlow.writePackets([packet], withProtocols: [proto])
    }

    // MARK: - Configuration

    private func loadCustomRules() -> String? {
        // Load rules from App Group shared container
        guard let containerURL = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: "group.com.bakelens.crust"
        ) else {
            return nil
        }

        let rulesURL = containerURL.appendingPathComponent("crust-rules.yaml")
        return try? String(contentsOf: rulesURL, encoding: .utf8)
    }
}
