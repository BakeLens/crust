package rules

import (
	"net/url"
	"path"
	"strings"

	"github.com/BakeLens/crust/internal/pathutil"
)

// extractReadTool extracts info from Read/read_file tool
func (e *Extractor) extractReadTool(info *ExtractedInfo) {
	info.addOperation(OpRead)
	e.extractPathFields(info)
}

// extractWriteTool extracts info from Write/write_file tool
func (e *Extractor) extractWriteTool(info *ExtractedInfo) {
	info.addOperation(OpWrite)
	e.extractPathFields(info)
	e.extractContentField(info)
}

// extractEditTool extracts info from Edit tool
func (e *Extractor) extractEditTool(info *ExtractedInfo) {
	info.addOperation(OpWrite)
	e.extractPathFields(info)
	e.extractContentField(info)
}

// extractDeleteTool extracts info from delete_file tool (Cursor)
func (e *Extractor) extractDeleteTool(info *ExtractedInfo) {
	info.addOperation(OpDelete)
	e.extractPathFields(info)
}

// extractUnknownTool handles the default case in Layer 1: tools with unrecognized names.
// It actively tries all extraction strategies based on argument field shapes, in priority
// order, to infer what the tool does. Unlike augmentFromArgShape (Layer 2), this runs
// ONLY for unknown tools and sets the initial operation — Layer 2 can still upgrade it.
//
// Priority order:
//  1. Command field → shell AST parsing (highest signal)
//  2. URL field → host extraction + OpNetwork
//  3. Path + edit fields (old_string/new_string) → OpWrite
//  4. Path + content fields → OpWrite
//  5. Path only → OpRead
//
// All steps run unconditionally (no early returns) so multiple signals are merged.
func (e *Extractor) extractUnknownTool(info *ExtractedInfo) {
	// Step 1: Try shell AST parsing on any command-like field.
	// This catches tools like Cursor's run_terminal_cmd, Windsurf's "Run Command", etc.
	e.extractBashCommand(info)

	// Step 2: Extract hosts from URL-bearing fields.
	// This catches tools like Windsurf's "Read URL Content", MCP API tools, etc.
	// Handles both "https://evil.com/path" and scheme-less "evil.com/path".
	e.extractURLFields(info)

	// Step 3: Extract paths from known field names.
	e.extractPathFields(info)

	// Step 4: If paths were found, infer operation from accompanying fields.
	// Only infer when operation is still unknown — don't override explicit ops.
	if len(info.Paths) > 0 && info.Operation == OpNone {
		// Check for edit signals (old_string/new_string)
		_, hasOld := info.RawArgs["oldstring"]
		_, hasNew := info.RawArgs["newstring"]
		if hasOld || hasNew {
			info.addOperation(OpWrite)
		}

		// Check for write signals (content fields)
		if info.Operation == OpNone {
			for _, f := range knownContentFields {
				if _, ok := info.RawArgs[f]; ok {
					info.addOperation(OpWrite)
					break
				}
			}
		}

		// Path with no other signals = read
		if info.Operation == OpNone {
			info.addOperation(OpRead)
		}
	}

	// Extract content for content-matching rules
	e.extractContentField(info)
}

// augmentFromArgShape scans argument fields to detect tool intent regardless
// of tool name. This is Layer 2 (shape-based) defense — it always runs after
// the name-based Layer 1 to catch bypasses via renamed tools.
// It never downgrades the operation, only upgrades via operationPriority.
// It NEVER returns early — all steps always execute.
func (e *Extractor) augmentFromArgShape(info *ExtractedInfo) {
	// Step 1: If any command field present and not yet parsed → shell AST parse
	if info.Command == "" {
		for _, field := range knownCommandFields {
			if val, ok := info.RawArgs[field]; ok {
				if len(fieldStrings(val)) > 0 {
					e.extractBashCommand(info)
					break // found a command field, no need to check more
				}
			}
		}
		// DO NOT return — continue to check url/paths below
	}

	// Step 2: Check URL-bearing fields for host extraction
	// Handles both scheme-prefixed and scheme-less URLs.
	e.extractURLFields(info)

	// Step 3: Extract paths from known field names (additive)
	existingPaths := len(info.Paths)
	e.extractPathFields(info)
	newPathsFound := len(info.Paths) > existingPaths

	// Step 4: If paths exist, infer operation from field shape
	// Use operationPriority — only UPGRADE, never downgrade
	if len(info.Paths) > 0 {
		inferredOp := OpNone

		// Check for edit signals (old_string/new_string)
		_, hasOld := info.RawArgs["oldstring"]
		_, hasNew := info.RawArgs["newstring"]
		if hasOld || hasNew {
			inferredOp = OpWrite
		}

		// Check for write signals (content fields)
		if inferredOp == OpNone {
			for _, f := range knownContentFields {
				if _, ok := info.RawArgs[f]; ok {
					inferredOp = OpWrite
					break
				}
			}
		}

		// Path only with no other signals = read
		if inferredOp == OpNone && newPathsFound {
			inferredOp = OpRead
		}

		// Only upgrade, never downgrade (addOperation enforces this internally)
		if inferredOp != OpNone {
			info.addOperation(inferredOp)
		}
	}

	// SECURITY: Expand DNS rebinding hosts — services like nip.io and sslip.io
	// resolve arbitrary IPs (e.g., 127.0.0.1.nip.io → 127.0.0.1). Add the
	// embedded IP alongside the original hostname so IP-based host rules match.
	info.Hosts = expandRebindingHosts(info.Hosts)

	// SECURITY: Resolve hostnames via DNS and add loopback IPs to the host list.
	// Catches custom domains pointing to 127.0.0.1 that bypass regex/rebinding checks.
	info.Hosts = ResolveAndExpandHosts(info.Hosts)

	// Deduplicate
	info.Paths = deduplicateStrings(info.Paths)
	info.Hosts = deduplicateStrings(info.Hosts)
}

// extractWebFetchTool extracts info from WebFetch tool
func (e *Extractor) extractWebFetchTool(info *ExtractedInfo) {
	if val, ok := info.RawArgs["url"]; ok {
		for _, urlStr := range fieldStrings(val) {
			// SECURITY: file:// URLs are local reads, not network fetches.
			// Force OpRead so path-based rules catch file:// bypasses like
			// "WebFetch(url: file:///home/user/.ssh/id_rsa)".
			if p := extractPathFromFileURL(urlStr); p != "" {
				info.Paths = append(info.Paths, p)
				info.forceOperation(OpRead)
				continue
			}
			if host := extractHostFromURL(urlStr); host != "" {
				info.Hosts = append(info.Hosts, host)
				info.addOperation(OpNetwork)
			}
		}
	}
	// Default to OpNetwork if no URL was recognized
	if info.Operation == OpNone {
		info.addOperation(OpNetwork)
	}
}

// extractPathFromFileURL returns the local path from a file: URL.
// Handles all valid forms: file:///path, file://host/path, file:/path.
// Returns "" for non-file URLs or unparseable input.
func extractPathFromFileURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	if strings.EqualFold(u.Scheme, "file") && u.Path != "" {
		// normalize // and .. in file: paths, then strip leading "/"
		// before Windows drive letters (e.g., "/C:/Users" → "C:/Users").
		return pathutil.StripFileURIDriveLetter(path.Clean(u.Path))
	}
	return ""
}

// extractPathFields extracts paths from known field names.
// Handles string values, []any arrays, and case-collision merged values.
func (e *Extractor) extractPathFields(info *ExtractedInfo) {
	for _, field := range knownPathFields {
		if val, ok := info.RawArgs[field]; ok {
			info.Paths = append(info.Paths, fieldStrings(val)...)
		}
	}
}

// extractURLFields extracts hosts from known URL field names.
// Handles string values, []any arrays, case-collision merged values, and scheme-less URLs.
func (e *Extractor) extractURLFields(info *ExtractedInfo) {
	for _, field := range knownURLFields {
		if val, ok := info.RawArgs[field]; ok {
			for _, u := range fieldStrings(val) {
				host := extractHostFromURLField(u)
				if host != "" {
					info.Hosts = append(info.Hosts, host)
					info.addOperation(OpNetwork)
				}
				// SECURITY: file:// URLs in any tool's URL field are local reads.
				// Without this, only recognized WebFetch tools get file:// extraction.
				if p := extractPathFromFileURL(u); p != "" {
					info.Paths = append(info.Paths, p)
					info.addOperation(OpRead)
				}
			}
		}
	}
}

// extractContentField extracts content from Write/Edit tool args.
// Handles string values, []any arrays (from case-collision merging), etc.
// For arrays, concatenates all string values so content-matching rules see everything.
func (e *Extractor) extractContentField(info *ExtractedInfo) {
	for _, field := range knownContentFields {
		if val, ok := info.RawArgs[field]; ok {
			if strs := fieldStrings(val); len(strs) > 0 {
				info.Content = strings.Join(strs, "\n")
				return
			}
		}
	}
}

// ── Mobile tool extraction ──────────────────────────────────────────────────
//
// Mobile AI agents call tools that map to virtual paths under "mobile://".
// This lets the existing rule engine (path-based glob matching) protect mobile
// resources without schema changes. Desktop rules and mobile rules coexist in
// the same YAML file.

// MobileVirtualPathPrefix is the scheme prefix for all mobile virtual paths.
const MobileVirtualPathPrefix = "mobile://"

// extractMobileTool handles Layer 1 extraction for known mobile tool names.
// It maps each tool to an operation + virtual path(s) derived from the tool's
// JSON arguments. Unknown mobile tools fall through to extractUnknownTool.
func (e *Extractor) extractMobileTool(info *ExtractedInfo, toolLower string) bool {
	switch toolLower {
	// ── PII access ──
	case "read_contacts", "get_contacts", "access_contacts":
		info.addOperation(OpRead)
		info.Paths = append(info.Paths, "mobile://pii/contacts")
	case "read_photos", "get_photos", "access_photos", "access_photo_library":
		info.addOperation(OpRead)
		info.Paths = append(info.Paths, "mobile://pii/photos")
	case "read_calendar", "get_calendar", "access_calendar", "get_events":
		info.addOperation(OpRead)
		info.Paths = append(info.Paths, "mobile://pii/calendar")
	case "read_location", "get_location", "access_location", "get_gps":
		info.addOperation(OpRead)
		info.Paths = append(info.Paths, "mobile://pii/location")
	case "read_health_data", "get_health_data", "access_health":
		info.addOperation(OpRead)
		info.Paths = append(info.Paths, "mobile://pii/health")

	// ── Keychain ──
	case "keychain_get", "keychain_read", "get_keychain_item", "read_keychain":
		info.addOperation(OpRead)
		info.Paths = append(info.Paths, mobileKeychainPath(info.RawArgs))
	case "keychain_set", "keychain_write", "set_keychain_item", "write_keychain",
		"keychain_add", "add_keychain_item":
		info.addOperation(OpWrite)
		info.Paths = append(info.Paths, mobileKeychainPath(info.RawArgs))
	case "keychain_delete", "delete_keychain_item", "remove_keychain_item":
		info.addOperation(OpDelete)
		info.Paths = append(info.Paths, mobileKeychainPath(info.RawArgs))

	// ── Clipboard ──
	case "read_clipboard", "get_clipboard", "get_pasteboard":
		info.addOperation(OpRead)
		info.Paths = append(info.Paths, "mobile://clipboard")
	case "write_clipboard", "set_clipboard", "set_pasteboard", "copy_to_clipboard":
		info.addOperation(OpWrite)
		info.Paths = append(info.Paths, "mobile://clipboard")

	// ── URL schemes ──
	case "open_url", "open_deep_link", "open_link", "open_universal_link":
		info.addOperation(OpExecute)
		info.Paths = append(info.Paths, mobileURLSchemePath(info.RawArgs))
		// Also extract host for network rules
		e.extractURLFields(info)

	// ── Background tasks / persistence ──
	case "schedule_task", "schedule_background_task", "register_background_task",
		"register_background", "schedule_job":
		info.addOperation(OpWrite)
		info.Paths = append(info.Paths, mobileAutostartPath(info.RawArgs))
	case "cancel_task", "cancel_background_task", "unregister_background_task":
		info.addOperation(OpDelete)
		info.Paths = append(info.Paths, mobileAutostartPath(info.RawArgs))

	// ── Notifications ──
	case "send_notification", "push_notification", "schedule_notification",
		"show_notification":
		info.addOperation(OpWrite)
		info.Paths = append(info.Paths, "mobile://notification")

	// ── Permissions ──
	case "request_permission", "request_authorization":
		info.addOperation(OpExecute)
		info.Paths = append(info.Paths, mobilePermissionPath(info.RawArgs))

	// ── Data sharing / exfiltration vector ──
	case "share_data", "share_file", "share_content", "airdrop":
		info.addOperation(OpNetwork)
		info.Paths = append(info.Paths, mobileSharePath(info.RawArgs))

	// ── Camera ──
	case "capture_photo", "take_photo", "take_picture", "capture_image",
		"record_video", "start_video_recording", "capture_video":
		info.addOperation(OpRead)
		info.Paths = append(info.Paths, "mobile://pii/camera")

	// ── Microphone ──
	case "record_audio", "start_recording", "capture_audio",
		"start_audio_recording", "voice_record":
		info.addOperation(OpRead)
		info.Paths = append(info.Paths, "mobile://pii/microphone")

	// ── Bluetooth / NFC ──
	case "scan_bluetooth", "bluetooth_scan", "discover_bluetooth",
		"bluetooth_connect", "connect_bluetooth":
		info.addOperation(OpNetwork)
		info.Paths = append(info.Paths, "mobile://hardware/bluetooth")
	case "read_nfc", "scan_nfc", "nfc_read", "nfc_scan":
		info.addOperation(OpRead)
		info.Paths = append(info.Paths, "mobile://hardware/nfc")
	case "write_nfc", "nfc_write":
		info.addOperation(OpWrite)
		info.Paths = append(info.Paths, "mobile://hardware/nfc")

	// ── Biometric authentication ──
	case "authenticate_biometric", "biometric_auth", "request_biometric",
		"touch_id", "face_id", "fingerprint_auth":
		info.addOperation(OpExecute)
		info.Paths = append(info.Paths, "mobile://auth/biometric")

	// ── In-app purchases ──
	case "purchase_item", "buy_item", "make_purchase", "in_app_purchase",
		"start_purchase", "request_purchase":
		info.addOperation(OpExecute)
		info.Paths = append(info.Paths, mobilePurchasePath(info.RawArgs))

	// ── Call log / SMS history ──
	case "read_call_log", "get_call_history", "access_call_log":
		info.addOperation(OpRead)
		info.Paths = append(info.Paths, "mobile://pii/call-log")
	case "read_sms", "get_sms", "read_messages", "get_messages":
		info.addOperation(OpRead)
		info.Paths = append(info.Paths, "mobile://pii/sms")

	default:
		return false // not a known mobile tool
	}

	// Extract content for content-matching rules
	e.extractContentField(info)
	return true
}

// mobileKeychainPath builds a virtual keychain path from args.
// e.g., {"key": "api_token"} → "mobile://keychain/api_token"
func mobileKeychainPath(args map[string]any) string {
	for _, field := range []string{"key", "account", "service", "item", "name", "identifier"} {
		if val, ok := args[field]; ok {
			if strs := fieldStrings(val); len(strs) > 0 {
				return MobileVirtualPathPrefix + "keychain/" + sanitizeVirtualPathSegment(strs[0])
			}
		}
	}
	return MobileVirtualPathPrefix + "keychain/_unknown"
}

// mobileURLSchemePath builds a virtual URL scheme path from args.
// e.g., {"url": "tel:+1234567890"} → "mobile://url-scheme/tel"
func mobileURLSchemePath(args map[string]any) string {
	for _, field := range []string{"url", "uri", "link", "deeplink"} {
		if val, ok := args[field]; ok {
			if strs := fieldStrings(val); len(strs) > 0 {
				if scheme := extractURLScheme(strs[0]); scheme != "" {
					return MobileVirtualPathPrefix + "url-scheme/" + scheme
				}
			}
		}
	}
	return MobileVirtualPathPrefix + "url-scheme/_unknown"
}

// mobileAutostartPath builds a virtual autostart path from args.
// e.g., {"task_id": "sync_data"} → "mobile://autostart/sync_data"
func mobileAutostartPath(args map[string]any) string {
	for _, field := range []string{"taskid", "task", "jobid", "job", "name", "identifier"} {
		if val, ok := args[field]; ok {
			if strs := fieldStrings(val); len(strs) > 0 {
				return MobileVirtualPathPrefix + "autostart/" + sanitizeVirtualPathSegment(strs[0])
			}
		}
	}
	return MobileVirtualPathPrefix + "autostart/_unknown"
}

// mobilePermissionPath builds a virtual permission path from args.
// e.g., {"permission": "camera"} → "mobile://permission/camera"
func mobilePermissionPath(args map[string]any) string {
	for _, field := range []string{"permission", "authorization", "capability", "entitlement", "name"} {
		if val, ok := args[field]; ok {
			if strs := fieldStrings(val); len(strs) > 0 {
				return MobileVirtualPathPrefix + "permission/" + sanitizeVirtualPathSegment(strs[0])
			}
		}
	}
	return MobileVirtualPathPrefix + "permission/_unknown"
}

// mobileSharePath builds a virtual share path from args.
// e.g., {"target": "email"} → "mobile://share/email"
func mobileSharePath(args map[string]any) string {
	for _, field := range []string{"target", "destination", "method", "via"} {
		if val, ok := args[field]; ok {
			if strs := fieldStrings(val); len(strs) > 0 {
				return MobileVirtualPathPrefix + "share/" + sanitizeVirtualPathSegment(strs[0])
			}
		}
	}
	return MobileVirtualPathPrefix + "share/_unknown"
}

// mobilePurchasePath builds a virtual purchase path from args.
// e.g., {"product_id": "premium_monthly"} → "mobile://purchase/premium_monthly"
func mobilePurchasePath(args map[string]any) string {
	for _, field := range []string{"productid", "sku", "item", "itemid", "name", "identifier"} {
		if val, ok := args[field]; ok {
			if strs := fieldStrings(val); len(strs) > 0 {
				return MobileVirtualPathPrefix + "purchase/" + sanitizeVirtualPathSegment(strs[0])
			}
		}
	}
	return MobileVirtualPathPrefix + "purchase/_unknown"
}

// ExtractURLScheme returns the scheme portion of a URL string.
// e.g., "tel:+1234567890" → "tel", "https://example.com" → "https"
// Per RFC 3986, schemes must start with a letter.
// Exported for use by libcrust's ValidateURL.
func ExtractURLScheme(rawURL string) string {
	return extractURLScheme(rawURL)
}

// extractURLScheme is the internal implementation.
func extractURLScheme(rawURL string) string {
	if i := strings.Index(rawURL, ":"); i > 0 && i < 32 {
		scheme := strings.ToLower(rawURL[:i])
		// RFC 3986: scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
		// First character must be a letter.
		if scheme[0] < 'a' || scheme[0] > 'z' {
			return ""
		}
		for _, c := range scheme[1:] {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '+' && c != '-' && c != '.' {
				return ""
			}
		}
		return scheme
	}
	return ""
}

// sanitizeVirtualPathSegment cleans a user-provided string for use in a virtual path.
// Strips slashes and path traversal to prevent injection like "../../etc/passwd".
func sanitizeVirtualPathSegment(s string) string {
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "\\", "_")
	s = strings.ReplaceAll(s, "..", "_")
	if s == "" || s == "_" {
		return "_unknown"
	}
	return s
}

// IsMobileVirtualPath returns true if the path uses the mobile:// virtual path scheme.
func IsMobileVirtualPath(p string) bool {
	return strings.HasPrefix(p, MobileVirtualPathPrefix)
}
