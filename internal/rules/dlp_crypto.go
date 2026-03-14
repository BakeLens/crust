package rules

import (
	"bufio"
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/BakeLens/crust/internal/pathutil"
	"github.com/btcsuite/btcd/btcutil/base58"
	"golang.org/x/text/unicode/norm"
)

//go:generate go run bip39_verify.go

// Crypto DLP: detects cryptocurrency secrets using cryptographic validation.
// - BIP39 mnemonics: sliding window over unified 10-language wordlist (20,480 words)
// - Extended private keys (xprv/yprv/zprv/tprv): regex + base58check checksum
// - WIF private keys (5/K/L prefix): regex + base58check checksum + version byte
// - Wallet path protection: hardcoded directory check using OS-specific data dirs

// cryptoDLPMatch holds a crypto DLP detection result.
type cryptoDLPMatch struct {
	name    string
	message string
}

// scanCrypto checks content for cryptocurrency secrets.
// Returns the first match found, or nil if clean.
func scanCrypto(content string) *cryptoDLPMatch {
	if content == "" {
		return nil
	}
	if m := scanBIP39Mnemonic(content); m != nil {
		return m
	}
	if m := scanExtendedPrivateKey(content); m != nil {
		return m
	}
	if m := scanWIFKey(content); m != nil {
		return m
	}
	return nil
}

// --- BIP39 Mnemonic Detection ---

// bip39WordlistFS embeds all BIP39 wordlist files (10 languages, 2048 words each).
// Source: https://github.com/bitcoin/bips/tree/master/bip-0039
//
//go:embed bip39/*.txt
var bip39WordlistFS embed.FS

// bip39Unified is a union of all BIP39 wordlists across all languages.
// Built once at init from the embedded text files.
var bip39Unified map[string]bool

func init() {
	bip39Unified = make(map[string]bool, 20480) // 10 langs × 2048, with overlap
	entries, err := bip39WordlistFS.ReadDir("bip39")
	if err != nil {
		// Embedded FS is baked in at compile time; this cannot fail.
		fmt.Fprintf(os.Stderr, "FATAL: bip39: cannot read embedded wordlist directory: %v\n", err)
		os.Exit(1)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		f, err := bip39WordlistFS.Open("bip39/" + entry.Name())
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			word := strings.TrimSpace(scanner.Text())
			if word != "" {
				// Normalize to NFC: BIP39 wordlists use NFD encoding
				// (e.g. Spanish á = a + combining accent, Korean Jamo decomposition).
				bip39Unified[norm.NFC.String(word)] = true
			}
		}
		f.Close()
	}
}

// bip39ValidLengths are the valid BIP39 mnemonic lengths.
var bip39ValidLengths = []int{12, 15, 18, 21, 24}

// scanBIP39Mnemonic detects BIP39 seed phrases using a sliding window.
// Checks against the unified wordlist covering all 10 BIP39 languages.
func scanBIP39Mnemonic(content string) *cryptoDLPMatch {
	words := extractBIP39Words(content)
	if len(words) < 12 {
		return nil
	}

	for _, windowSize := range bip39ValidLengths {
		if len(words) < windowSize {
			break
		}
		for i := 0; i <= len(words)-windowSize; i++ {
			allMatch := true
			for j := range windowSize {
				if !bip39Unified[words[i+j]] {
					// Skip ahead: no point checking windows that include this non-BIP39 word.
					i += j
					allMatch = false
					break
				}
			}
			if allMatch {
				return &cryptoDLPMatch{
					name:    "builtin:dlp-crypto-bip39-mnemonic",
					message: "Cannot expose BIP39 mnemonic seed phrase — potential cryptocurrency key leak",
				}
			}
		}
	}
	return nil
}

// extractBIP39Words splits content into candidate BIP39 words.
// Handles both Latin scripts (English, Spanish, French, etc.) and CJK scripts
// (Chinese, Japanese, Korean) by using rune count instead of byte length.
// BIP39 words range from 1 rune (Chinese) to 9 runes (Japanese).
func extractBIP39Words(s string) []string {
	// NFC-normalize the input to match the NFC-normalized wordlist keys.
	s = norm.NFC.String(s)
	var words []string
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return !unicode.IsLetter(r)
	})
	for _, f := range fields {
		w := strings.ToLower(f)
		n := utf8.RuneCountInString(w)
		if n >= 1 && n <= 9 {
			words = append(words, w)
		}
	}
	return words
}

// --- Extended Private Key Detection (xprv/yprv/zprv/tprv) ---

// xprvRegex matches base58-encoded extended private keys.
var xprvRegex = regexp.MustCompile(`[xyzt]prv[1-9A-HJ-NP-Za-km-z]{107,112}`)

// scanExtendedPrivateKey detects Bitcoin HD extended private keys with checksum validation.
func scanExtendedPrivateKey(content string) *cryptoDLPMatch {
	matches := xprvRegex.FindAllString(content, 5) // limit to 5 candidates
	for _, match := range matches {
		_, _, err := base58.CheckDecode(match)
		if err == nil {
			return &cryptoDLPMatch{
				name:    "builtin:dlp-crypto-xprv",
				message: "Cannot expose extended private key (xprv/yprv/zprv/tprv) — potential cryptocurrency key leak",
			}
		}
	}
	return nil
}

// --- WIF Private Key Detection ---

// wifRegex matches WIF-encoded Bitcoin private keys.
// Uncompressed: starts with 5, 51 chars total.
// Compressed: starts with K or L, 52 chars total.
var wifRegex = regexp.MustCompile(`[5KL][1-9A-HJ-NP-Za-km-z]{50,51}`)

// scanWIFKey detects Bitcoin WIF private keys with checksum + version byte validation.
func scanWIFKey(content string) *cryptoDLPMatch {
	matches := wifRegex.FindAllString(content, 5) // limit to 5 candidates
	for _, match := range matches {
		decoded, version, err := base58.CheckDecode(match)
		if err != nil {
			continue
		}
		// WIF version byte: 0x80 for mainnet, 0xEF for testnet.
		if version != 0x80 && version != 0xEF {
			continue
		}
		// WIF payload: 32 bytes (uncompressed) or 33 bytes (compressed, ends with 0x01).
		if len(decoded) == 32 || (len(decoded) == 33 && decoded[32] == 0x01) {
			return &cryptoDLPMatch{
				name:    "builtin:dlp-crypto-wif",
				message: "Cannot expose WIF private key — potential cryptocurrency key leak",
			}
		}
	}
	return nil
}

// --- Crypto Wallet Path Protection ---

// cryptoWalletDirs are computed once at init using OS-specific data directories.
// Checked after symlink resolution (step 11) so symlink bypasses are caught.
var cryptoWalletDirs []string

// cryptoDataDir returns the OS-specific data directory for a cryptocurrency.
// Follows the same convention as Bitcoin Core and most crypto wallets:
//   - Linux/FreeBSD: ~/.chainname  (lowercase, dot prefix)
//   - macOS:         ~/Library/Application Support/Chainname  (title case)
//   - Windows:       %LOCALAPPDATA%\Chainname  (title case)
func cryptoDataDir(home, chain string) string {
	upper := string(unicode.ToUpper(rune(chain[0]))) + chain[1:]
	lower := string(unicode.ToLower(rune(chain[0]))) + chain[1:]

	switch runtime.GOOS {
	case goosWindows:
		appData := os.Getenv("LOCALAPPDATA")
		if appData == "" {
			appData = os.Getenv("APPDATA")
		}
		if appData != "" {
			return filepath.Join(appData, upper)
		}
	case "darwin":
		if home != "" {
			return filepath.Join(home, "Library", "Application Support", upper)
		}
	default:
		if home != "" {
			return filepath.Join(home, "."+lower)
		}
	}
	return ""
}

func init() {
	home, err := os.UserHomeDir()
	if err != nil {
		home = ""
	}

	// All major chains that follow the standard data directory convention.
	for _, chain := range []string{
		"bitcoin", "litecoin", "dogecoin", "dash", // Bitcoin forks
		"ethereum", "electrum", "monero", "zcash", // Major chains
		"cardano", "cosmos", "polkadot", // PoS chains
		"avalanche", "tron", // Other popular
	} {
		if dir := cryptoDataDir(home, chain); dir != "" {
			cryptoWalletDirs = append(cryptoWalletDirs, dir)
		}
	}

	// Solana (non-standard locations).
	if home != "" {
		cryptoWalletDirs = append(cryptoWalletDirs,
			filepath.Join(home, ".solana"),
			filepath.Join(home, ".config", "solana"),
		)
		// Sui, Aptos (newer chains with non-standard locations).
		cryptoWalletDirs = append(cryptoWalletDirs,
			filepath.Join(home, ".sui"),
			filepath.Join(home, ".aptos"),
		)
	}

	// Normalize wallet dirs: forward slashes + lowercase on case-insensitive
	// filesystems (NTFS, default APFS). hasCryptoWalletPath uses
	// pathutil.CleanPath which outputs forward slashes, so dirs must match.
	fs := pathutil.DefaultFS()
	for i, dir := range cryptoWalletDirs {
		cryptoWalletDirs[i] = fs.Lower(pathutil.ToSlash(dir))
	}
}

// hasCryptoWalletPath checks if any path is inside a crypto wallet directory.
// Defense-in-depth: lowercases cleaned paths on case-insensitive filesystems
// to match the lowered cryptoWalletDirs (set in init). This catches any paths
// that bypass the normalizer's lowering (e.g., symlink-resolved paths).
func hasCryptoWalletPath(paths []string) (bool, string) {
	fs := pathutil.DefaultFS()
	for _, p := range paths {
		cleaned := fs.Lower(pathutil.CleanPath(p))
		for _, dir := range cryptoWalletDirs {
			if pathutil.HasPathPrefix(cleaned, dir) {
				return true, p
			}
		}
	}
	return false, ""
}

// The BIP39 English wordlist was previously hardcoded here (2048 entries).
// Replaced by //go:embed bip39/*.txt which loads all 10 BIP39 languages
// into bip39Unified at init time. See the bip39/ directory.
