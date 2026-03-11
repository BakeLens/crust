package rules

import (
	"crypto/sha512"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// BIP32 test vector 1 — well-known master extended private key.
const testXprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"

// Known WIF private key from Bitcoin wiki (uncompressed, mainnet).
const testWIF = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"

// Standard BIP39 12-word test mnemonic.
const testMnemonic12 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

// Standard BIP39 15-word test mnemonic.
const testMnemonic15 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

// Standard BIP39 18-word test mnemonic.
const testMnemonic18 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

// Standard BIP39 24-word test mnemonic.
const testMnemonic24 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

func TestCryptoDLPDetection(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantNil bool
		wantID  string
	}{
		// --- BIP39 Mnemonic Detection ---
		{
			name:    "12-word BIP39 mnemonic",
			content: testMnemonic12,
			wantID:  "builtin:dlp-crypto-bip39-mnemonic",
		},
		{
			name:    "24-word BIP39 mnemonic",
			content: testMnemonic24,
			wantID:  "builtin:dlp-crypto-bip39-mnemonic",
		},
		{
			name:    "15-word BIP39 mnemonic",
			content: testMnemonic15,
			wantID:  "builtin:dlp-crypto-bip39-mnemonic",
		},
		{
			name:    "18-word BIP39 mnemonic",
			content: testMnemonic18,
			wantID:  "builtin:dlp-crypto-bip39-mnemonic",
		},
		{
			name:    "mnemonic embedded in code",
			content: `const seed = "` + testMnemonic12 + `"`,
			wantID:  "builtin:dlp-crypto-bip39-mnemonic",
		},
		{
			name:    "mnemonic with surrounding text",
			content: "Here is my wallet backup: " + testMnemonic12 + " — keep this safe!",
			wantID:  "builtin:dlp-crypto-bip39-mnemonic",
		},
		{
			name:    "mnemonic with newlines between words",
			content: strings.ReplaceAll(testMnemonic12, " ", "\n"),
			wantID:  "builtin:dlp-crypto-bip39-mnemonic",
		},

		// --- Extended Private Key Detection ---
		{
			name:    "xprv key (BIP32 test vector 1)",
			content: testXprv,
			wantID:  "builtin:dlp-crypto-xprv",
		},
		{
			name:    "xprv embedded in JSON",
			content: `{"master_key": "` + testXprv + `"}`,
			wantID:  "builtin:dlp-crypto-xprv",
		},

		// --- WIF Key Detection ---
		{
			name:    "WIF key (uncompressed)",
			content: testWIF,
			wantID:  "builtin:dlp-crypto-wif",
		},
		{
			name:    "WIF key embedded in config",
			content: "PRIVATE_KEY=" + testWIF,
			wantID:  "builtin:dlp-crypto-wif",
		},

		// --- Multilingual BIP39 Detection ---
		{
			name:    "Spanish 12-word mnemonic",
			content: "ábaco abdomen abeja abierto abogado abono abrazo abrir abuelo abuso acción aceite",
			wantID:  "builtin:dlp-crypto-bip39-mnemonic",
		},
		{
			name:    "Japanese 12-word mnemonic",
			content: "あいこくしん あいさつ あいだ あおぞら あかちゃん あきる あけがた あける あこがれる あさい あさひ あしあと",
			wantID:  "builtin:dlp-crypto-bip39-mnemonic",
		},
		{
			name:    "Chinese simplified 12-word mnemonic",
			content: "的 一 是 在 不 了 有 和 人 这 中 大",
			wantID:  "builtin:dlp-crypto-bip39-mnemonic",
		},
		{
			name:    "Korean 12-word mnemonic",
			content: "가격 가끔 가난 가능 가득 가르침 가뭄 가방 가상 가슴 가운데 가을",
			wantID:  "builtin:dlp-crypto-bip39-mnemonic",
		},
		{
			name:    "French 12-word mnemonic",
			content: "abaisser abandon abdiquer abeille abolir aborder aboutir aboyer abrasif absence abroger absolu",
			wantID:  "builtin:dlp-crypto-bip39-mnemonic",
		},

		// --- No Detection (clean content) ---
		{
			name:    "empty content",
			content: "",
			wantNil: true,
		},
		{
			name:    "normal English text",
			content: "The quick brown fox jumps over the lazy dog.",
			wantNil: true,
		},
		{
			name:    "Go source code",
			content: `func main() { fmt.Println("hello world") }`,
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanCrypto(tt.content)
			if tt.wantNil {
				if result != nil {
					t.Errorf("scanCrypto() = %q, want nil", result.name)
				}
				return
			}
			if result == nil {
				t.Fatal("scanCrypto() = nil, want match")
				return
			}
			if result.name != tt.wantID {
				t.Errorf("scanCrypto().name = %q, want %q", result.name, tt.wantID)
			}
			if result.message == "" {
				t.Error("scanCrypto().message is empty")
			}
		})
	}
}

func TestCryptoDLPFalsePositives(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "11 BIP39 words (below minimum)",
			content: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
		},
		{
			name:    "12 common English words (not all BIP39)",
			content: "the quick brown fox jumps over the lazy dog near the house",
		},
		{
			name:    "xprv-like string with bad checksum",
			content: "xprvAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		},
		{
			name:    "random K-prefixed string (not valid WIF)",
			content: "KzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzZ",
		},
		{
			name:    "base58 alphabet soup",
			content: "5" + strings.Repeat("1", 50),
		},
		{
			name:    "xprv in variable name only",
			content: `var xprvKeyPath = "/some/path"`,
		},
		{
			name:    "Bitcoin address (not a private key)",
			content: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
		},
		{
			name:    "words from BIP39 mixed with non-BIP39",
			content: "abandon ability xylophone microphone telephone abandon ability xylophone microphone telephone abandon ability",
		},
		{
			name:    "short WIF-like prefix in URL",
			content: "https://example.com/5K/path/to/resource",
		},
		{
			name:    "code with abandon in comments",
			content: "// We should abandon this approach and start over with a new design pattern",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanCrypto(tt.content)
			if result != nil {
				t.Errorf("scanCrypto() = %q, want nil (false positive)", result.name)
			}
		})
	}
}

func TestCryptoWalletPaths(t *testing.T) {
	// Verify that cryptoWalletDirs was populated at init.
	if len(cryptoWalletDirs) == 0 {
		t.Fatal("cryptoWalletDirs is empty — init() failed")
	}

	// Should contain at least bitcoin and ethereum.
	hasBitcoin := false
	hasEthereum := false
	for _, dir := range cryptoWalletDirs {
		lower := strings.ToLower(dir)
		if strings.Contains(lower, "bitcoin") {
			hasBitcoin = true
		}
		if strings.Contains(lower, "ethereum") {
			hasEthereum = true
		}
	}
	if !hasBitcoin {
		t.Error("cryptoWalletDirs missing bitcoin directory")
	}
	if !hasEthereum {
		t.Error("cryptoWalletDirs missing ethereum directory")
	}

	// Test hasCryptoWalletPath.
	t.Run("direct access", func(t *testing.T) {
		// Use the first wallet dir as test target.
		testDir := cryptoWalletDirs[0]
		testPath := filepath.Join(testDir, "wallet.dat")

		blocked, path := hasCryptoWalletPath([]string{testPath})
		if !blocked {
			t.Errorf("hasCryptoWalletPath(%q) = false, want true", testPath)
		}
		if path != testPath {
			t.Errorf("matched path = %q, want %q", path, testPath)
		}
	})

	t.Run("unrelated path", func(t *testing.T) {
		blocked, _ := hasCryptoWalletPath([]string{"/tmp/safe/file.txt"})
		if blocked {
			t.Error("hasCryptoWalletPath(/tmp/safe/file.txt) = true, want false")
		}
	})

	t.Run("directory itself", func(t *testing.T) {
		testDir := cryptoWalletDirs[0]
		blocked, _ := hasCryptoWalletPath([]string{testDir})
		if !blocked {
			t.Errorf("hasCryptoWalletPath(%q) = false, want true (directory itself)", testDir)
		}
	})
}

func TestCryptoWalletPathsOSSpecific(t *testing.T) {
	// Verify paths follow OS conventions via btcutil.AppDataDir.
	// On case-insensitive filesystems (default macOS APFS), paths are lowercased
	// at init time via pathutil.DefaultFS().Lower().
	switch runtime.GOOS {
	case "darwin":
		// macOS: ~/Library/Application Support/Bitcoin (lowercased on case-insensitive APFS)
		found := false
		for _, dir := range cryptoWalletDirs {
			lower := strings.ToLower(dir)
			if strings.Contains(lower, "library/application support") && strings.Contains(lower, "itcoin") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("macOS: expected Library/Application Support path for Bitcoin, got: %v", cryptoWalletDirs)
		}
	case "linux":
		// Linux: ~/.bitcoin
		found := false
		for _, dir := range cryptoWalletDirs {
			if strings.Contains(dir, ".bitcoin") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Linux: expected .bitcoin path, got: %v", cryptoWalletDirs)
		}
	}
}

// TestBIP39WordlistIntegrity verifies that embedded BIP39 wordlist files have not
// been tampered with. SHA-512 checksums match the canonical bitcoin/bips repository:
// https://github.com/bitcoin/bips/tree/master/bip-0039
func TestBIP39WordlistIntegrity(t *testing.T) {
	expected := map[string]string{
		"chinese_simplified.txt":  "f5b6d696a6b75bdeeacd0e0742d31eaa06cd683bb3c149052d82e0d47039534b23c82fc47fb193c86ff2b7c2b22f73ccc48cc500f09abc5e228998d9bc413ef7",
		"chinese_traditional.txt": "1e2689a48317a12a6b4a6a74de2241380fef57b250fafe6ab00a479db85d12661f8c33749240c9cec6535acd7f91e71dcba0bb8a27d1d32a3b76fe34797cad5b",
		"czech.txt":               "3d56a9d507b5b07a99b9d9924d8540944dd226d4b5050852027f09309a85513db2e57c9186f70b8f8226c342c28efcedd1e8edd507e1d39f8da693cfac0c39ca",
		"english.txt":             "416c71ba30018ea292bb36cdc23c9329673485a8d8933266a9d9a7cc72153b8baed3d430f52eab4f5d3addf6583611b3777a50454599f1e42716f5f879621123",
		"french.txt":              "001b2e7d1d17416776fa5306e4f7ec5812f3f35cc26fde46800a7dab1412870ac8b779b0c2fec1d75c24b80868e55bc5bfb88c8ded50c84040248b76a2c5332d",
		"italian.txt":             "d3dca24cf03f04eea1872d98c91748a8aa7aeac6e2c885a99f2d452904a75ffcf271506db369335726c0e3f7c8a6454935782586414b9affd2fe0eb004223da1",
		"japanese.txt":            "3faf87f7e48eb6635f7d7b18a34e7dacbc2c43a1cf6aa9c96015b2a3549710b8b7a0961e5d2e32d7e369099db89a874c4d761a8384fb558744c7f47ca8cb0772",
		"korean.txt":              "e645a1e0f26f2727a8fb7605d3b59668a670c9df04d07576fe473d844a23d0192020aedc286fbb9b1f64709ad30e6acb825803cf9f872954c1324aefd4977710",
		"portuguese.txt":          "0e6aa42870c6f9a77bda0931ea9423febffefbeb49e9dbda5fa732fc3479942629050517fef57bb1a76026195e16785186c0cfe26261c8fcc31f52fe69beda0f",
		"spanish.txt":             "0e838229265de6c80505088682d2dc9510147c3ab1713b556b594d09529b493cc3a7e391ad690dda2052d4e11c56572f8a215a7fffdb2630b13b4637329f3c31",
	}

	entries, err := bip39WordlistFS.ReadDir("bip39")
	if err != nil {
		t.Fatal(err)
	}

	found := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		wantHash, ok := expected[entry.Name()]
		if !ok {
			t.Errorf("unexpected file in bip39/: %s", entry.Name())
			continue
		}
		data, err := bip39WordlistFS.ReadFile("bip39/" + entry.Name())
		if err != nil {
			t.Errorf("read %s: %v", entry.Name(), err)
			continue
		}
		gotHash := fmt.Sprintf("%x", sha512.Sum512(data))
		if gotHash != wantHash {
			t.Errorf("%s: SHA-512 mismatch\n  got:  %s\n  want: %s\n  → file may have been tampered with", entry.Name(), gotHash, wantHash)
		}
		found++
	}

	if found != len(expected) {
		t.Errorf("expected %d wordlist files, found %d", len(expected), found)
	}
}

func TestBIP39UnifiedWordlistCount(t *testing.T) {
	// 10 languages × 2048 words each, minus overlap between languages.
	// The unified set should have at least 10,000 unique words.
	if len(bip39Unified) < 10000 {
		t.Errorf("bip39Unified has %d words, want >= 10000", len(bip39Unified))
	}
	// Each language has exactly 2048 words, so max is 20480.
	if len(bip39Unified) > 20480 {
		t.Errorf("bip39Unified has %d words, want <= 20480", len(bip39Unified))
	}
	// Spot-check: English "abandon", Spanish "ábaco", Japanese "あいこくしん"
	spotChecks := []string{"abandon", "zoo", "ábaco", "あいこくしん", "的", "가격"}
	for _, w := range spotChecks {
		if !bip39Unified[w] {
			t.Errorf("bip39Unified missing expected word %q", w)
		}
	}
}
