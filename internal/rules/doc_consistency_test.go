package rules

// doc_consistency_test.go ensures that numbers and facts stated in documentation
// (README.md, docs/cli.md, docs/how-it-works.md) match the live source code.
//
// These tests act as a guardrail: if you add a DLP pattern, change the number
// of builtin rules, or rename a CLI command, the corresponding test will fail
// and tell you exactly which doc files to update.

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// packageDir returns the absolute path of the directory containing this file.
// Derived from the compiler's source path — stable across working-directory changes.
// Used by both repoRoot (this file) and getTestDataPath (scenario_test.go).
func packageDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Dir(file)
}

// repoRoot returns the repository root: two directories above internal/rules/.
func repoRoot(t *testing.T) string {
	t.Helper()
	return filepath.Dir(filepath.Dir(packageDir()))
}

func readDoc(t *testing.T, relPath string) string {
	t.Helper()
	path := filepath.Join(repoRoot(t), relPath)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("readDoc(%q): %v", relPath, err)
	}
	return string(data)
}

// docContains asserts that the document at relPath contains substr,
// and reports which file to update on failure.
func docContains(t *testing.T, relPath, substr string) {
	t.Helper()
	content := readDoc(t, relPath)
	if !strings.Contains(content, substr) {
		t.Errorf("%s does not contain %q — update this file to match the source code", relPath, substr)
	}
}

// ── DLP patterns ─────────────────────────────────────────────────────────────

// wantDLPPatternCount is the expected number of hardcoded DLP patterns.
// Update this constant AND the docs below whenever patterns are added or removed.
const wantDLPPatternCount = 46

// Docs that reference the DLP pattern count:
//   - README.md: "46 DLP token-detection patterns"
//   - docs/how-it-works.md: should mention 46

func TestDocConsistency_DLPPatternCount(t *testing.T) {
	got := len(dlpPatterns)
	if got != wantDLPPatternCount {
		t.Errorf("len(dlpPatterns) = %d, want %d\n"+
			"  → Update wantDLPPatternCount in this file AND:\n"+
			"    - README.md  (\"46 DLP token-detection patterns\")\n"+
			"    - docs/how-it-works.md",
			got, wantDLPPatternCount)
	}

	docContains(t, "README.md", "46 DLP token-detection patterns")
}

// ── Dynamic protection rules ─────────────────────────────────────────────────

// wantDynamicRuleCount is the number of rules produced by generateProtectionRules.
const wantDynamicRuleCount = 3

func TestDocConsistency_ProtectionRules(t *testing.T) {
	rules := generateProtectionRules(EngineConfig{UserRulesDir: t.TempDir()})

	if len(rules) != wantDynamicRuleCount {
		t.Errorf("generateProtectionRules() returned %d rules, want %d\n"+
			"  → Update wantDynamicRuleCount in this file",
			len(rules), wantDynamicRuleCount)
	}

	for _, r := range rules {
		if !r.IsLocked() {
			t.Errorf("protection rule %q must be locked (Locked: true)", r.Name)
		}
	}
}

// ── Builtin rule counts ───────────────────────────────────────────────────────

// wantTotalRuleCount = YAML rules + dynamic protection rules
// wantLockedRuleCount = YAML locked + dynamic (all locked)
// wantUserDisablableCount = total - locked
//
// Docs that reference these numbers:
//   - README.md: "30 security rules (30 locked, 3 user-disablable)"
//   - docs/cli.md: "31 locked" rules note for --disable-builtin

const (
	wantTotalRuleCount      = 34
	wantLockedRuleCount     = 31
	wantUserDisablableCount = 3
)

func TestDocConsistency_BuiltinRuleCounts(t *testing.T) {
	loader := NewLoader("")
	yamlRules, err := loader.LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin: %v", err)
	}

	dynamic := generateProtectionRules(EngineConfig{UserRulesDir: t.TempDir()})

	total := len(yamlRules) + len(dynamic)
	locked := len(dynamic) // all dynamic rules are locked
	for _, r := range yamlRules {
		if r.IsLocked() {
			locked++
		}
	}
	userDisablable := total - locked

	if total != wantTotalRuleCount {
		t.Errorf("total builtin rules = %d, want %d\n"+
			"  → Update wantTotalRuleCount in this file AND:\n"+
			"    - README.md  (\"30 security rules\")\n"+
			"    - docs/cli.md",
			total, wantTotalRuleCount)
	}
	if locked != wantLockedRuleCount {
		t.Errorf("locked builtin rules = %d, want %d\n"+
			"  → Update wantLockedRuleCount in this file AND:\n"+
			"    - README.md  (\"27 locked\")\n"+
			"    - docs/cli.md  (--disable-builtin description)",
			locked, wantLockedRuleCount)
	}
	if userDisablable != wantUserDisablableCount {
		t.Errorf("user-disablable rules = %d, want %d\n"+
			"  → Update wantUserDisablableCount in this file AND:\n"+
			"    - README.md  (\"3 user-disablable\")",
			userDisablable, wantUserDisablableCount)
	}

	// Assert docs reflect the source counts (README uses markdown bold around numbers)
	docContains(t, "README.md", "34 security rules")
	docContains(t, "README.md", "31 locked")
	docContains(t, "README.md", "3 user-disablable")
}

// ── CLI commands ──────────────────────────────────────────────────────────────

// requiredCLICommands lists user-facing commands that must appear in docs/cli.md.
// Hidden aliases (wrap, mcp, lint-rules) are internal and not required in docs.
var requiredCLICommands = []string{
	"crust start",
	"crust stop",
	"crust status",
	"crust logs",
	"crust add-rule",
	"crust remove-rule",
	"crust list-rules",
	"crust doctor",
}

func TestDocConsistency_CLICommands(t *testing.T) {
	for _, cmd := range requiredCLICommands {
		docContains(t, "docs/cli.md", cmd)
	}
}

// ── Fuzz targets ─────────────────────────────────────────────────────────────

func TestDocConsistency_FuzzTargetCount(t *testing.T) {
	root := repoRoot(t)
	count := 0
	err := filepath.Walk(filepath.Join(root, "internal"), func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, "_test.go") {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		count += strings.Count(string(data), "\nfunc Fuzz")
		return nil
	})
	if err != nil {
		t.Fatalf("walking internal/: %v", err)
	}

	// README badge: "Fuzz%20Tested-NN%20targets"
	readme := readDoc(t, "README.md")
	badge := fmt.Sprintf("Fuzz%%20Tested-%d%%20targets", count)
	if !strings.Contains(readme, badge) {
		t.Errorf("README.md fuzz badge does not match source code\n"+
			"  actual fuzz targets: %d\n"+
			"  → Update the Fuzz Tested badge in README.md", count)
	}
}

// ── CVE tracker ──────────────────────────────────────────────────────────────

func TestDocConsistency_CVETrackerCount(t *testing.T) {
	tracker := readDoc(t, "docs/cve-tracker.md")
	readme := readDoc(t, "README.md")

	// Extract total from tracker: | **Total** | **NN** |
	totalIdx := strings.Index(tracker, "| **Total**")
	if totalIdx < 0 {
		t.Fatal("cve-tracker.md missing Total row")
	}
	line := tracker[totalIdx : totalIdx+60]
	// Extract number between ** **
	parts := strings.Split(line, "**")
	if len(parts) < 4 {
		t.Fatal("cannot parse Total row in cve-tracker.md")
	}
	trackerTotal := strings.TrimSpace(parts[3])

	// README should reference the same count
	expected := trackerTotal + " real-world CVEs"
	if !strings.Contains(readme, expected) {
		t.Errorf("README.md CVE count does not match cve-tracker.md\n"+
			"  tracker total: %s\n"+
			"  → Update README.md to say \"%s\"", trackerTotal, expected)
	}
}

// ── Crypto wallet chains ─────────────────────────────────────────────────────

func TestDocConsistency_CryptoChainCount(t *testing.T) {
	// Count chains by reading dlp_crypto.go source — the loop chains + hardcoded ones.
	cryptoFile := readDoc(t, filepath.Join("internal", "rules", "dlp_crypto.go"))

	// Count chains in the for-range loop (e.g., "bitcoin", "litecoin", ...)
	loopChains := 0
	inLoop := false
	for line := range strings.SplitSeq(cryptoFile, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "for _, chain := range []string{") {
			inLoop = true
			continue
		}
		if inLoop {
			if trimmed == "} {" || trimmed == "}" {
				break
			}
			loopChains += strings.Count(trimmed, `"`) / 2 // each chain is a quoted string
		}
	}

	// Hardcoded chains after the loop: solana, sui, aptos
	hardcoded := 0
	for _, chain := range []string{".solana", ".sui", ".aptos"} {
		if strings.Contains(cryptoFile, chain) {
			hardcoded++
		}
	}

	total := loopChains + hardcoded

	// Verify docs
	readme := readDoc(t, "README.md")
	expected := fmt.Sprintf("for %d chains", total)
	if !strings.Contains(readme, expected) {
		t.Errorf("README.md crypto chain count does not match source\n"+
			"  actual chains: %d (loop: %d + hardcoded: %d)\n"+
			"  → Update README.md to say \"%s\"", total, loopChains, hardcoded, expected)
	}

	howItWorks := readDoc(t, filepath.Join("docs", "how-it-works.md"))
	expectedHIW := fmt.Sprintf("(%d chains)", total)
	if !strings.Contains(howItWorks, expectedHIW) {
		t.Errorf("docs/how-it-works.md crypto chain count does not match source\n"+
			"  actual chains: %d\n"+
			"  → Update docs/how-it-works.md", total)
	}
}

// ── DLP provider count ──────────────────────────────────────────────────────

func TestDocConsistency_DLPProviderCount(t *testing.T) {
	howItWorks := readDoc(t, filepath.Join("docs", "how-it-works.md"))

	// Count data rows in the DLP provider table (between "| Provider |" and next blank line)
	providerCount := 0
	inTable := false
	for line := range strings.SplitSeq(howItWorks, "\n") {
		if strings.HasPrefix(line, "| Provider |") {
			inTable = true
			continue
		}
		if inTable {
			if strings.HasPrefix(line, "|--") {
				continue
			}
			if !strings.HasPrefix(line, "| ") {
				break
			}
			providerCount++
		}
	}

	// README says "AWS, GitHub, Stripe, OpenAI, Anthropic, and NN more"
	readme := readDoc(t, "README.md")
	namedInReadme := 5 // AWS, GitHub, Stripe, OpenAI, Anthropic
	moreCount := providerCount - namedInReadme
	expected := fmt.Sprintf("and [%d more]", moreCount)
	if !strings.Contains(readme, expected) {
		t.Errorf("README.md DLP provider 'N more' does not match how-it-works.md table\n"+
			"  how-it-works.md providers: %d, README names %d, so 'more' should be %d\n"+
			"  → Update README.md", providerCount, namedInReadme, moreCount)
	}
}

// ── Pre-commit hook count ───────────────────────────────────────────────────

// nonSecurityHooks are pre-commit hooks that are not security checks.
var nonSecurityHooks = map[string]bool{
	"demo-gif": true,
}

func TestDocConsistency_SecurityCheckCount(t *testing.T) {
	precommit := readDoc(t, ".pre-commit-config.yaml")

	total := 0
	security := 0
	scanner := bufio.NewScanner(strings.NewReader(precommit))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if after, ok := strings.CutPrefix(line, "- id: "); ok {
			id := after
			total++
			if !nonSecurityHooks[id] {
				security++
			}
		}
	}

	// README: "NN automated security checks"
	readme := readDoc(t, "README.md")
	expected := fmt.Sprintf("%d automated security checks", security)
	if !strings.Contains(readme, expected) {
		t.Errorf("README.md security check count does not match .pre-commit-config.yaml\n"+
			"  total hooks: %d, security hooks: %d (excluding %v)\n"+
			"  → Update README.md to say \"%s\"", total, security, nonSecurityHooks, expected)
	}
}

// ── Block mode strings ────────────────────────────────────────────────────────

// Verify the block mode description is consistent across all docs.
// The correct description is "text warning block" — NOT "echo command".
func TestDocConsistency_BlockModeDescription(t *testing.T) {
	stalePhrase := "echo command"
	docs := []string{"README.md", "docs/cli.md", "docs/configuration.md"}
	for _, doc := range docs {
		content := readDoc(t, doc)
		if strings.Contains(content, stalePhrase) {
			t.Errorf("%s contains stale phrase %q — replace with \"text warning block\"", doc, stalePhrase)
		}
	}
}
