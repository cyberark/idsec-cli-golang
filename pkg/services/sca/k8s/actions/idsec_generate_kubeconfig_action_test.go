package actions

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/cyberark/idsec-sdk-golang/pkg/config"
)

func TestParseAllFlagFromArgv(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		argv   []string
		want   string
		wantOK bool
	}{
		{name: "empty", argv: []string{}, want: "", wantOK: false},
		{name: "no_all_flag", argv: []string{"generate-kubeconfig", "--csp", "aws"}, want: "", wantOK: false},
		{name: "equals_false", argv: []string{"generate-kubeconfig", "--all=false"}, want: "false", wantOK: true},
		{name: "equals_true", argv: []string{"generate-kubeconfig", "--all=true"}, want: "true", wantOK: true},
		{name: "two_token_false", argv: []string{"generate-kubeconfig", "--all", "false"}, want: "false", wantOK: true},
		{name: "two_token_true", argv: []string{"generate-kubeconfig", "--all", "true"}, want: "true", wantOK: true},
		{name: "bare_all", argv: []string{"generate-kubeconfig", "--all", "--verbose"}, want: "true", wantOK: true},
		{name: "bare_all_at_end", argv: []string{"generate-kubeconfig", "--verbose", "--all"}, want: "true", wantOK: true},
		{name: "last_wins_equals", argv: []string{"generate-kubeconfig", "--all", "false", "--all=true"}, want: "true", wantOK: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := parseAllFlagFromArgv(tt.argv)
			if got != tt.want || ok != tt.wantOK {
				t.Fatalf("parseAllFlagFromArgv(%v) = (%q, %v), want (%q, %v)", tt.argv, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func TestArgvAfterSubcommand(t *testing.T) {
	t.Parallel()
	got := argvAfterSubcommand([]string{"idsec", "exec", "sca", "k8s", "generate-kubeconfig", "--all", "false"}, "generate-kubeconfig")
	want := []string{"generate-kubeconfig", "--all", "false"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("argvAfterSubcommand() = %v, want %v", got, want)
	}
}

func TestNormalizeGenerateKubeconfigResultExpandsAllValue(t *testing.T) {
	t.Parallel()
	got := normalizeGenerateKubeconfigResult("", map[string]string{
		"all": mustJSON(t, map[string]string{
			"aws":   "apiVersion: v1\nkind: Config\nclusters: []\n",
			"azure": "error: backend failure",
		}),
	})
	want := map[string]string{
		"aws":   "apiVersion: v1\nkind: Config\nclusters: []\n",
		"azure": "error: backend failure",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalizeGenerateKubeconfigResult() = %#v, want %#v", got, want)
	}
}

func TestNormalizeGenerateKubeconfigResultRemapsSingleEntryToRequestedCSP(t *testing.T) {
	t.Parallel()
	got := normalizeGenerateKubeconfigResult("aws", map[string]string{"all": "apiVersion: v1"})
	want := map[string]string{"aws": "apiVersion: v1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalizeGenerateKubeconfigResult() = %#v, want %#v", got, want)
	}
}

func TestWriteKubeconfigsPartialSuccess(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	result := map[string]string{
		"aws": `apiVersion: v1
kind: Config
preferences: {}
clusters: []`,
		"azure": "error: Failed to fetch clusters for azure",
	}

	summary, successCount, failureCount := writeKubeconfigs(result, tempDir)
	// Both CSPs write a file: aws writes the real kubeconfig, azure writes the empty one.
	if successCount != 2 || failureCount != 0 {
		t.Fatalf("writeKubeconfigs() counts = (%d, %d), want (2, 0)", successCount, failureCount)
	}
	if _, err := os.Stat(filepath.Join(tempDir, "aws.yml")); err != nil {
		t.Fatalf("aws kubeconfig not written: %v", err)
	}
	// azure should now exist with the empty kubeconfig (stale file overwritten).
	if _, err := os.Stat(filepath.Join(tempDir, "azure.yml")); err != nil {
		t.Fatalf("azure empty kubeconfig should have been written: %v", err)
	}
	if summary["azure"] != "no eligible targets" {
		t.Fatalf("azure summary = %q, want 'no eligible targets'", summary["azure"])
	}
}

func TestWriteKubeconfigs_NoEligibleTargets_WritesEmptyKubeconfig(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	result := map[string]string{
		"aws":   "error: no eligible K8s clusters for this user",
		"azure": "error: no eligible K8s clusters for this user",
	}

	summary, successCount, failureCount := writeKubeconfigs(result, tempDir)
	if successCount != 2 || failureCount != 0 {
		t.Fatalf("writeKubeconfigs() counts = (%d, %d), want (2, 0)", successCount, failureCount)
	}

	for _, csp := range []string{"aws", "azure"} {
		kubeconfigPath := filepath.Join(tempDir, csp+".yml")
		data, err := os.ReadFile(kubeconfigPath)
		if err != nil {
			t.Fatalf("[%s] empty kubeconfig not written: %v", csp, err)
		}
		if string(data) != emptyKubeconfigContent {
			t.Fatalf("[%s] kubeconfig content = %q, want emptyKubeconfigContent", csp, string(data))
		}
		if summary[csp] != "no eligible targets" {
			t.Fatalf("[%s] summary = %q, want 'no eligible targets'", csp, summary[csp])
		}
	}
}

func TestWriteKubeconfigs_NoEligibleTargets_OverwritesExistingStaleKubeconfig(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	staleContent := "apiVersion: v1\nkind: Config\nclusters:\n- name: stale-cluster\n"
	staleFile := filepath.Join(tempDir, "aws.yml")
	if err := os.WriteFile(staleFile, []byte(staleContent), 0600); err != nil {
		t.Fatalf("failed to write stale kubeconfig: %v", err)
	}

	result := map[string]string{
		"aws": "error: no eligible K8s clusters for this user",
	}

	_, successCount, failureCount := writeKubeconfigs(result, tempDir)
	if successCount != 1 || failureCount != 0 {
		t.Fatalf("writeKubeconfigs() counts = (%d, %d), want (1, 0)", successCount, failureCount)
	}

	data, err := os.ReadFile(staleFile)
	if err != nil {
		t.Fatalf("kubeconfig file should still exist after overwrite: %v", err)
	}
	if string(data) == staleContent {
		t.Fatalf("stale kubeconfig was not overwritten: content still = %q", string(data))
	}
	if string(data) != emptyKubeconfigContent {
		t.Fatalf("kubeconfig content = %q, want emptyKubeconfigContent", string(data))
	}
}

func TestWriteKubeconfigs_NoEligibleTargets_WithCustomKubeconfigLocation(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	customPath := filepath.Join(tempDir, "my-custom.yaml")

	result := map[string]string{
		"aws": "error: no eligible K8s clusters for this user",
	}

	_, successCount, failureCount := writeKubeconfigs(result, customPath)
	if successCount != 1 || failureCount != 0 {
		t.Fatalf("writeKubeconfigs() counts = (%d, %d), want (1, 0)", successCount, failureCount)
	}

	data, err := os.ReadFile(customPath)
	if err != nil {
		t.Fatalf("custom kubeconfig not written: %v", err)
	}
	if string(data) != emptyKubeconfigContent {
		t.Fatalf("custom kubeconfig content = %q, want emptyKubeconfigContent", string(data))
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return string(data)
}

// ── parseVersionMismatchBody ──────────────────────────────────────────────────

func TestParseVersionMismatchBody(t *testing.T) {
	tests := []struct {
		name             string
		errMsg           string
		expectedRequired string
		expectedOK       bool
	}{
		{
			name:             "parses_structured_426_with_minVersion",
			errMsg:           `generate-kubeconfig API returned status 426. Response body: {"code":"CLI_VERSION_UNSUPPORTED","message":"idsec CLI version mismatch. Current: 0.13.0, required: >= 0.15.0.","currentVersion":"0.13.0","minVersion":"0.15.0"}`,
			expectedRequired: "0.15.0",
			expectedOK:       true,
		},
		{
			name:             "parses_nested_error_with_426",
			errMsg:           `generate-kubeconfig API call failed: generate-kubeconfig API returned status 426. Response body: {"code":"CLI_VERSION_UNSUPPORTED","currentVersion":"0.13.0","minVersion":"2.5.0"}`,
			expectedRequired: "2.5.0",
			expectedOK:       true,
		},
		{
			name:             "returns_false_for_different_error_code",
			errMsg:           `generate-kubeconfig API returned status 403. Response body: {"code":"permission_denied"}`,
			expectedRequired: "",
			expectedOK:       false,
		},
		{
			name:             "returns_false_for_non_json_body",
			errMsg:           `generate-kubeconfig API returned status 403. Response body: SCA eligibility request failed looks like something is misconfigured.`,
			expectedRequired: "",
			expectedOK:       false,
		},
		{
			name:             "returns_false_when_no_response_body_marker",
			errMsg:           `generate-kubeconfig API call failed: connection refused`,
			expectedRequired: "",
			expectedOK:       false,
		},
		{
			name:             "returns_false_for_empty_body",
			errMsg:           `generate-kubeconfig API returned status 403. Response body: `,
			expectedRequired: "",
			expectedOK:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			required, ok := parseVersionMismatchBody(tt.errMsg)
			assert.Equal(t, tt.expectedOK, ok)
			assert.Equal(t, tt.expectedRequired, required)
		})
	}
}

// ── VersionMismatchHint ───────────────────────────────────────────────────────

func TestVersionMismatchHint(t *testing.T) {
	config.SetIdsecVersion("0.15.0")

	t.Run("structured_426_shows_exact_min_version", func(t *testing.T) {
		errMsg := `generate-kubeconfig API call failed: generate-kubeconfig API returned status 426. Response body: {"code":"CLI_VERSION_UNSUPPORTED","message":"idsec CLI version mismatch. Current: 0.15.0, required: >= 0.17.0.","currentVersion":"0.15.0","minVersion":"0.17.0"}`
		result := VersionMismatchHint(errMsg)

		assert.Contains(t, result, "idsec CLI version mismatch")
		assert.Contains(t, result, "Current version : 0.15.0")
		assert.Contains(t, result, "Required version: >= 0.17.0")

		// Raw error replaced entirely — not appended
		assert.NotContains(t, result, "generate-kubeconfig API call failed")
	})

	t.Run("does_not_show_vague_hint_language", func(t *testing.T) {
		errMsg := `generate-kubeconfig API returned status 426. Response body: {"code":"CLI_VERSION_UNSUPPORTED","currentVersion":"0.15.0","minVersion":"2.5.0"}`
		result := VersionMismatchHint(errMsg)

		assert.NotContains(t, result, "may indicate")
		assert.Contains(t, result, "Required version: >= 2.5.0")
	})

	t.Run("unrelated_403_returned_unchanged", func(t *testing.T) {
		errMsg := "generate-kubeconfig API returned status 403. Access denied by policy."
		result := VersionMismatchHint(errMsg)

		assert.Equal(t, errMsg, result, "unrelated 403 must be returned unchanged")
	})

	t.Run("unrelated_401_returned_unchanged", func(t *testing.T) {
		errMsg := "generate-kubeconfig API returned status 401. Unauthorized."
		result := VersionMismatchHint(errMsg)

		assert.Equal(t, errMsg, result, "unrelated error must be returned unchanged")
	})

	t.Run("network_error_returned_unchanged", func(t *testing.T) {
		errMsg := "generate-kubeconfig API call failed: dial tcp: connection refused"
		result := VersionMismatchHint(errMsg)

		assert.Equal(t, errMsg, result)
	})

	t.Run("version_mismatch_without_minVersion_field_shows_fallback", func(t *testing.T) {
		errMsg := `generate-kubeconfig API returned status 426. Response body: {"code":"CLI_VERSION_UNSUPPORTED"}`
		result := VersionMismatchHint(errMsg)

		assert.Contains(t, result, "idsec CLI version mismatch")
		assert.Contains(t, result, "Current version : 0.15.0")
		assert.Contains(t, result, "unknown (please upgrade to the latest version)")
		assert.NotContains(t, result, "Required version: \n")
	})

	// Every endpoint behind the server-side version check returns the same body; only the SDK prefix differs.
	for name, errMsg := range map[string]string{
		"list_targets": `list-clusters API returned status 426. Response body: {"code":"CLI_VERSION_UNSUPPORTED","currentVersion":"0.15.0","minVersion":"0.17.0"}`,
		"evaluate":     `eligibility evaluation failed: evaluate eligibility API returned status 426. Response body: {"code":"CLI_VERSION_UNSUPPORTED","currentVersion":"0.15.0","minVersion":"0.17.0"}`,
		"elevate":      `elevate API call failed: elevate API returned status 426. Response body: {"code":"CLI_VERSION_UNSUPPORTED","currentVersion":"0.15.0","minVersion":"0.17.0"}`,
	} {
		t.Run("rewrites_426_from_"+name, func(t *testing.T) {
			result := VersionMismatchHint(errMsg)

			assert.Contains(t, result, "Current version : 0.15.0")
			assert.Contains(t, result, "Required version: >= 0.17.0")
			assert.NotContains(t, result, "Response body")
		})
	}

	t.Run("both_upgrade_paths_always_present", func(t *testing.T) {
		errMsg := `generate-kubeconfig API returned status 426. Response body: {"code":"CLI_VERSION_UNSUPPORTED","currentVersion":"0.15.0","minVersion":"0.17.0"}`
		result := VersionMismatchHint(errMsg)

		assert.Contains(t, result, "Current version : 0.15.0")
		assert.Contains(t, result, "Required version: >= 0.17.0")
	})
}

func TestFindVersionMismatch(t *testing.T) {
	body := `API call failed: generate-kubeconfig API returned status 426. Response body: {"code":"CLI_VERSION_UNSUPPORTED","minVersion":"0.13.0"}`
	t.Run("detects mismatch across CSPs", func(t *testing.T) {
		msg, ok := findVersionMismatch(map[string]string{"aws": body, "azure": body})
		if !ok || !strings.Contains(msg, ">= 0.13.0") {
			t.Fatalf("expected mismatch, got ok=%v msg=%q", ok, msg)
		}
	})
	t.Run("ignores other errors and valid results", func(t *testing.T) {
		_, ok := findVersionMismatch(map[string]string{"aws": "API call failed: boom", "azure": "apiVersion: v1"})
		if ok {
			t.Fatal("did not expect mismatch")
		}
	})
}
