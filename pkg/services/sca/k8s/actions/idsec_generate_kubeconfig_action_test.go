package actions

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
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
