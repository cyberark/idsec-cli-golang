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
	if successCount != 1 || failureCount != 1 {
		t.Fatalf("writeKubeconfigs() counts = (%d, %d), want (1, 1)", successCount, failureCount)
	}
	if _, err := os.Stat(filepath.Join(tempDir, "aws.yml")); err != nil {
		t.Fatalf("aws kubeconfig not written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tempDir, "azure.yml")); !os.IsNotExist(err) {
		t.Fatalf("azure kubeconfig should not exist, err = %v", err)
	}
	if summary["azure"] != "error: Failed to fetch clusters for azure" {
		t.Fatalf("azure summary = %q, want error string", summary["azure"])
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
