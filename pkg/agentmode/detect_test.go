package agentmode_test

import (
	"regexp"
	"sort"
	"testing"

	"github.com/cyberark/idsec-cli-golang/pkg/agentmode"
)

// detectorTable is written out literally, not derived from the registry, so
// that renaming a slug (a telemetry contract) breaks a test.
var detectorTable = []struct {
	envVar   string
	wantSlug string
}{
	{"CLAUDECODE", "claude-code"},
	{"CLAUDE_CODE", "claude-code"},
	{"CURSOR_AGENT", "cursor"},
	{"CODEX", "codex"},
	{"OPENAI_CODEX", "codex"},
	{"AIDER", "aider"},
	{"CLINE", "cline"},
	{"WINDSURF_AGENT", "windsurf"},
	{"GITHUB_COPILOT", "copilot"},
	{"AMAZON_Q", "amazon-q"},
	{"AWS_Q_DEVELOPER", "amazon-q"},
	{"GEMINI_CODE_ASSIST", "gemini"},
	{"SRC_CODY", "cody"},
	{"PI_CODING_AGENT", "pi"},
	{"AGENT", "generic"},
}

// clearAllAgentEnv neutralises IDSEC_AGENT_MODE, IDSEC_FORCE_AGENT_MODE and every
// agent detector. Detectors only match non-empty values, so setting "" is
// equivalent to unsetting.
func clearAllAgentEnv(t *testing.T) {
	t.Helper()
	t.Setenv(agentmode.EnvVar, "")
	t.Setenv(agentmode.ForceEnvVar, "")
	for _, v := range agentmode.DetectorEnvVars() {
		t.Setenv(v, "")
	}
}

func TestDetect(t *testing.T) {
	t.Run("success_each_detector_maps_to_slug", func(t *testing.T) {
		if len(detectorTable) != 15 {
			t.Fatalf("Expected 15 detector rows, got %d", len(detectorTable))
		}
		for _, tt := range detectorTable {
			t.Run(tt.envVar, func(t *testing.T) {
				clearAllAgentEnv(t)
				t.Setenv(tt.envVar, "1")

				if got := agentmode.Detect(); got != tt.wantSlug {
					t.Errorf("Detect() with %s=1 = %q, want %q", tt.envVar, got, tt.wantSlug)
				}
			})
		}
	})

	t.Run("success_registry_fully_covered", func(t *testing.T) {
		var tableVars []string
		for _, tt := range detectorTable {
			tableVars = append(tableVars, tt.envVar)
		}
		registryVars := agentmode.DetectorEnvVars()
		sort.Strings(tableVars)
		sort.Strings(registryVars)

		if len(tableVars) != len(registryVars) {
			t.Fatalf("Table has %d vars, registry has %d: table=%v registry=%v", len(tableVars), len(registryVars), tableVars, registryVars)
		}
		for i := range tableVars {
			if tableVars[i] != registryVars[i] {
				t.Errorf("Table and registry differ: table=%v registry=%v", tableVars, registryVars)
				break
			}
		}
	})

	t.Run("success_first_match_wins", func(t *testing.T) {
		tests := []struct {
			name     string
			env      map[string]string
			wantSlug string
		}{
			{"agent_tier", map[string]string{"CLAUDECODE": "1", "CURSOR_AGENT": "1"}, "claude-code"},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				clearAllAgentEnv(t)
				for k, v := range tt.env {
					t.Setenv(k, v)
				}
				if got := agentmode.Detect(); got != tt.wantSlug {
					t.Errorf("Detect() = %q, want %q", got, tt.wantSlug)
				}
			})
		}
	})

	t.Run("success_generic_agent_lowest_ai_priority", func(t *testing.T) {
		clearAllAgentEnv(t)
		t.Setenv("AGENT", "1")
		t.Setenv("AIDER", "1")

		if got := agentmode.Detect(); got != "aider" {
			t.Errorf("Detect() = %q, want %q", got, "aider")
		}
	})

	t.Run("edge_case_ci_vars_not_detected", func(t *testing.T) {
		clearAllAgentEnv(t)
		t.Setenv("GITHUB_ACTIONS", "true")
		t.Setenv("GITLAB_CI", "true")
		t.Setenv("JENKINS_URL", "http://x")
		t.Setenv("CI", "true")

		if got := agentmode.Detect(); got != "" {
			t.Errorf("Detect() with only CI vars = %q, want empty", got)
		}
		vars := agentmode.DetectorEnvVars()
		for _, ci := range []string{"GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL", "CI"} {
			for _, v := range vars {
				if v == ci {
					t.Errorf("DetectorEnvVars() unexpectedly contains %s", ci)
				}
			}
		}
	})

	t.Run("success_no_env_returns_empty", func(t *testing.T) {
		clearAllAgentEnv(t)

		if got := agentmode.Detect(); got != "" {
			t.Errorf("Detect() = %q, want empty", got)
		}
	})

	t.Run("success_raw_value_never_returned", func(t *testing.T) {
		clearAllAgentEnv(t)
		t.Setenv("CURSOR_AGENT", "tok_SECRET/value")

		if got := agentmode.Detect(); got != "cursor" {
			t.Errorf("Detect() = %q, want %q", got, "cursor")
		}
	})

	t.Run("success_slugs_are_closed_set", func(t *testing.T) {
		format := regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
		for _, v := range agentmode.DetectorEnvVars() {
			t.Run(v, func(t *testing.T) {
				clearAllAgentEnv(t)
				t.Setenv(v, "1")

				slug := agentmode.Detect()
				if !format.MatchString(slug) {
					t.Errorf("Slug %q for %s does not match %s", slug, v, format)
				}
				if len(slug) > 32 {
					t.Errorf("Slug %q for %s is %d chars, want <= 32", slug, v, len(slug))
				}
			})
		}
	})

	t.Run("success_detector_env_vars_returns_copy", func(t *testing.T) {
		first := agentmode.DetectorEnvVars()
		want := append([]string(nil), first...)
		for i := range first {
			first[i] = "MUTATED"
		}

		second := agentmode.DetectorEnvVars()
		if len(second) != len(want) {
			t.Fatalf("DetectorEnvVars() length = %d, want %d", len(second), len(want))
		}
		for i := range want {
			if second[i] != want[i] {
				t.Errorf("DetectorEnvVars()[%d] = %q, want %q", i, second[i], want[i])
			}
		}
	})
}
