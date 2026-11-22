package agentmode_test

import (
	"os"
	"testing"

	"github.com/cyberark/idsec-cli-golang/pkg/agentmode"
)

// clearAgentEnv neutralises IDSEC_AGENT_MODE, IDSEC_FORCE_AGENT_MODE and every
// detector, and resets the package state once the test finishes.
func clearAgentEnv(t *testing.T) {
	t.Helper()
	t.Setenv(agentmode.EnvVar, "")
	t.Setenv(agentmode.ForceEnvVar, "")
	for _, v := range agentmode.DetectorEnvVars() {
		t.Setenv(v, "")
	}
	t.Cleanup(func() {
		_ = os.Setenv(agentmode.EnvVar, "")
		_ = os.Setenv(agentmode.ForceEnvVar, "")
		for _, v := range agentmode.DetectorEnvVars() {
			_ = os.Setenv(v, "")
		}
		agentmode.Resolve(false, false)
	})
}

type resolveWant struct {
	enabled  bool
	source   agentmode.Source
	detected string
}

func assertResolved(t *testing.T, want resolveWant) {
	t.Helper()
	if got := agentmode.IsEnabled(); got != want.enabled {
		t.Errorf("IsEnabled() = %v, want %v", got, want.enabled)
	}
	if got := agentmode.ResolvedSource(); got != want.source {
		t.Errorf("ResolvedSource() = %q, want %q", got, want.source)
	}
	if got := agentmode.DetectedAgent(); got != want.detected {
		t.Errorf("DetectedAgent() = %q, want %q", got, want.detected)
	}
}

func TestResolve_PrecedenceMatrix(t *testing.T) {
	tests := []struct {
		name        string
		flagAgent   bool
		flagNoAgent bool
		// idsecAgentValues runs one inner subtest per value; nil means IDSEC_AGENT_MODE is unset.
		idsecAgentValues []string
		forceAgent       string
		detectorEnv      map[string]string
		want             resolveWant
	}{
		{
			name: "success_default_off",
			want: resolveWant{false, agentmode.SourceDefault, ""},
		},
		{
			name:      "success_flag_agent_on",
			flagAgent: true,
			want:      resolveWant{true, agentmode.SourceFlag, ""},
		},
		{
			name:        "success_flag_no_agent_off",
			flagNoAgent: true,
			want:        resolveWant{false, agentmode.SourceFlag, ""},
		},
		{
			name:        "edge_case_both_flags_no_agent_wins",
			flagAgent:   true,
			flagNoAgent: true,
			want:        resolveWant{false, agentmode.SourceFlag, ""},
		},
		{
			name:             "success_flag_agent_beats_env_off",
			flagAgent:        true,
			idsecAgentValues: []string{"0"},
			want:             resolveWant{true, agentmode.SourceFlag, ""},
		},
		{
			name:             "success_flag_no_agent_beats_env_on",
			flagNoAgent:      true,
			idsecAgentValues: []string{"1"},
			want:             resolveWant{false, agentmode.SourceFlag, ""},
		},
		{
			name:        "success_flag_no_agent_beats_autodetect",
			flagNoAgent: true,
			detectorEnv: map[string]string{"CURSOR_AGENT": "1"},
			want:        resolveWant{false, agentmode.SourceFlag, "cursor"},
		},
		{
			name:        "success_flag_agent_still_detects",
			flagAgent:   true,
			detectorEnv: map[string]string{"CLAUDECODE": "1"},
			want:        resolveWant{true, agentmode.SourceFlag, "claude-code"},
		},
		{
			name:             "success_env_on_1",
			idsecAgentValues: []string{"1"},
			want:             resolveWant{true, agentmode.SourceEnv, ""},
		},
		{
			name:             "success_env_on_spellings",
			idsecAgentValues: []string{"true", "TRUE", "yes", "on", " Yes "},
			want:             resolveWant{true, agentmode.SourceEnv, ""},
		},
		{
			name:             "success_env_off_beats_autodetect",
			idsecAgentValues: []string{"0", "false", "no", "off"},
			detectorEnv:      map[string]string{"CURSOR_AGENT": "1"},
			want:             resolveWant{false, agentmode.SourceEnv, "cursor"},
		},
		{
			name:             "success_env_on_still_detects",
			idsecAgentValues: []string{"1"},
			detectorEnv:      map[string]string{"CLAUDECODE": "1"},
			want:             resolveWant{true, agentmode.SourceEnv, "claude-code"},
		},
		{
			name:             "edge_case_env_unrecognised_falls_through",
			idsecAgentValues: []string{"maybe"},
			detectorEnv:      map[string]string{"CURSOR_AGENT": "1"},
			want:             resolveWant{true, agentmode.SourceAutoDetect, "cursor"},
		},
		{
			name:             "edge_case_env_unrecognised_no_detector",
			idsecAgentValues: []string{"maybe"},
			want:             resolveWant{false, agentmode.SourceDefault, ""},
		},
		{
			name:        "success_autodetect_on",
			detectorEnv: map[string]string{"CURSOR_AGENT": "1"},
			want:        resolveWant{true, agentmode.SourceAutoDetect, "cursor"},
		},
		{
			name:        "edge_case_ci_vars_not_detected",
			detectorEnv: map[string]string{"GITHUB_ACTIONS": "true", "JENKINS_URL": "http://x", "CI": "true"},
			want:        resolveWant{false, agentmode.SourceDefault, ""},
		},
		{
			name:        "edge_case_empty_detector_ignored",
			detectorEnv: map[string]string{"CURSOR_AGENT": ""},
			want:        resolveWant{false, agentmode.SourceDefault, ""},
		},
		{
			name:       "success_force_on",
			forceAgent: "1",
			want:       resolveWant{true, agentmode.SourceEnv, ""},
		},
		{
			name:       "success_force_truthy_spelling",
			forceAgent: "true",
			want:       resolveWant{true, agentmode.SourceEnv, ""},
		},
		{
			name:             "success_force_beats_env_off",
			forceAgent:       "1",
			idsecAgentValues: []string{"0"},
			want:             resolveWant{true, agentmode.SourceEnv, ""},
		},
		{
			name:        "success_force_on_still_detects",
			forceAgent:  "1",
			detectorEnv: map[string]string{"CLAUDECODE": "1"},
			want:        resolveWant{true, agentmode.SourceEnv, "claude-code"},
		},
		{
			name:        "success_flag_no_agent_beats_force",
			flagNoAgent: true,
			forceAgent:  "1",
			want:        resolveWant{false, agentmode.SourceFlag, ""},
		},
		{
			name:        "edge_case_force_falsy_not_an_off_switch",
			forceAgent:  "0",
			detectorEnv: map[string]string{"CURSOR_AGENT": "1"},
			want:        resolveWant{true, agentmode.SourceAutoDetect, "cursor"},
		},
		{
			name:       "edge_case_force_unrecognised_ignored",
			forceAgent: "maybe",
			want:       resolveWant{false, agentmode.SourceDefault, ""},
		},
		{
			// IDSEC_AGENT (old name) must be ignored — only IDSEC_AGENT_MODE works.
			name:        "edge_case_legacy_idsec_agent_ignored",
			detectorEnv: map[string]string{"IDSEC_AGENT": "1"},
			want:        resolveWant{false, agentmode.SourceDefault, ""},
		},
	}

	if len(tests) != 25 {
		t.Fatalf("Expected 25 precedence rows, got %d", len(tests))
	}

	for _, tt := range tests {
		run := func(t *testing.T, idsecAgent *string) {
			clearAgentEnv(t)
			if idsecAgent != nil {
				t.Setenv(agentmode.EnvVar, *idsecAgent)
			}
			if tt.forceAgent != "" {
				t.Setenv(agentmode.ForceEnvVar, tt.forceAgent)
			}
			for k, v := range tt.detectorEnv {
				t.Setenv(k, v)
			}

			agentmode.Resolve(tt.flagAgent, tt.flagNoAgent)

			assertResolved(t, tt.want)
		}

		t.Run(tt.name, func(t *testing.T) {
			switch len(tt.idsecAgentValues) {
			case 0:
				run(t, nil)
			case 1:
				run(t, &tt.idsecAgentValues[0])
			default:
				for i := range tt.idsecAgentValues {
					value := tt.idsecAgentValues[i]
					t.Run(value, func(t *testing.T) {
						run(t, &value)
					})
				}
			}
		})
	}
}

func TestResolve_StateTransitions(t *testing.T) {
	t.Run("success_resolve_is_idempotent_and_overwrites", func(t *testing.T) {
		clearAgentEnv(t)
		agentmode.Resolve(true, false)
		assertResolved(t, resolveWant{true, agentmode.SourceFlag, ""})

		clearAgentEnv(t)
		agentmode.Resolve(false, false)
		assertResolved(t, resolveWant{false, agentmode.SourceDefault, ""})
	})
}
