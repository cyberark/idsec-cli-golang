package agentmode

import "testing"

func TestScanAgentFlags(t *testing.T) {
	tests := []struct {
		name        string
		argv        []string
		wantAgent   bool
		wantNoAgent bool
	}{
		{"edge_case_empty", []string{}, false, false},
		{"edge_case_nil", nil, false, false},
		{"success_agent", []string{"exec", "--agent"}, true, false},
		{"success_agent_true", []string{"--agent=true"}, true, false},
		{"success_agent_false", []string{"--agent=false"}, false, false},
		{"success_no_agent", []string{"--no-agent"}, false, true},
		{"success_no_agent_false", []string{"--no-agent=false"}, false, false},
		{"success_both", []string{"--agent", "--no-agent"}, true, true},
		{"success_last_occurrence_wins", []string{"--agent", "--agent=false"}, false, false},
		{"edge_case_after_double_dash", []string{"--", "--agent"}, false, false},
		{"edge_case_before_double_dash", []string{"--agent", "--", "--no-agent"}, true, false},
		{"edge_case_prefix_is_not_flag", []string{"--agentx"}, false, false},
		{"edge_case_garbage_value", []string{"--agent=garbage"}, false, false},
		{"edge_case_single_dash", []string{"-agent"}, false, false},
		{"edge_case_value_token", []string{"--description", "--agent"}, true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotAgent, gotNoAgent := scanAgentFlags(tt.argv)
			if gotAgent != tt.wantAgent || gotNoAgent != tt.wantNoAgent {
				t.Errorf("scanAgentFlags(%q) = (%v, %v), want (%v, %v)",
					tt.argv, gotAgent, gotNoAgent, tt.wantAgent, tt.wantNoAgent)
			}
		})
	}
}
