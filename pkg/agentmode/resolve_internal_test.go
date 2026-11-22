package agentmode

import "testing"

func TestParseEnvBool(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantValue bool
		wantOK    bool
	}{
		{"success_truthy_1", "1", true, true},
		{"success_truthy_true", "true", true, true},
		{"success_truthy_yes", "yes", true, true},
		{"success_truthy_on", "on", true, true},
		{"success_falsy_0", "0", false, true},
		{"success_falsy_false", "false", false, true},
		{"success_falsy_no", "no", false, true},
		{"success_falsy_off", "off", false, true},
		{"success_truthy_upper_case", "TRUE", true, true},
		{"success_truthy_mixed_case", "Yes", true, true},
		{"success_falsy_mixed_case", "Off", false, true},
		{"success_truthy_surrounding_whitespace", " Yes ", true, true},
		{"success_falsy_tabs_and_newline", "\tno\n", false, true},
		{"edge_case_empty_unrecognised", "", false, false},
		{"edge_case_whitespace_only_unrecognised", "   ", false, false},
		{"edge_case_maybe_unrecognised", "maybe", false, false},
		{"edge_case_2_unrecognised", "2", false, false},
		{"edge_case_strconv_short_form_unrecognised", "t", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotValue, gotOK := parseEnvBool(tt.input)
			if gotValue != tt.wantValue || gotOK != tt.wantOK {
				t.Errorf("parseEnvBool(%q) = (%v, %v), want (%v, %v)", tt.input, gotValue, gotOK, tt.wantValue, tt.wantOK)
			}
		})
	}
}

func TestEnableDisable(t *testing.T) {
	// Reset state fully before and after.
	enabled = false
	detectedSlug = ""
	source = SourceDefault
	defer func() {
		enabled = false
		detectedSlug = ""
		source = SourceDefault
	}()

	t.Run("success_enable_sets_slug", func(t *testing.T) {
		enable("x")
		if !enabled {
			t.Error("expected enabled=true after enable")
		}
		if detectedSlug != "x" {
			t.Errorf("detectedSlug = %q, want %q", detectedSlug, "x")
		}
	})

	t.Run("success_disable_clears_enabled_keeps_slug", func(t *testing.T) {
		enable("x")
		disable()
		if enabled {
			t.Error("expected enabled=false after disable")
		}
		if detectedSlug != "x" {
			t.Errorf("detectedSlug = %q after disable, want %q", detectedSlug, "x")
		}
	})
}
