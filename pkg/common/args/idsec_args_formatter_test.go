package args

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	survey "github.com/Iilun/survey/v2"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/cyberark/idsec-sdk-golang/pkg/config"
)

// captureFormatterStderr redirects os.Stderr to an in-memory pipe, runs fn,
// closes the write end, restores os.Stderr, and returns the captured bytes.
func captureFormatterStderr(fn func()) string {
	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	fn()
	_ = w.Close()
	os.Stderr = old
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String()
}

// captureFormatterStdout redirects os.Stdout to an in-memory pipe, runs fn,
// closes the write end, restores os.Stdout, and returns the captured bytes.
func captureFormatterStdout(fn func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String()
}

// setConfigState applies the given interactive/allowingOutput state and returns a
// cleanup function that restores the previous state.  Not safe for parallel tests
// because the config globals are process-wide.
func setConfigState(interactive, allowingOutput bool) func() {
	wasInteractive := config.IsInteractive()
	wasAllowing := config.IsAllowingOutput()

	if interactive {
		config.EnableInteractive()
	} else {
		config.DisableInteractive()
	}
	if allowingOutput {
		config.AllowOutput()
	} else {
		config.DisallowOutput()
	}

	return func() {
		if wasInteractive {
			config.EnableInteractive()
		} else {
			config.DisableInteractive()
		}
		if wasAllowing {
			config.AllowOutput()
		} else {
			config.DisallowOutput()
		}
	}
}

func TestPrintFailure(t *testing.T) {
	// Not using t.Parallel() – tests mutate process-global config state.
	tests := []struct {
		name         string
		interactive  bool
		allowOutput  bool
		msg          string
		wantOnStderr bool
		wantOnStdout bool
	}{
		{
			name:         "success_ungated_writes_to_stderr_when_non_interactive_and_output_disallowed",
			interactive:  false,
			allowOutput:  false,
			msg:          "fatal error",
			wantOnStderr: true,
			wantOnStdout: false,
		},
		{
			name:         "success_ungated_writes_to_stderr_when_interactive",
			interactive:  true,
			allowOutput:  false,
			msg:          "something went wrong",
			wantOnStderr: true,
			wantOnStdout: false,
		},
		{
			name:         "success_does_not_write_to_stdout",
			interactive:  false,
			allowOutput:  false,
			msg:          "stdout should be empty",
			wantOnStderr: true,
			wantOnStdout: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config.DisableColor()
			defer config.EnableColor()
			restore := setConfigState(tt.interactive, tt.allowOutput)
			defer restore()

			stderr := captureFormatterStderr(func() {
				PrintFailure(tt.msg)
			})
			stdout := captureFormatterStdout(func() {
				PrintFailure(tt.msg)
			})

			if tt.wantOnStderr && !strings.Contains(stderr, tt.msg) {
				t.Errorf("expected stderr to contain %q, got %q", tt.msg, stderr)
			}
			if !tt.wantOnStderr && stderr != "" {
				t.Errorf("expected empty stderr, got %q", stderr)
			}
			if tt.wantOnStdout && !strings.Contains(stdout, tt.msg) {
				t.Errorf("expected stdout to contain %q, got %q", tt.msg, stdout)
			}
			if !tt.wantOnStdout && stdout != "" {
				t.Errorf("expected empty stdout, got %q", stdout)
			}
		})
	}
}

func TestPrintWarning(t *testing.T) {
	// Not using t.Parallel() – tests mutate process-global config state.
	tests := []struct {
		name         string
		interactive  bool
		allowOutput  bool
		msg          string
		wantOnStderr bool
	}{
		{
			name:         "success_gated_suppressed_when_not_interactive_and_output_disallowed",
			interactive:  false,
			allowOutput:  false,
			msg:          "watch out",
			wantOnStderr: false,
		},
		{
			name:         "success_writes_to_stderr_when_allowing_output",
			interactive:  false,
			allowOutput:  true,
			msg:          "disk almost full",
			wantOnStderr: true,
		},
		{
			name:         "success_writes_to_stderr_when_interactive",
			interactive:  true,
			allowOutput:  false,
			msg:          "check your config",
			wantOnStderr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config.DisableColor()
			defer config.EnableColor()
			restore := setConfigState(tt.interactive, tt.allowOutput)
			defer restore()

			stderr := captureFormatterStderr(func() {
				PrintWarning(tt.msg)
			})

			if tt.wantOnStderr && !strings.Contains(stderr, tt.msg) {
				t.Errorf("expected stderr to contain %q, got %q", tt.msg, stderr)
			}
			if !tt.wantOnStderr && stderr != "" {
				t.Errorf("expected empty stderr (gated), got %q", stderr)
			}
		})
	}
}

func TestPrintColoredStderr(t *testing.T) {
	// Not using t.Parallel() – tests mutate process-global config state.
	tests := []struct {
		name         string
		interactive  bool
		allowOutput  bool
		msg          string
		wantOnStderr bool
	}{
		{
			name:         "success_gated_suppressed_when_not_interactive_and_output_disallowed",
			interactive:  false,
			allowOutput:  false,
			msg:          "info message",
			wantOnStderr: false,
		},
		{
			name:         "success_writes_to_stderr_when_allowing_output",
			interactive:  false,
			allowOutput:  true,
			msg:          "important notice",
			wantOnStderr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config.DisableColor()
			defer config.EnableColor()
			restore := setConfigState(tt.interactive, tt.allowOutput)
			defer restore()

			stderr := captureFormatterStderr(func() {
				PrintColoredStderr(tt.msg, color.New())
			})

			if tt.wantOnStderr && !strings.Contains(stderr, tt.msg) {
				t.Errorf("expected stderr to contain %q, got %q", tt.msg, stderr)
			}
			if !tt.wantOnStderr && stderr != "" {
				t.Errorf("expected empty stderr (gated), got %q", stderr)
			}
		})
	}
}

func TestPrintSuccess_StaysOnStdout(t *testing.T) {
	// Not using t.Parallel() – tests mutate process-global config state.
	tests := []struct {
		name string
		msg  string
	}{
		{
			name: "success_output_on_stdout_regression_guard",
			msg:  "operation succeeded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config.DisableColor()
			defer config.EnableColor()
			restore := setConfigState(true, false) // interactive=true so output is allowed
			defer restore()

			stdout := captureFormatterStdout(func() {
				PrintSuccess(tt.msg)
			})
			stderr := captureFormatterStderr(func() {
				PrintSuccess(tt.msg)
			})

			if !strings.Contains(stdout, tt.msg) {
				t.Errorf("expected stdout to contain %q, got %q", tt.msg, stdout)
			}
			if stderr != "" {
				t.Errorf("expected empty stderr for PrintSuccess, got %q", stderr)
			}
		})
	}
}

func TestPrintNormal_StaysOnStdout(t *testing.T) {
	// Not using t.Parallel() – tests mutate process-global config state.
	tests := []struct {
		name string
		msg  string
	}{
		{
			name: "success_output_on_stdout_regression_guard",
			msg:  "normal message",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config.DisableColor()
			defer config.EnableColor()
			restore := setConfigState(true, false) // interactive=true so output is allowed
			defer restore()

			stdout := captureFormatterStdout(func() {
				PrintNormal(tt.msg)
			})
			stderr := captureFormatterStderr(func() {
				PrintNormal(tt.msg)
			})

			if !strings.Contains(stdout, tt.msg) {
				t.Errorf("expected stdout to contain %q, got %q", tt.msg, stdout)
			}
			if stderr != "" {
				t.Errorf("expected empty stderr for PrintNormal, got %q", stderr)
			}
		})
	}
}

func TestStderrColor(t *testing.T) {
	// Not using t.Parallel() – tests stub the process-global IsStderrTTY var.
	tests := []struct {
		name         string
		isStderrTTY  bool
		wantColorOff bool
	}{
		{
			name:         "success_disables_color_on_instance_when_not_tty",
			isStderrTTY:  false,
			wantColorOff: true,
		},
		{
			name:         "success_keeps_color_when_tty",
			isStderrTTY:  true,
			wantColorOff: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origIsStderrTTY := IsStderrTTY
			IsStderrTTY = func() bool { return tt.isStderrTTY }
			defer func() { IsStderrTTY = origIsStderrTTY }()

			// Seed the instance with color explicitly enabled so that a
			// subsequent DisableColor() call made by stderrColor (when not a
			// TTY) is the only thing that can silence it. The test environment
			// sets NO_COLOR=1, which makes color.New() bake in noColor=true;
			// we need to override that at the instance level before we hand
			// it to stderrColor.
			c := color.New(color.FgRed)
			c.EnableColor() // baseline: color ON (noColor=false on the instance)

			result := stderrColor(c)

			// Sprint("x") returns plain "x" when color is disabled on the
			// instance (DisableColor was called), or returns ANSI-escaped
			// text when EnableColor is in effect.
			got := result.Sprint("x")
			hasANSI := strings.Contains(got, "\x1b[")

			if tt.wantColorOff && hasANSI {
				t.Errorf("expected no ANSI escapes when stderr is not a TTY, got %q", got)
			}
			if !tt.wantColorOff && !hasANSI {
				t.Errorf("expected ANSI escapes when stderr is a TTY, got %q", got)
			}
		})
	}
}

func TestGetArg_NonInteractive(t *testing.T) {
	tests := []struct {
		name               string
		flagVal            string
		existingVal        string
		prioritizeExisting bool
		emptyAllowed       bool
		wantVal            string
		wantErr            bool
		wantMissing        bool
	}{
		{name: "flag_value_returned", flagVal: "myval", wantVal: "myval"},
		{name: "existing_val_prioritized", existingVal: "existing", prioritizeExisting: true, wantVal: "existing"},
		{name: "empty_required_returns_missing", wantErr: true, wantMissing: true},
		{name: "empty_allowed_returns_empty", emptyAllowed: true, wantVal: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			restore := setConfigState(false, true)
			defer restore()
			orig := askOne
			t.Cleanup(func() { askOne = orig })
			askOne = func(_ survey.Prompt, _ interface{}, _ ...survey.AskOpt) error {
				t.Fatal("askOne must not be called in non-interactive mode")
				return nil
			}

			cmd := &cobra.Command{}
			cmd.Flags().String("mykey", "", "")
			if tt.flagVal != "" {
				_ = cmd.Flags().Set("mykey", tt.flagVal)
			}
			got, err := GetArg(cmd, "mykey", "Enter value", tt.existingVal, false, tt.prioritizeExisting, tt.emptyAllowed)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tt.wantErr)
			}
			if tt.wantMissing && !errors.Is(err, ErrMissingRequiredInput) {
				t.Fatalf("expected ErrMissingRequiredInput, got %v", err)
			}
			if tt.wantMissing {
				var m *MissingRequiredInputError
				if !errors.As(err, &m) {
					t.Fatalf("expected MissingRequiredInputError, got %T", err)
				}
				if m.Flag != "mykey" {
					t.Fatalf("Flag = %q, want %q", m.Flag, "mykey")
				}
				want := "flag --mykey is required but was not provided"
				if err.Error() != want {
					t.Fatalf("Error() = %q, want %q", err.Error(), want)
				}
			}
			if !tt.wantErr && got != tt.wantVal {
				t.Fatalf("got %q, want %q", got, tt.wantVal)
			}
		})
	}
}

func TestGetBoolArg_NonInteractive(t *testing.T) {
	tests := []struct {
		name     string
		flagVal  bool
		existing *bool
		prio     bool
		want     bool
	}{
		{name: "flag_true", flagVal: true, want: true},
		{name: "flag_false_default", flagVal: false, want: false},
		{name: "existing_prioritized", flagVal: false, existing: boolPtr(true), prio: true, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			restore := setConfigState(false, true)
			defer restore()
			orig := askOne
			t.Cleanup(func() { askOne = orig })
			askOne = func(_ survey.Prompt, _ interface{}, _ ...survey.AskOpt) error {
				t.Fatal("askOne must not be called in non-interactive mode")
				return nil
			}
			cmd := &cobra.Command{}
			cmd.Flags().Bool("mybool", false, "")
			if tt.flagVal {
				_ = cmd.Flags().Set("mybool", "true")
			}
			got, err := GetBoolArg(cmd, "mybool", "Choose", tt.existing, tt.prio)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetSwitchArg_NonInteractive(t *testing.T) {
	tests := []struct {
		name        string
		flagVal     string
		possible    []string
		wantVal     string
		wantErr     bool
		wantMissing bool
	}{
		{name: "valid_flag", flagVal: "b", possible: []string{"a", "b", "c"}, wantVal: "b"},
		{name: "empty_flag_returns_missing", possible: []string{"a", "b"}, wantErr: true, wantMissing: true},
		{name: "invalid_value_not_missing", flagVal: "z", possible: []string{"a", "b"}, wantErr: true, wantMissing: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			restore := setConfigState(false, true)
			defer restore()
			orig := askOne
			t.Cleanup(func() { askOne = orig })
			askOne = func(_ survey.Prompt, _ interface{}, _ ...survey.AskOpt) error {
				t.Fatal("askOne must not be called in non-interactive mode")
				return nil
			}
			cmd := &cobra.Command{}
			cmd.Flags().String("sw", "", "")
			if tt.flagVal != "" {
				_ = cmd.Flags().Set("sw", tt.flagVal)
			}
			got, err := GetSwitchArg(cmd, "sw", "Pick one", tt.possible, "", false)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tt.wantErr)
			}
			if tt.wantMissing && !errors.Is(err, ErrMissingRequiredInput) {
				t.Fatalf("expected ErrMissingRequiredInput, got %v", err)
			}
			if !tt.wantMissing && tt.wantErr && errors.Is(err, ErrMissingRequiredInput) {
				t.Fatalf("expected non-missing error, got ErrMissingRequiredInput")
			}
			if !tt.wantErr && got != tt.wantVal {
				t.Fatalf("got %q, want %q", got, tt.wantVal)
			}
		})
	}
}

func TestGetCheckboxArgs_NonInteractive(t *testing.T) {
	tests := []struct {
		name     string
		vals     []string
		possible []string
		wantOut  []string
		wantErr  bool
	}{
		{name: "valid_values", vals: []string{"a", "b"}, possible: []string{"a", "b", "c"}, wantOut: []string{"a", "b"}},
		{name: "duplicates_removed", vals: []string{"a", "a"}, possible: []string{"a", "b"}, wantOut: []string{"a"}},
		{name: "empty_stripped", vals: []string{"", "b"}, possible: []string{"a", "b"}, wantOut: []string{"b"}},
		{name: "no_values_empty_slice", vals: []string{}, possible: []string{"a", "b"}, wantOut: []string{}},
		{name: "invalid_value_error", vals: []string{"z"}, possible: []string{"a", "b"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			restore := setConfigState(false, true)
			defer restore()
			orig := askOne
			t.Cleanup(func() { askOne = orig })
			askOne = func(_ survey.Prompt, _ interface{}, _ ...survey.AskOpt) error {
				t.Fatal("askOne must not be called in non-interactive mode")
				return nil
			}
			// Build cmd with flags for each val
			cmd := &cobra.Command{}
			keys := []string{}
			for i, v := range tt.vals {
				key := fmt.Sprintf("k%d", i)
				keys = append(keys, key)
				cmd.Flags().String(key, "", "")
				if v != "" {
					_ = cmd.Flags().Set(key, v)
				}
			}
			got, err := GetCheckboxArgs(cmd, keys, "Pick", tt.possible, nil, false)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if len(got) != len(tt.wantOut) {
					t.Fatalf("got %v, want %v", got, tt.wantOut)
				}
				for i := range got {
					if got[i] != tt.wantOut[i] {
						t.Fatalf("got[%d] = %q, want %q", i, got[i], tt.wantOut[i])
					}
				}
			}
		})
	}
}

func TestGetConfirmation_NonInteractive(t *testing.T) {
	t.Run("yes_flag_returns_true_no_prompt", func(t *testing.T) {
		restore := setConfigState(false, true)
		defer restore()
		orig := askOne
		t.Cleanup(func() { askOne = orig })
		askOne = func(_ survey.Prompt, _ interface{}, _ ...survey.AskOpt) error {
			t.Fatal("askOne must not be called when --yes is set")
			return nil
		}
		cmd := &cobra.Command{}
		cmd.Flags().Bool("yes", false, "")
		_ = cmd.Flags().Set("yes", "true")
		ok, err := GetConfirmation(cmd, "yes", "Confirm?")
		if err != nil || !ok {
			t.Fatalf("got ok=%v err=%v, want ok=true err=nil", ok, err)
		}
	})

	t.Run("no_yes_non_interactive_returns_missing_input", func(t *testing.T) {
		restore := setConfigState(false, true)
		defer restore()
		orig := askOne
		t.Cleanup(func() { askOne = orig })
		askOne = func(_ survey.Prompt, _ interface{}, _ ...survey.AskOpt) error {
			t.Fatal("askOne must not be called in non-interactive mode")
			return nil
		}
		cmd := &cobra.Command{}
		cmd.Flags().Bool("yes", false, "")
		ok, err := GetConfirmation(cmd, "yes", "Confirm?")
		if ok {
			t.Fatal("expected ok=false")
		}
		if !errors.Is(err, ErrMissingRequiredInput) {
			t.Fatalf("expected ErrMissingRequiredInput, got %v", err)
		}
		var m *MissingRequiredInputError
		if !errors.As(err, &m) || m.Flag != "yes" {
			t.Fatalf("expected Flag=yes, got %v", m)
		}
	})
}

func boolPtr(b bool) *bool { return &b }
