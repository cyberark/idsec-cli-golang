package args

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/fatih/color"
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
