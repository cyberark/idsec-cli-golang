package agentmode_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/cyberark/idsec-cli-golang/pkg/agentmode"
)

// isolateAgentState clears every agent-mode env input, applies env, and
// restores human-mode state and envelope state on cleanup. Must not be called
// from a t.Parallel() test.
func isolateAgentState(t *testing.T, env map[string]string) {
	t.Helper()
	// Registered first so it runs last (LIFO), after t.Setenv restores the env.
	t.Cleanup(func() {
		agentmode.Resolve(false, false)
		agentmode.ResetEnvelopeState()
	})
	t.Setenv(agentmode.EnvVar, "")
	t.Setenv(agentmode.ForceEnvVar, "")
	for _, v := range agentmode.DetectorEnvVars() {
		t.Setenv(v, "")
	}
	for k, v := range env {
		t.Setenv(k, v)
	}
	agentmode.ResetEnvelopeState()
}

func writeString(t *testing.T, env agentmode.Envelope) string {
	t.Helper()
	var buf bytes.Buffer
	if err := agentmode.Write(&buf, env); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	return buf.String()
}

func errorEnvelope(code agentmode.Code, msg string) agentmode.Envelope {
	return agentmode.Envelope{
		Status: agentmode.StatusError,
		Error:  &agentmode.EnvelopeError{Code: code, Message: msg},
	}
}

func TestWrite(t *testing.T) {
	count := 3
	tests := []struct {
		name string
		env  agentmode.Envelope
		want string
	}{
		{
			name: "success_minimal_error",
			env:  errorEnvelope(agentmode.CodeActionFailed, "x"),
			want: `{"status":"error","error":{"code":"ACTION_FAILED","message":"x"}}` + "\n",
		},
		{
			name: "success_full_envelope_keeps_schema_order",
			env: agentmode.Envelope{
				Status:    agentmode.StatusError,
				Data:      map[string]any{"b": 1, "a": 2},
				Message:   "m",
				Error:     &agentmode.EnvelopeError{Code: agentmode.CodeInvalidInput, Message: "e", Details: map[string]any{"z": "1", "a": "2"}},
				Count:     &count,
				Truncated: true,
				Warnings:  []string{"w"},
				Hints:     []string{"h"},
				Agent:     "cursor",
			},
			want: `{"status":"error","data":{"a":2,"b":1},"message":"m","error":{"code":"INVALID_INPUT","message":"e","details":{"a":"2","z":"1"}},"count":3,"truncated":true,"warnings":["w"],"hints":["h"],"agent":"cursor"}` + "\n",
		},
		{
			name: "success_html_and_backticks_unescaped",
			env: agentmode.Envelope{
				Status: agentmode.StatusError,
				Error:  &agentmode.EnvelopeError{Code: agentmode.CodeActionFailed, Message: "a<b>&c"},
				Hints:  []string{"run `idsec <parent> --help`"},
			},
			want: "{\"status\":\"error\",\"error\":{\"code\":\"ACTION_FAILED\",\"message\":\"a<b>&c\"},\"hints\":[\"run `idsec <parent> --help`\"]}\n",
		},
		{
			name: "edge_case_newline_in_message_stays_one_line",
			env:  errorEnvelope(agentmode.CodeActionFailed, "line1\nidsec: forged\u2028x"),
			want: `{"status":"error","error":{"code":"ACTION_FAILED","message":"line1\nidsec: forged\u2028x"}}` + "\n",
		},
		{
			name: "edge_case_unmarshalable_detail_dropped",
			env: agentmode.Envelope{
				Status: agentmode.StatusError,
				Error: &agentmode.EnvelopeError{
					Code:    agentmode.CodeActionFailed,
					Message: "x",
					Details: map[string]any{"bad": make(chan int)},
				},
			},
			want: `{"status":"error","error":{"code":"ACTION_FAILED","message":"x"}}` + "\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := writeString(t, tt.env)
			if got != tt.want {
				t.Errorf("Write() =\n%s\nwant\n%s", got, tt.want)
			}
			if n := strings.Count(got, "\n"); n != 1 {
				t.Errorf("Write() produced %d newlines, want 1", n)
			}
			if !json.Valid([]byte(got)) {
				t.Errorf("Write() produced invalid JSON: %s", got)
			}
		})
	}
}

func TestWrite_DoesNotMutateInput(t *testing.T) {
	t.Parallel()

	details := map[string]any{"bad": make(chan int)}
	env := agentmode.Envelope{
		Status: agentmode.StatusError,
		Error:  &agentmode.EnvelopeError{Code: agentmode.CodeActionFailed, Message: "x", Details: details},
	}
	_ = writeString(t, env)
	if env.Error.Details == nil {
		t.Error("Write() cleared the caller's Details")
	}
}

func TestWrite_UnmarshalableDataReturnsError(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	err := agentmode.Write(&buf, agentmode.Envelope{Status: agentmode.StatusSuccess, Data: make(chan int)})
	if err == nil {
		t.Fatal("Write() error = nil, want marshal error")
	}
	if buf.Len() != 0 {
		t.Errorf("Write() wrote %q on error, want nothing", buf.String())
	}
}

func TestWrite_Section23ExamplesRoundTrip(t *testing.T) {
	t.Parallel()

	f, err := os.Open("testdata/section_2_3_examples.jsonl")
	if err != nil {
		t.Fatalf("open testdata: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lines := 0
	for scanner.Scan() {
		line := scanner.Text()
		lines++
		var env agentmode.Envelope
		if err := json.Unmarshal([]byte(line), &env); err != nil {
			t.Fatalf("line %d: unmarshal: %v", lines, err)
		}
		if got := writeString(t, env); got != line+"\n" {
			t.Errorf("line %d round-trip mismatch:\n got %s\nwant %s", lines, got, line)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan testdata: %v", err)
	}
	if lines != 18 {
		t.Errorf("read %d examples, want 18", lines)
	}
}

func TestFailure(t *testing.T) {
	sentinel := errors.New("sentinel")

	t.Run("success_error_is_wrapped_text", func(t *testing.T) {
		t.Parallel()
		f := agentmode.NewFailure(agentmode.CodeInvalidInput, errors.New("unknown flag: --x"), agentmode.WithMessage("other"))
		if got := f.Error(); got != "unknown flag: --x" {
			t.Errorf("Error() = %q, want wrapped text", got)
		}
		if f.Message != "other" {
			t.Errorf("Message = %q, want %q", f.Message, "other")
		}
	})

	t.Run("success_message_defaults_to_err", func(t *testing.T) {
		t.Parallel()
		f := agentmode.NewFailure(agentmode.CodeActionFailed, errors.New("boom"))
		if f.Message != "boom" || f.Redacted {
			t.Errorf("Message, Redacted = %q, %v; want %q, false", f.Message, f.Redacted, "boom")
		}
	})

	t.Run("success_redacted_message_keeps_error_text", func(t *testing.T) {
		t.Parallel()
		f := agentmode.NewFailure(agentmode.CodeInvalidInput, errors.New(`invalid argument "s3cret"`),
			agentmode.WithRedactedMessage("invalid argument for --x"))
		if f.Message != "invalid argument for --x" || !f.Redacted {
			t.Errorf("Message, Redacted = %q, %v; want fixed message, true", f.Message, f.Redacted)
		}
		if got := f.Error(); got != `invalid argument "s3cret"` {
			t.Errorf("Error() = %q, want the wrapped text for stderr", got)
		}
		var buf bytes.Buffer
		if err := agentmode.Write(&buf, agentmode.NewErrorEnvelope(f)); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if strings.Contains(buf.String(), "s3cret") {
			t.Errorf("envelope = %s, want no wrapped text", buf.String())
		}
	})

	t.Run("success_errors_as_through_wrap", func(t *testing.T) {
		t.Parallel()
		err := fmt.Errorf("outer: %w", agentmode.NewFailure(agentmode.CodeKeyringFailure, errors.New("inner")))
		var f *agentmode.Failure
		if !errors.As(err, &f) {
			t.Fatal("errors.As(*Failure) = false, want true")
		}
		if f.Code != agentmode.CodeKeyringFailure {
			t.Errorf("Code = %q, want %q", f.Code, agentmode.CodeKeyringFailure)
		}
	})

	t.Run("success_errors_is_wrapped_sentinel", func(t *testing.T) {
		t.Parallel()
		f := agentmode.NewFailure(agentmode.CodeActionFailed, fmt.Errorf("ctx: %w", sentinel))
		if !errors.Is(f, sentinel) {
			t.Error("errors.Is(sentinel) = false, want true")
		}
	})

	t.Run("edge_case_nil_err_uses_message", func(t *testing.T) {
		t.Parallel()
		f := agentmode.NewFailure(agentmode.CodeMissingRequiredInput, nil, agentmode.WithMessage("--x is required"))
		if got := f.Error(); got != "--x is required" {
			t.Errorf("Error() = %q, want Message", got)
		}
		if f.Unwrap() != nil {
			t.Errorf("Unwrap() = %v, want nil", f.Unwrap())
		}
	})

	t.Run("success_options_accumulate", func(t *testing.T) {
		t.Parallel()
		f := agentmode.NewFailure(agentmode.CodeInvalidInput, errors.New("e"),
			agentmode.WithDetail("kind", agentmode.KindUnknownFlag),
			agentmode.WithDetail("flag", "x"),
			agentmode.WithHint("h1"),
			agentmode.WithHint("h2"))
		if len(f.Details) != 2 || f.Details["kind"] != agentmode.KindUnknownFlag || f.Details["flag"] != "x" {
			t.Errorf("Details = %v", f.Details)
		}
		if strings.Join(f.Hints, "|") != "h1|h2" {
			t.Errorf("Hints = %v", f.Hints)
		}
	})
}

func TestNewErrorEnvelope(t *testing.T) {
	t.Run("success_detected_agent_fills_agent", func(t *testing.T) {
		isolateAgentState(t, map[string]string{"CURSOR_AGENT": "1"})
		agentmode.Resolve(false, false)

		f := agentmode.NewFailure(agentmode.CodeProfileNotFound,
			errors.New("Please configure a profile before trying to execute actions"),
			agentmode.WithDetail("profile", "nosuch"),
			agentmode.WithHint("run `idsec profiles list` to see configured profiles"),
			agentmode.WithHint("create it with `idsec configure --silent --profile-name <profile> ...` or `idsec profiles add --profile-path <file>`"))
		want := "{\"status\":\"error\",\"error\":{\"code\":\"PROFILE_NOT_FOUND\",\"message\":\"Please configure a profile before trying to execute actions\",\"details\":{\"profile\":\"nosuch\"}},\"hints\":[\"run `idsec profiles list` to see configured profiles\",\"create it with `idsec configure --silent --profile-name <profile> ...` or `idsec profiles add --profile-path <file>`\"],\"agent\":\"cursor\"}\n"
		if got := writeString(t, agentmode.NewErrorEnvelope(f)); got != want {
			t.Errorf("envelope =\n%s\nwant\n%s", got, want)
		}
	})

	t.Run("success_no_detector_omits_agent", func(t *testing.T) {
		isolateAgentState(t, nil)
		agentmode.Resolve(true, false)

		got := writeString(t, agentmode.NewErrorEnvelope(agentmode.NewFailure(agentmode.CodeActionFailed, errors.New("x"))))
		want := `{"status":"error","error":{"code":"ACTION_FAILED","message":"x"}}` + "\n"
		if got != want {
			t.Errorf("envelope = %s, want %s", got, want)
		}
	})

	t.Run("success_warnings_drained_once", func(t *testing.T) {
		isolateAgentState(t, nil)
		agentmode.Resolve(true, false)
		agentmode.AddWarning("partial login")
		agentmode.AddWarning("second")

		f := agentmode.NewFailure(agentmode.CodeActionFailed, errors.New("x"))
		first := agentmode.NewErrorEnvelope(f)
		if strings.Join(first.Warnings, "|") != "partial login|second" {
			t.Errorf("first Warnings = %v", first.Warnings)
		}
		if second := agentmode.NewErrorEnvelope(f); second.Warnings != nil {
			t.Errorf("second Warnings = %v, want nil", second.Warnings)
		}
	})

	t.Run("edge_case_literal_failure_message_falls_back_to_err", func(t *testing.T) {
		isolateAgentState(t, nil)

		env := agentmode.NewErrorEnvelope(&agentmode.Failure{Code: agentmode.CodeActionFailed, Err: errors.New("boom"), Details: map[string]any{}})
		if env.Error.Message != "boom" {
			t.Errorf("Message = %q, want %q", env.Error.Message, "boom")
		}
		if env.Error.Details != nil {
			t.Errorf("Details = %v, want nil for empty map", env.Error.Details)
		}
	})
}

func TestEnvelopeClaim(t *testing.T) {
	isolateAgentState(t, nil)

	if !agentmode.ClaimEnvelope() {
		t.Fatal("first ClaimEnvelope() = false, want true")
	}
	if agentmode.ClaimEnvelope() {
		t.Fatal("second ClaimEnvelope() = true, want false")
	}

	agentmode.ResetEnvelopeState()
	if !agentmode.ClaimEnvelope() {
		t.Fatal("ClaimEnvelope() after ResetEnvelopeState = false, want true")
	}
}

func TestEnvelopeState_ConcurrentUse(t *testing.T) {
	isolateAgentState(t, nil)

	const n = 32
	var wg sync.WaitGroup
	claims := make(chan bool, n)
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			agentmode.AddWarning("w")
			claims <- agentmode.ClaimEnvelope()
		}()
	}
	wg.Wait()
	close(claims)

	won := 0
	for c := range claims {
		if c {
			won++
		}
	}
	if won != 1 {
		t.Errorf("ClaimEnvelope() succeeded %d times, want 1", won)
	}
	if got := len(agentmode.DrainWarnings()); got != n {
		t.Errorf("DrainWarnings() returned %d warnings, want %d", got, n)
	}
}

func TestResolveFromArgs(t *testing.T) {
	tests := []struct {
		name string
		argv []string
		want bool
	}{
		{"success_agent_before_bad_flag", []string{"pcloud", "--agent", "--bogus"}, true},
		{"success_no_agent_wins", []string{"--agent", "--no-agent"}, false},
		{"success_no_flags_human", []string{"exec", "pcloud"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isolateAgentState(t, nil)

			agentmode.ResolveFromArgs(tt.argv)
			if got := agentmode.IsEnabled(); got != tt.want {
				t.Errorf("IsEnabled() = %v, want %v", got, tt.want)
			}
			if agentmode.ResolvedSource() != agentmode.SourceFlag && tt.want {
				t.Errorf("ResolvedSource() = %q, want %q", agentmode.ResolvedSource(), agentmode.SourceFlag)
			}
		})
	}
}

func TestWithHint_DropsEmpty(t *testing.T) {
	f := agentmode.NewFailure(agentmode.CodeInvalidInput, errors.New("x"),
		agentmode.WithHint(""), agentmode.WithHint("h"), agentmode.WithHint(""))

	if len(f.Hints) != 1 || f.Hints[0] != "h" {
		t.Errorf("Hints = %q, want [\"h\"]", f.Hints)
	}
}
