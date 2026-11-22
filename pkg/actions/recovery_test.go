package actions

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/cyberark/idsec-cli-golang/pkg/agentmode"
)

func TestExtractErrorMessage(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected string
	}{
		{
			name:     "error_type",
			input:    errors.New("something went wrong"),
			expected: "something went wrong",
		},
		{
			name:     "string_type",
			input:    "plain string panic",
			expected: "plain string panic",
		},
		{
			name:     "integer_type",
			input:    42,
			expected: "42",
		},
		{
			name:     "nil_error",
			input:    error(nil),
			expected: "<nil>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractErrorMessage(tt.input)
			if result != tt.expected {
				t.Errorf("extractErrorMessage() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestCategorizeError(t *testing.T) {
	tests := []struct {
		name             string
		msg              string
		expectedContains string
	}{
		{
			name:             "reflection_panic_reflect_colon",
			msg:              "reflect: call of reflect.Value.Elem on zero Value",
			expectedContains: "internal processing error",
		},
		{
			name:             "reflection_panic_reflect_value",
			msg:              "reflect.Value.Field on zero Value",
			expectedContains: "internal processing error",
		},
		{
			name:             "slice_index_out_of_range",
			msg:              "runtime error: index out of range [0] with length 0",
			expectedContains: "internal data processing error",
		},
		{
			name:             "slice_bounds_out_of_range",
			msg:              "runtime error: slice bounds out of range [-1:]",
			expectedContains: "internal data processing error",
		},
		{
			name:             "interface_conversion_panic",
			msg:              "interface conversion: interface {} is nil, not *auth.IdentitySettings",
			expectedContains: "type mismatch",
		},
		{
			name:             "connection_refused",
			msg:              "dial tcp 127.0.0.1:443: connection refused",
			expectedContains: "connection error",
		},
		{
			name:             "no_such_host",
			msg:              "dial tcp: lookup bad.host: no such host",
			expectedContains: "connection error",
		},
		{
			name:             "authentication_error",
			msg:              "authentication failed: invalid credentials",
			expectedContains: "authentication error",
		},
		{
			name:             "token_expired",
			msg:              "token has expired",
			expectedContains: "authentication error",
		},
		{
			name:             "generic_unknown_error",
			msg:              "some completely unknown error",
			expectedContains: "unexpected error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := categorizeError(tt.msg)
			if !containsCaseInsensitive(result, tt.expectedContains) {
				t.Errorf("categorizeError(%q) = %q, expected it to contain %q", tt.msg, result, tt.expectedContains)
			}
		})
	}
}

func TestRecoverFromPanicCatchesErrorPanic(t *testing.T) {
	recovered := false
	func() {
		defer func() {
			r := recover()
			if r == nil {
				recovered = true
			}
		}()

		defer func() {
			if r := recover(); r != nil {
				recovered = true
				msg := extractErrorMessage(r)
				if msg != "intentional error" {
					t.Errorf("expected 'intentional error', got %q", msg)
				}
				friendly := categorizeError(msg)
				if containsCaseInsensitive(friendly, "") {
					// categorizeError should always return something
				}
			}
		}()

		panic(errors.New("intentional error"))
	}()

	if !recovered {
		t.Error("expected panic to be recovered")
	}
}

func TestRecoverFromPanicCatchesStringPanic(t *testing.T) {
	recovered := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				recovered = true
				msg := extractErrorMessage(r)
				if msg != "string panic" {
					t.Errorf("expected 'string panic', got %q", msg)
				}
			}
		}()

		panic("string panic")
	}()

	if !recovered {
		t.Error("expected panic to be recovered")
	}
}

func TestRecoverFromPanicCatchesRuntimePanic(t *testing.T) {
	recovered := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				recovered = true
				msg := extractErrorMessage(r)
				friendly := categorizeError(msg)
				if !containsCaseInsensitive(friendly, "internal data processing error") {
					t.Errorf("expected slice-related category, got %q for message %q", friendly, msg)
				}
			}
		}()

		s := []int{1, 2, 3}
		_ = s[5] // index out of range
	}()

	if !recovered {
		t.Error("expected runtime panic to be recovered")
	}
}

func containsCaseInsensitive(s, substr string) bool {
	return len(substr) == 0 ||
		len(s) >= len(substr) &&
			containsLower(s, substr)
}

func containsLower(s, substr string) bool {
	sLower := toLower(s)
	subLower := toLower(substr)
	for i := 0; i <= len(sLower)-len(subLower); i++ {
		if sLower[i:i+len(subLower)] == subLower {
			return true
		}
	}
	return false
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := range s {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

func reportPanicCapture(t *testing.T, r any) (stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	reportPanic(r, &out, &errOut)
	return out.String(), errOut.String()
}

func singleEnvelope(t *testing.T, stdout string) agentmode.Envelope {
	t.Helper()
	if strings.Count(stdout, "\n") != 1 || !strings.HasSuffix(stdout, "\n") {
		t.Fatalf("stdout = %q, want exactly one envelope line", stdout)
	}
	var env agentmode.Envelope
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("unmarshal %q: %v", stdout, err)
	}
	if env.Status != agentmode.StatusError || env.Error == nil {
		t.Fatalf("envelope = %+v, want an error envelope", env)
	}
	return env
}

const wantPanicStderr = "[ERROR] An unexpected error occurred: boom\n\nFor detailed error information, run with IDSEC_DEBUG=true\n"

func TestReportPanic_AgentInternalError(t *testing.T) {
	isolateAgentEnvelope(t)
	t.Setenv(idsecDebugEnvVar, "")
	agentmode.Resolve(true, false)

	stdout, stderr := reportPanicCapture(t, errors.New("boom"))

	if stderr != wantPanicStderr {
		t.Errorf("stderr = %q, want %q", stderr, wantPanicStderr)
	}
	env := singleEnvelope(t, stdout)
	if env.Error.Code != agentmode.CodeInternalError || env.Error.Message != "An unexpected error occurred: boom" {
		t.Errorf("error = %q %q", env.Error.Code, env.Error.Message)
	}
	if want := map[string]any{"category": "An unexpected error occurred"}; !reflect.DeepEqual(env.Error.Details, want) {
		t.Errorf("details = %#v, want %#v", env.Error.Details, want)
	}
	if !reflect.DeepEqual(env.Hints, []string{hintInternalError}) {
		t.Errorf("hints = %#v", env.Hints)
	}
}

func TestReportPanic_AgentNonErrorValue(t *testing.T) {
	isolateAgentEnvelope(t)
	t.Setenv(idsecDebugEnvVar, "")
	agentmode.Resolve(true, false)

	stdout, _ := reportPanicCapture(t, "interface conversion: interface {} is nil")

	env := singleEnvelope(t, stdout)
	want := map[string]any{"category": "Internal type mismatch error"}
	if env.Error.Code != agentmode.CodeInternalError || !reflect.DeepEqual(env.Error.Details, want) {
		t.Errorf("error = %q %#v", env.Error.Code, env.Error.Details)
	}
}

func TestReportPanic_AgentClassifiedError(t *testing.T) {
	isolateAgentEnvelope(t)
	t.Setenv(idsecDebugEnvVar, "")
	agentmode.Resolve(true, false)

	opErr := &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}
	panicErr := fmt.Errorf("failed to fetch latest release: %w", &url.Error{Op: "Get", URL: "https://api.example", Err: opErr})
	stdout, stderr := reportPanicCapture(t, panicErr)

	if !strings.HasPrefix(stderr, "[ERROR] Connection error: "+panicErr.Error()+"\n") {
		t.Errorf("stderr = %q", stderr)
	}
	env := singleEnvelope(t, stdout)
	if env.Error.Code != agentmode.CodeEndpointUnreachable || env.Error.Message != panicErr.Error() {
		t.Errorf("error = %q %q", env.Error.Code, env.Error.Message)
	}
}

func TestReportPanic_AgentEnvelopeAlreadyWritten(t *testing.T) {
	isolateAgentEnvelope(t)
	t.Setenv(idsecDebugEnvVar, "")
	agentmode.Resolve(true, false)
	agentmode.ClaimEnvelope()

	stdout, stderr := reportPanicCapture(t, errors.New("boom"))

	if stdout != "" || stderr != wantPanicStderr {
		t.Errorf("stdout = %q, stderr = %q", stdout, stderr)
	}
}

func TestReportPanic_HumanUnchanged(t *testing.T) {
	isolateAgentEnvelope(t)
	t.Setenv(idsecDebugEnvVar, "")

	stdout, stderr := reportPanicCapture(t, errors.New("boom"))

	if stdout != "" {
		t.Errorf("stdout = %q, want empty", stdout)
	}
	if stderr != wantPanicStderr {
		t.Errorf("stderr = %q, want %q", stderr, wantPanicStderr)
	}
}
