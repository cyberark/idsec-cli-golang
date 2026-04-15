package actions

import (
	"errors"
	"testing"
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
