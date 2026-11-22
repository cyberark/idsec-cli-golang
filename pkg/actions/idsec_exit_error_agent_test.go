package actions

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/cyberark/idsec-cli-golang/pkg/agentmode"
	commonargs "github.com/cyberark/idsec-cli-golang/pkg/common/args"
)

func failureOf(t *testing.T, err error) *agentmode.Failure {
	t.Helper()
	var exitErr *ExitCodeError
	if !errors.As(err, &exitErr) {
		t.Fatalf("errors.As(*ExitCodeError) = false for %v", err)
	}
	var f *agentmode.Failure
	if !errors.As(err, &f) {
		t.Fatalf("errors.As(*agentmode.Failure) = false for %#v", err)
	}
	if exitErr.Failure != f {
		t.Fatal("Failure found by errors.As is not ExitCodeError.Failure")
	}
	return f
}

func TestExitHelpers_CarryFailure(t *testing.T) {
	otherErr := errors.New("prompt failed")
	tests := []struct {
		name         string
		call         func() error
		wantStderr   string
		wantCode     agentmode.Code
		wantMessage  string
		wantDetails  map[string]any
		wantHints    []string
		wantWrapping error
	}{
		{
			name: "success_missing_input_missing_required_input_error",
			call: func() error {
				return missingInputFailure("Refusing to delete profile p without confirmation", commonargs.NewMissingRequiredInputError("yes"))
			},
			wantStderr: "Refusing to delete profile p without confirmation: flag --yes is required but was not provided\n" +
				"idsec: missing_required_input flag=--yes\n",
			wantCode:     agentmode.CodeMissingRequiredInput,
			wantMessage:  "Refusing to delete profile p without confirmation: flag --yes is required but was not provided",
			wantDetails:  map[string]any{"missing_flags": []string{"yes"}},
			wantHints:    []string{"agent mode never prompts; pass --yes"},
			wantWrapping: commonargs.ErrMissingRequiredInput,
		},
		{
			name: "success_missing_input_other_error",
			call: func() error {
				return missingInputFailure("Refusing to clear all profiles without confirmation", otherErr)
			},
			wantStderr:   "Refusing to clear all profiles without confirmation: prompt failed\n",
			wantCode:     agentmode.CodeActionFailed,
			wantMessage:  "Refusing to clear all profiles without confirmation: prompt failed",
			wantWrapping: otherErr,
		},
		{
			name:        "success_missing_flag",
			call:        func() error { return missingFlagFailure("--profile-path is required", "profile-path") },
			wantStderr:  "--profile-path is required\nidsec: missing_required_input flag=--profile-path\n",
			wantCode:    agentmode.CodeMissingRequiredInput,
			wantMessage: "--profile-path is required",
			wantDetails: map[string]any{"missing_flags": []string{"profile-path"}},
			wantHints:   []string{"agent mode never prompts; pass --profile-path"},
		},
		{
			name:        "success_interactive_required",
			call:        func() error { return interactiveRequiredFailure("profiles edit requires an interactive terminal") },
			wantStderr:  "profiles edit requires an interactive terminal\nidsec: interactive_required\n",
			wantCode:    agentmode.CodeInteractiveRequired,
			wantMessage: "profiles edit requires an interactive terminal",
		},
		{
			name: "success_interactive_required_with_options",
			call: func() error {
				return interactiveRequiredFailure("profiles edit requires an interactive terminal",
					agentmode.WithDetail("command", "idsec profiles edit"),
					agentmode.WithHint("h"))
			},
			wantStderr:  "profiles edit requires an interactive terminal\nidsec: interactive_required\n",
			wantCode:    agentmode.CodeInteractiveRequired,
			wantMessage: "profiles edit requires an interactive terminal",
			wantDetails: map[string]any{"command": "idsec profiles edit"},
			wantHints:   []string{"h"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			stderr := withCapturedStderr(func() { err = tt.call() })

			if stderr != tt.wantStderr {
				t.Errorf("stderr = %q, want %q", stderr, tt.wantStderr)
			}
			if !errors.Is(err, ErrActionFailed) {
				t.Errorf("errors.Is(err, ErrActionFailed) = false")
			}
			if tt.wantWrapping != nil && !errors.Is(err, tt.wantWrapping) {
				t.Errorf("errors.Is(err, %v) = false", tt.wantWrapping)
			}
			f := failureOf(t, err)
			if f.Code != tt.wantCode {
				t.Errorf("Code = %q, want %q", f.Code, tt.wantCode)
			}
			if f.Message != tt.wantMessage {
				t.Errorf("Message = %q, want %q", f.Message, tt.wantMessage)
			}
			if len(f.Details) != len(tt.wantDetails) || (len(tt.wantDetails) > 0 && !reflect.DeepEqual(f.Details, tt.wantDetails)) {
				t.Errorf("Details = %#v, want %#v", f.Details, tt.wantDetails)
			}
			if !reflect.DeepEqual(f.Hints, tt.wantHints) {
				t.Errorf("Hints = %#v, want %#v", f.Hints, tt.wantHints)
			}
		})
	}
}

func TestExitCodeError_Semantics(t *testing.T) {
	t.Run("success_code_4_is_not_action_failed", func(t *testing.T) {
		if errors.Is(&ExitCodeError{Code: 4}, ErrActionFailed) {
			t.Error("errors.Is(ExitCodeError{4}, ErrActionFailed) = true, want false")
		}
	})
	t.Run("success_any_exit_1_is_action_failed", func(t *testing.T) {
		if !errors.Is(&ExitCodeError{Code: 1, Failure: agentmode.NewFailure(agentmode.CodeActionFailed, nil)}, ErrActionFailed) {
			t.Error("errors.Is(ExitCodeError{1}, ErrActionFailed) = false, want true")
		}
	})
	t.Run("success_same_code_matches", func(t *testing.T) {
		if !errors.Is(&ExitCodeError{Code: 4}, &ExitCodeError{Code: 4}) {
			t.Error("errors.Is(ExitCodeError{4}, ExitCodeError{4}) = false, want true")
		}
	})
	t.Run("success_other_target_type_does_not_match", func(t *testing.T) {
		if (&ExitCodeError{Code: 1}).Is(errors.New("")) {
			t.Error("Is(non-ExitCodeError) = true, want false")
		}
	})
	t.Run("success_error_text_stays_empty", func(t *testing.T) {
		err := &ExitCodeError{Code: 1, Failure: agentmode.NewFailure(agentmode.CodeActionFailed, errors.New("boom"))}
		if err.Error() != "" {
			t.Errorf("Error() = %q, want empty", err.Error())
		}
	})
	t.Run("edge_case_unwrap_without_failure_is_nil", func(t *testing.T) {
		if got := (&ExitCodeError{Code: 1}).Unwrap(); got != nil {
			t.Errorf("Unwrap() = %#v, want untyped nil", got)
		}
	})
}

func TestReportFailure(t *testing.T) {
	cause := errors.New("cause")
	var err error
	var stderr string
	stdout := withCapturedOutput(func() {
		stderr = withCapturedStderr(func() {
			err = reportFailure(agentmode.CodeConfigError, "Failed to load profile \"dev\"", cause, agentmode.WithDetail("profile", "dev"))
		})
	})

	if stderr != "Failed to load profile \"dev\"\n" {
		t.Errorf("stderr = %q", stderr)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty", stdout)
	}
	f := failureOf(t, err)
	if f.Code != agentmode.CodeConfigError || f.Message != "Failed to load profile \"dev\"" || f.Details["profile"] != "dev" {
		t.Errorf("Failure = %#v", f)
	}
	if !errors.Is(err, cause) {
		t.Error("errors.Is(err, cause) = false")
	}
}

func TestFailed_MergesWrappedFailure(t *testing.T) {
	inner := agentmode.NewFailure(agentmode.CodeInvalidInput, errors.New("invalid jq query"),
		agentmode.WithDetail("kind", agentmode.KindInvalidQuery),
		agentmode.WithDetail("command", "inner"),
		agentmode.WithHint("inner hint"))
	var err error
	stderr := withCapturedStderr(func() {
		err = failed(classifiedOr(inner, agentmode.CodeActionFailed), "Failed to execute action: invalid jq query", inner,
			agentmode.WithDetail("command", "idsec exec pcloud accounts list"))
	})

	if stderr != "" {
		t.Errorf("failed() printed %q, want nothing", stderr)
	}
	f := failureOf(t, err)
	want := map[string]any{"kind": agentmode.KindInvalidQuery, "command": "idsec exec pcloud accounts list"}
	if f.Code != agentmode.CodeInvalidInput || !reflect.DeepEqual(f.Details, want) {
		t.Errorf("Failure code/details = %q %#v", f.Code, f.Details)
	}
	if !reflect.DeepEqual(f.Hints, []string{"inner hint"}) {
		t.Errorf("Hints = %#v", f.Hints)
	}
	if inner.Details["command"] != "inner" {
		t.Error("failed() mutated the wrapped Failure")
	}
}

func TestQuietExit(t *testing.T) {
	err := quietExit(4)
	var exitErr *ExitCodeError
	if !errors.As(err, &exitErr) {
		t.Fatalf("quietExit(4) = %#v, want *ExitCodeError", err)
	}
	if exitErr.Code != 4 || !exitErr.Quiet || exitErr.Failure != nil {
		t.Errorf("quietExit(4) = %#v", exitErr)
	}
	if errors.Is(err, ErrActionFailed) {
		t.Error("errors.Is(quietExit(4), ErrActionFailed) = true, want false")
	}
}

// The stderr event and the envelope code are the same identifier in two casings.
func TestMachineLineEventsMatchCodes(t *testing.T) {
	if strings.ToUpper(eventMissingRequiredInput) != string(agentmode.CodeMissingRequiredInput) {
		t.Errorf("event %q != code %q", eventMissingRequiredInput, agentmode.CodeMissingRequiredInput)
	}
	if strings.ToUpper(eventInteractiveRequired) != string(agentmode.CodeInteractiveRequired) {
		t.Errorf("event %q != code %q", eventInteractiveRequired, agentmode.CodeInteractiveRequired)
	}

	helpers := map[string]func() error{
		"missingInputFailure":        func() error { return missingInputFailure("h", commonargs.NewMissingRequiredInputError("yes")) },
		"missingFlagFailure":         func() error { return missingFlagFailure("h", "profile-name") },
		"interactiveRequiredFailure": func() error { return interactiveRequiredFailure("h") },
	}
	for name, call := range helpers {
		t.Run(name, func(t *testing.T) {
			var err error
			stderr := withCapturedStderr(func() { err = call() })

			var event string
			for _, line := range strings.Split(stderr, "\n") {
				if rest, ok := strings.CutPrefix(line, machineLinePrefix); ok {
					event, _, _ = strings.Cut(rest, " ")
				}
			}
			if event == "" {
				t.Fatalf("no %q line in stderr %q", machineLinePrefix, stderr)
			}
			if got := failureOf(t, err).Code; strings.ToUpper(event) != string(got) {
				t.Errorf("event %q upper-cased != code %q", event, got)
			}
		})
	}
}
