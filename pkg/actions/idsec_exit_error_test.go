package actions

import (
	"errors"
	"fmt"
	"testing"

	commonargs "github.com/cyberark/idsec-cli-golang/pkg/common/args"
)

func TestMissingInputFailure_MissingRequiredInputError(t *testing.T) {
	var err error
	stderr := withCapturedStderr(func() {
		err = missingInputFailure("Refusing to delete profile p without confirmation", commonargs.NewMissingRequiredInputError("yes"))
	})

	if !errors.Is(err, ErrActionFailed) {
		t.Fatalf("expected ErrActionFailed, got %v", err)
	}
	want := "Refusing to delete profile p without confirmation: flag --yes is required but was not provided\n" +
		"idsec: missing_required_input flag=--yes\n"
	if stderr != want {
		t.Errorf("stderr = %q, want %q", stderr, want)
	}
}

func TestMissingInputFailure_WrappedMissingRequiredInputError(t *testing.T) {
	wrapped := fmt.Errorf("prompt: %w", commonargs.NewMissingRequiredInputError("yes"))
	var err error
	stderr := withCapturedStderr(func() {
		err = missingInputFailure("Refusing", wrapped)
	})

	if !errors.Is(err, ErrActionFailed) {
		t.Fatalf("expected ErrActionFailed, got %v", err)
	}
	want := "Refusing: prompt: flag --yes is required but was not provided\n" +
		"idsec: missing_required_input flag=--yes\n"
	if stderr != want {
		t.Errorf("stderr = %q, want %q", stderr, want)
	}
}

func TestMissingInputFailure_OtherError(t *testing.T) {
	var err error
	stderr := withCapturedStderr(func() {
		err = missingInputFailure("Refusing to clear all profiles without confirmation", errors.New("prompt failed"))
	})

	if !errors.Is(err, ErrActionFailed) {
		t.Fatalf("expected ErrActionFailed, got %v", err)
	}
	want := "Refusing to clear all profiles without confirmation: prompt failed\n"
	if stderr != want {
		t.Errorf("stderr = %q, want %q", stderr, want)
	}
}

func TestMissingFlagFailure(t *testing.T) {
	var err error
	stderr := withCapturedStderr(func() {
		err = missingFlagFailure("--profile-name is required", "profile-name")
	})

	if !errors.Is(err, ErrActionFailed) {
		t.Fatalf("expected ErrActionFailed, got %v", err)
	}
	want := "--profile-name is required\nidsec: missing_required_input flag=--profile-name\n"
	if stderr != want {
		t.Errorf("stderr = %q, want %q", stderr, want)
	}
}

func TestInteractiveRequiredFailure(t *testing.T) {
	var err error
	stderr := withCapturedStderr(func() {
		err = interactiveRequiredFailure("profiles edit requires an interactive terminal")
	})

	if !errors.Is(err, ErrActionFailed) {
		t.Fatalf("expected ErrActionFailed, got %v", err)
	}
	want := "profiles edit requires an interactive terminal\nidsec: interactive_required\n"
	if stderr != want {
		t.Errorf("stderr = %q, want %q", stderr, want)
	}
}
