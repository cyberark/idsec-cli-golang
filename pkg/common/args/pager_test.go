package args

import (
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/config"
)

func TestPromptContinue(t *testing.T) {
	tests := []struct {
		name     string
		key      byte
		readErr  error
		expected bool
	}{
		{name: "success_space_advances", key: ' ', expected: true},
		{name: "success_enter_advances", key: '\r', expected: true},
		{name: "success_other_key_advances", key: 'x', expected: true},
		{name: "success_q_quits", key: 'q', expected: false},
		{name: "success_capital_q_quits", key: 'Q', expected: false},
		{name: "success_esc_quits", key: 27, expected: false},
		{name: "success_ctrl_c_quits", key: 3, expected: false},
		{name: "success_ctrl_d_quits", key: 4, expected: false},
		{name: "error_read_failure_quits", readErr: errReadStub, expected: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := readSingleKey
			readSingleKey = func() (byte, error) { return tt.key, tt.readErr }
			defer func() { readSingleKey = original }()

			if got := PromptContinue(); got != tt.expected {
				t.Errorf("PromptContinue() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestShouldPage(t *testing.T) {
	// NOT t.Parallel() — mutates IsStdoutTTY and process-global config state.
	tests := []struct {
		name        string
		pageSize    int
		tty         bool
		interactive bool
		expected    bool
	}{
		{name: "success_pages_on_interactive_tty", pageSize: 2, tty: true, interactive: true, expected: true},
		{name: "success_page_size_zero_never_pages", pageSize: 0, tty: true, interactive: true, expected: false},
		{name: "success_negative_page_size_never_pages", pageSize: -1, tty: true, interactive: true, expected: false},
		{name: "success_non_tty_does_not_page", pageSize: 2, tty: false, interactive: true, expected: false},
		{name: "success_non_interactive_tty_does_not_page", pageSize: 2, tty: true, interactive: false, expected: false},
		{name: "success_non_interactive_non_tty_does_not_page", pageSize: 2, tty: false, interactive: false, expected: false},
		{name: "success_page_size_zero_non_tty_non_interactive", pageSize: 0, tty: false, interactive: false, expected: false},
	}

	origTTY := IsStdoutTTY
	prevInteractive := config.IsInteractive()
	t.Cleanup(func() {
		IsStdoutTTY = origTTY
		if prevInteractive {
			config.EnableInteractive()
		} else {
			config.DisableInteractive()
		}
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			IsStdoutTTY = func() bool { return tt.tty }
			if tt.interactive {
				config.EnableInteractive()
			} else {
				config.DisableInteractive()
			}

			if got := ShouldPage(tt.pageSize); got != tt.expected {
				t.Errorf("ShouldPage(%d) with tty=%v interactive=%v = %v, want %v",
					tt.pageSize, tt.tty, tt.interactive, got, tt.expected)
			}
		})
	}
}

func TestShouldContinueForNextItem(t *testing.T) {
	t.Run("success_non_boundary_does_not_prompt", func(t *testing.T) {
		if !ShouldContinueForNextItem(1, 3) {
			t.Fatal("expected continue on non-boundary item")
		}
	})

	t.Run("success_boundary_prompts_and_respects_quit", func(t *testing.T) {
		original := readSingleKey
		readSingleKey = func() (byte, error) { return 'q', nil }
		defer func() { readSingleKey = original }()

		if ShouldContinueForNextItem(3, 3) {
			t.Fatal("expected stop when prompt receives quit key")
		}
	})

	t.Run("success_disabled_page_size_always_continue", func(t *testing.T) {
		if !ShouldContinueForNextItem(10, 0) {
			t.Fatal("expected continue when page-size is disabled")
		}
	})
}

var errReadStub = stubError("read failed")

type stubError string

func (e stubError) Error() string { return string(e) }

func TestShouldContinueForNextItem_NonInteractive(t *testing.T) {
	// NOT t.Parallel() — mutates process-global config state and readSingleKey.
	config.DisableInteractive()
	defer config.EnableInteractive()

	orig := readSingleKey
	t.Cleanup(func() { readSingleKey = orig })
	readSingleKey = func() (byte, error) {
		t.Fatal("readSingleKey must not be called in non-interactive mode")
		return 0, nil
	}

	if !ShouldContinueForNextItem(3, 3) {
		t.Fatal("expected true at page boundary in non-interactive mode")
	}
}
