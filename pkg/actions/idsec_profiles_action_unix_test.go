//go:build !windows

package actions

import (
	"errors"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cyberark/idsec-cli-golang/pkg/actions/testutils"
	"github.com/cyberark/idsec-sdk-golang/pkg/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/profiles"
)

// A FIFO (or a symlink to one) would block os.ReadFile forever in a
// non-interactive run; it must be rejected before any read.
func TestRunAddAction_NotRegularFile_FIFO(t *testing.T) {
	setInteractiveForTest(t)

	fifo := filepath.Join(t.TempDir(), "profile.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo not supported here: %v", err)
	}

	saved := false
	mock := testutils.NewMockProfileLoader()
	mock.SaveProfileFunc = func(*models.IdsecProfile) error { saved = true; return nil }
	loader := profiles.ProfileLoader(mock)
	action := NewIdsecProfilesAction(&loader)

	// The select runs inside CaptureStreams so the real streams are restored
	// (and t.Fatal is visible) even if the action never returns.
	var err error
	timedOut := false
	_, stderr := testutils.CaptureStreams(func() {
		done := make(chan error, 1)
		go func() { done <- action.runAddAction(newAddCmd(fifo, false), []string{}) }()
		select {
		case err = <-done:
		case <-time.After(5 * time.Second):
			timedOut = true
		}
	})
	if timedOut {
		t.Fatal("guard regressed: ReadFile blocked on FIFO")
	}
	if !errors.Is(err, ErrActionFailed) {
		t.Fatalf("expected ErrActionFailed for a FIFO path, got %v", err)
	}
	if saved {
		t.Fatal("SaveProfile must not be called for a FIFO path")
	}
	if !strings.Contains(stderr, "is not a regular file, aborting") {
		t.Errorf("expected 'is not a regular file' failure on stderr, got %q", stderr)
	}
}
