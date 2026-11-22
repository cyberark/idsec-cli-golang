package args

import (
	"errors"
	"strings"
	"testing"

	"github.com/fatih/color"
	"github.com/cyberark/idsec-sdk-golang/pkg/config"
)

func TestPrintFailure_ObserverGetsPlainText(t *testing.T) {
	// Not using t.Parallel() – mutates the process-global observer and color state.
	t.Setenv("NO_COLOR", "")
	origNoColor, origIsStderrTTY, wasColoring := color.NoColor, IsStderrTTY, config.IsColoring()
	t.Cleanup(func() {
		color.NoColor, IsStderrTTY = origNoColor, origIsStderrTTY
		if wasColoring {
			config.EnableColor()
		} else {
			config.DisableColor()
		}
		SetFailureObserver(nil)
	})
	color.NoColor = false
	IsStderrTTY = func() bool { return true }
	config.EnableColor()

	var got []string
	SetFailureObserver(func(msg string) { got = append(got, msg) })

	stderr := captureFormatterStderr(func() {
		PrintFailure("Failed to clear profiles: x")
		PrintFailure(errors.New("boom"))
	})

	if !strings.Contains(stderr, "\x1b[") {
		t.Fatalf("stderr = %q, want ANSI-colored output", stderr)
	}
	want := []string{"Failed to clear profiles: x", "boom"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("observer got %q, want %q", got, want)
	}
}

func TestPrintFailure_NilObserverIsNoOp(t *testing.T) {
	// Not using t.Parallel() – mutates the process-global observer.
	t.Cleanup(func() { SetFailureObserver(nil) })
	called := false
	SetFailureObserver(func(string) { called = true })
	SetFailureObserver(nil)
	wasColoring := config.IsColoring()
	config.DisableColor()
	t.Cleanup(func() {
		if wasColoring {
			config.EnableColor()
		}
	})

	stderr := captureFormatterStderr(func() { PrintFailure("x") })

	if stderr != "x\n" {
		t.Errorf("stderr = %q, want %q", stderr, "x\n")
	}
	if called {
		t.Error("removed observer was called")
	}
}
