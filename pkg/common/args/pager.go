package args

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/mattn/go-isatty"
	"golang.org/x/term"
)

// IsStdoutTTY reports whether stdout is connected to an interactive terminal.
// It is a var so tests can override it.
var IsStdoutTTY = func() bool {
	return isatty.IsTerminal(os.Stdout.Fd()) || isatty.IsCygwinTerminal(os.Stdout.Fd())
}

// PromptContinue waits for a single keypress from the controlling terminal and
// returns false when the user asks to stop (q, Q, Esc, Ctrl-C, Ctrl-D). It
// returns true otherwise, so callers advance to the next page on space, enter,
// or any other key.
func PromptContinue() bool {
	key, err := readSingleKey()
	if err != nil {
		return false
	}
	switch key {
	case 'q', 'Q', 27 /* Esc */, 3 /* Ctrl-C */, 4 /* Ctrl-D */ :
		return false
	default:
		return true
	}
}

// ShouldContinueForNextItem applies generic page-boundary logic for interactive
// paging. It returns true when rendering should continue and false when the user
// asked to stop.
//
// Parameters:
//   - renderedCount: number of items already rendered
//   - pageSize: items per page
//
// Behavior:
//   - If pageSize <= 0, always continue
//   - If renderedCount is not on a page boundary, continue
//   - At each boundary (renderedCount % pageSize == 0), prompt for continuation
func ShouldContinueForNextItem(renderedCount, pageSize int) bool {
	if pageSize <= 0 || renderedCount == 0 || renderedCount%pageSize != 0 {
		return true
	}
	return PromptContinue()
}

// openControllingTTY returns a handle to the terminal for reading keypresses,
// independent of stdin (which may be a pipe or redirected file). It tries the
// Unix terminal device first, then the Windows console input device, and only
// falls back to stdin when neither can be opened.
func openControllingTTY() *os.File {
	if f, err := os.Open("/dev/tty"); err == nil {
		return f
	}
	if f, err := os.Open(`\\.\CONIN$`); err == nil {
		return f
	}
	return os.Stdin
}

// readSingleKey reads one byte from the controlling terminal in raw mode so a
// single keypress is returned without waiting for Enter. It is a var so tests
// can stub keypresses.
//
// The terminal is restored even if the process is terminated by a signal while
// blocked on the read: Go does not run deferred functions for unhandled
// signals, so a SIGINT/SIGTERM handler restores the terminal before exiting.
// Without this, an external kill would leave the user's shell stuck in raw mode.
var readSingleKey = func() (byte, error) {
	tty := openControllingTTY()
	if tty != os.Stdin {
		defer func() { _ = tty.Close() }()
	}

	fd := int(tty.Fd())
	if term.IsTerminal(fd) {
		oldState, rawErr := term.MakeRaw(fd)
		if rawErr != nil {
			fmt.Fprintln(os.Stderr, "paging: unable to enter raw mode; press a key then Enter to continue")
		} else {
			restore := func() { _ = term.Restore(fd, oldState) }
			defer restore()

			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
			defer func() {
				signal.Stop(sigCh)
				close(sigCh)
			}()
			go func() {
				if _, ok := <-sigCh; ok {
					restore()
					os.Exit(130)
				}
			}()
		}
	}

	var b [1]byte
	if _, readErr := tty.Read(b[:]); readErr != nil {
		return 0, readErr
	}
	return b[0], nil
}
