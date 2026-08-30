package actions

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/mattn/go-isatty"
)

// eraseSpinnerLine overwrites the current terminal line so spinner text is
// fully cleared before any other output lands on stderr.
const eraseSpinnerLine = "\r\033[2K"

var (
	progressMu     sync.Mutex
	activeProgress *kubectlLoginProgress
)

func getActiveProgress() *kubectlLoginProgress {
	progressMu.Lock()
	defer progressMu.Unlock()
	return activeProgress
}

func setActiveProgress(p *kubectlLoginProgress) {
	progressMu.Lock()
	activeProgress = p
	progressMu.Unlock()
}

// kubectlLoginProgress renders a single-line braille spinner on stderr so the
// user sees live phase updates during the kubectl-login cold path. Stdout is
// never touched (kubectl reads it as ExecCredential JSON). A nil receiver is
// a valid no-op so callers don't need nil checks.
type kubectlLoginProgress struct {
	mu            sync.Mutex
	msg           string
	frame         int
	active        bool
	lineVisible   bool          // true only while a spinner frame is drawn on screen
	renderNow     chan struct{} // buffered(1): signals animate() to render immediately on update()
	stopCh        chan struct{}
	doneCh        chan struct{}
	coloredFrames []string
}

// newKubectlLoginProgress returns a live spinner when stderr is a TTY and
// IDSEC_VERBOSE is off. Returns nil otherwise (all methods are nil-safe no-ops).
func newKubectlLoginProgress() *kubectlLoginProgress {
	stderrIsTTY := isatty.IsTerminal(os.Stderr.Fd()) || isatty.IsCygwinTerminal(os.Stderr.Fd())
	if !stderrIsTTY || kubectlLoginDiagnosticsEnabled() {
		return nil
	}
	frames := []rune{'⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'}
	cyan := color.New(color.FgCyan)
	coloredFrames := make([]string, len(frames))
	for i, f := range frames {
		coloredFrames[i] = cyan.Sprint(string(f))
	}
	p := &kubectlLoginProgress{
		renderNow:     make(chan struct{}, 1),
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
		coloredFrames: coloredFrames,
		active:        true, // goroutine is running from construction; msg="" keeps it silent until update()
	}
	go p.animate()
	setActiveProgress(p)
	return p
}

// update sets the status message shown beside the spinner.
func (p *kubectlLoginProgress) update(msg string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.msg = msg
	p.active = true
	p.mu.Unlock()
	// non-blocking: wake animate() immediately so the new message appears without
	// waiting for the next 100ms tick. Dropped if a signal is already pending.
	select {
	case p.renderNow <- struct{}{}:
	default:
	}
}

// done stops the spinner goroutine and clears the status line from stderr.
// It blocks until the animate goroutine has finished writing its final clear
// escape sequence, guaranteeing no residual characters on the terminal.
func (p *kubectlLoginProgress) done() {
	if p == nil {
		return
	}
	p.mu.Lock()
	alreadyStopped := !p.active
	p.active = false
	p.mu.Unlock()
	if alreadyStopped {
		return
	}
	close(p.stopCh)
	<-p.doneCh
	setActiveProgress(nil)
}

func (p *kubectlLoginProgress) animate() {
	defer close(p.doneCh)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-p.stopCh:
			p.mu.Lock()
			visible := p.lineVisible
			p.mu.Unlock()
			if visible {
				fmt.Fprint(os.Stderr, eraseSpinnerLine)
			}
			return
		case <-p.renderNow:
			p.mu.Lock()
			if p.active && p.msg != "" {
				char := p.coloredFrames[p.frame%len(p.coloredFrames)]
				fmt.Fprintf(os.Stderr, "%s%s %s", eraseSpinnerLine, char, p.msg)
				p.frame++
				p.lineVisible = true
			}
			p.mu.Unlock()
		case <-ticker.C:
			p.mu.Lock()
			if p.active && p.msg != "" {
				char := p.coloredFrames[p.frame%len(p.coloredFrames)]
				fmt.Fprintf(os.Stderr, "%s%s %s", eraseSpinnerLine, char, p.msg)
				p.frame++
				p.lineVisible = true
			}
			p.mu.Unlock()
		}
	}
}
