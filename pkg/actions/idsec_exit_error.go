package actions

import (
	"errors"
	"fmt"
	"os"

	"github.com/cyberark/idsec-cli-golang/pkg/agentmode"
	commonargs "github.com/cyberark/idsec-cli-golang/pkg/common/args"
)

// ExitCodeError signals that an action has already reported its failure to the
// user (via PrintFailure or equivalent) and only a specific non-zero process
// exit code is still required. main() recognizes it via errors.As and exits
// with Code without printing anything again, so failed actions no longer
// exit 0.
type ExitCodeError struct {
	Code int
	// Failure carries the agent-mode code; it is consumed only in agent mode.
	Failure *agentmode.Failure
	// Quiet marks a state result reported only through the exit code, in agent
	// mode too: no envelope is written.
	Quiet bool
}

func (e *ExitCodeError) Error() string { return "" }

// Unwrap exposes Failure so errors.As finds it through the exit error.
func (e *ExitCodeError) Unwrap() error {
	if e.Failure == nil {
		return nil
	}
	return e.Failure
}

// Is matches any *ExitCodeError with the same Code, so errors.Is(err,
// ErrActionFailed) holds for every exit-1 failure.
func (e *ExitCodeError) Is(target error) bool {
	t, ok := target.(*ExitCodeError)
	return ok && t.Code == e.Code
}

// ErrActionFailed is the generic "already reported, just exit non-zero"
// sentinel, used where a single failure exit code (1) is sufficient.
var ErrActionFailed = &ExitCodeError{Code: 1}

// failed returns an already-reported exit-1 error carrying an agent-mode code.
// It prints nothing. msg is the human text the caller printed. Details and
// hints of a Failure wrapped by cause are kept, and so is its message when it
// is redacted, since msg usually embeds cause's text; opts are applied after them.
func failed(code agentmode.Code, msg string, cause error, opts ...agentmode.FailureOption) error {
	f := agentmode.NewFailure(code, cause, agentmode.WithMessage(msg))
	var inner *agentmode.Failure
	if errors.As(cause, &inner) {
		if inner.Redacted {
			agentmode.WithRedactedMessage(inner.Message)(f)
		}
		for k, v := range inner.Details {
			agentmode.WithDetail(k, v)(f)
		}
		f.Hints = append(f.Hints, inner.Hints...)
	}
	for _, opt := range opts {
		opt(f)
	}
	return &ExitCodeError{Code: 1, Failure: f}
}

// reportFailure prints msg via PrintFailure and returns failed(...).
func reportFailure(code agentmode.Code, msg string, cause error, opts ...agentmode.FailureOption) error {
	commonargs.PrintFailure(msg)
	return failed(code, msg, cause, opts...)
}

// quietExit is a state result reported only through the exit code (status --quiet).
func quietExit(code int) error { return &ExitCodeError{Code: code, Quiet: true} }

// machineLinePrefix starts every stable, machine-readable stderr line. Agents
// match on these lines instead of parsing the human failure message.
const machineLinePrefix = "idsec: "

// Machine-line events. Each upper-cased is its agentmode.Code.
const (
	eventMissingRequiredInput = "missing_required_input"
	eventInteractiveRequired  = "interactive_required"
)

// emitMachineLine writes a machine-readable line to stderr. body must not
// contain user-controlled text, or a newline in it could forge another line.
func emitMachineLine(body string) {
	fmt.Fprintln(os.Stderr, machineLinePrefix+body)
}

// missingFlagOptions records flags in details.missing_flags with one hint per
// flag. flags must be CLI flag names, never user input.
func missingFlagOptions(flags ...string) []agentmode.FailureOption {
	opts := []agentmode.FailureOption{agentmode.WithDetail("missing_flags", flags)}
	for _, flag := range flags {
		opts = append(opts, agentmode.WithHint(passFlagHint(flag)))
	}
	return opts
}

// missingInputFailure reports a refused confirmation. It prints
// "<human>: <err>" and, if err is a MissingRequiredInputError, the
// missing_required_input line, then returns an exit-1 error.
func missingInputFailure(human string, err error) error {
	msg := fmt.Sprintf("%s: %s", human, err.Error())
	var m *commonargs.MissingRequiredInputError
	if !errors.As(err, &m) {
		return reportFailure(agentmode.CodeActionFailed, msg, err)
	}
	failure := reportFailure(agentmode.CodeMissingRequiredInput, msg, err, missingFlagOptions(m.Flag)...)
	emitMachineLine(eventMissingRequiredInput + " flag=--" + m.Flag)
	return failure
}

// missingFlagFailure reports a required flag that wasn't given and returns an
// exit-1 error.
func missingFlagFailure(human, flag string) error {
	failure := reportFailure(agentmode.CodeMissingRequiredInput, human, nil, missingFlagOptions(flag)...)
	emitMachineLine(eventMissingRequiredInput + " flag=--" + flag)
	return failure
}

// interactiveRequiredFailure reports a command that can't run without a
// terminal and returns an exit-1 error. opts add details and hints.
func interactiveRequiredFailure(human string, opts ...agentmode.FailureOption) error {
	failure := reportFailure(agentmode.CodeInteractiveRequired, human, nil, opts...)
	emitMachineLine(eventInteractiveRequired)
	return failure
}
