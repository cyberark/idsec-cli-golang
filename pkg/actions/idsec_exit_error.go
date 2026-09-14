package actions

// ExitCodeError signals that an action has already reported its failure to the
// user (via PrintFailure or equivalent) and only a specific non-zero process
// exit code is still required. main() recognizes it via errors.As and exits
// with Code without printing anything again, so failed actions no longer
// exit 0.
type ExitCodeError struct {
	Code int
}

func (e *ExitCodeError) Error() string { return "" }

// ErrActionFailed is the generic "already reported, just exit non-zero"
// sentinel, used where a single failure exit code (1) is sufficient.
var ErrActionFailed = &ExitCodeError{Code: 1}
