// Package actions provides base functionality for Idsec SDK command line actions.
//
// This file contains panic recovery logic for the CLI. RecoverFromPanic is
// intended to be deferred at the top of main() so that any unhandled panic
// (intentional panic(err) calls, reflection errors, slice-bounds errors, etc.)
// is caught and presented to the user as a friendly message instead of a raw
// goroutine stack trace.
//
// Set IDSEC_DEBUG=true to include the full stack trace in the output.
package actions

import (
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"

	"github.com/cyberark/idsec-cli-golang/pkg/agentmode"
	authcommon "github.com/cyberark/idsec-sdk-golang/pkg/auth/common"
)

const (
	idsecDebugEnvVar = "IDSEC_DEBUG"
)

// RecoverFromPanic catches any panic in the current goroutine and prints a
// user-friendly error message. When IDSEC_DEBUG=true, the full stack trace is
// printed to stderr. The function calls os.Exit(1) after handling the panic.
//
// Usage — add as the first deferred call in main():
//
//	func main() {
//	    defer actions.RecoverFromPanic()
//	    // ...
//	}
func RecoverFromPanic() {
	r := recover()
	if r == nil {
		return
	}

	reportPanic(r, os.Stdout, os.Stderr)
	os.Exit(1)
}

// reportPanic writes the panic report to stderr and, in agent mode, one error
// envelope to stdout.
func reportPanic(r any, stdout, stderr io.Writer) {
	errMsg := extractErrorMessage(r)
	friendlyMsg := categorizeError(errMsg)

	// Write directly to stderr — never gated by --silent or --raw flags,
	// because if the CLI panicked the user must always see the error.
	_, _ = fmt.Fprintf(stderr, "[ERROR] %s: %s\n", friendlyMsg, errMsg)

	if strings.EqualFold(os.Getenv(idsecDebugEnvVar), "true") {
		_, _ = fmt.Fprintf(stderr, "\nStack trace:\n%s\n", debug.Stack())
	} else {
		_, _ = fmt.Fprintln(stderr, "\nFor detailed error information, run with IDSEC_DEBUG=true")
	}

	if agentmode.IsEnabled() {
		WriteErrorEnvelope(stdout, panicFailure(r, errMsg, friendlyMsg))
	}
}

// panicFailure classifies an error-valued panic by its SDK reason, so a
// network outage is not reported as a CLI bug; anything else is INTERNAL_ERROR.
func panicFailure(r any, errMsg, friendlyMsg string) *agentmode.Failure {
	err, _ := r.(error)
	if err != nil {
		if reason, ok := authcommon.Classify(err); ok {
			return agentmode.NewFailure(agentmode.Code(reason), err)
		}
	}
	return agentmode.NewFailure(agentmode.CodeInternalError, err,
		agentmode.WithMessage(friendlyMsg+": "+errMsg),
		agentmode.WithDetail("category", friendlyMsg),
		agentmode.WithHint(hintInternalError))
}

// extractErrorMessage converts the recovered panic value to a string.
func extractErrorMessage(r interface{}) string {
	switch v := r.(type) {
	case error:
		return v.Error()
	case string:
		return v
	default:
		return fmt.Sprintf("%v", v)
	}
}

// categorizeError inspects the raw panic message and returns a short,
// user-friendly label for the error category. The original error message
// is always printed alongside this label so users still see the full details.
func categorizeError(msg string) string {
	lower := strings.ToLower(msg)

	switch {
	case strings.Contains(lower, "reflect:") || strings.Contains(lower, "reflect.value"):
		return "Internal processing error"
	case strings.Contains(lower, "index out of range") || strings.Contains(lower, "slice bounds out of range"):
		return "Internal data processing error"
	case strings.Contains(lower, "interface conversion"):
		return "Internal type mismatch error"
	case strings.Contains(lower, "connection refused") || strings.Contains(lower, "no such host"):
		return "Connection error"
	case strings.Contains(lower, "authentication") || strings.Contains(lower, "token") || strings.Contains(lower, "expired"):
		return "Authentication error"
	default:
		return "An unexpected error occurred"
	}
}
