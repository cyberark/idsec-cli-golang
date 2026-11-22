package agentmode_test

import (
	"regexp"
	"testing"

	"github.com/cyberark/idsec-cli-golang/pkg/agentmode"
)

var allCodes = []agentmode.Code{
	agentmode.CodeProfileNotFound,
	agentmode.CodeConfigError,
	agentmode.CodeUsernameRequired,
	agentmode.CodeSecretRequired,
	agentmode.CodeAuthFailed,
	agentmode.CodeMFARequired,
	agentmode.CodeEndpointUnreachable,
	agentmode.CodeKeyringFailure,
	agentmode.CodeCertificateError,
	agentmode.CodeMissingRequiredInput,
	agentmode.CodeInteractiveRequired,
	agentmode.CodeUnknownCommand,
	agentmode.CodeInvalidInput,
	agentmode.CodeNotAuthenticated,
	agentmode.CodeActionFailed,
	agentmode.CodeInternalError,
}

var allKinds = []string{
	agentmode.KindUnknownCommand,
	agentmode.KindIncompleteCommand,
	agentmode.KindUnknownFlag,
	agentmode.KindMissingValue,
	agentmode.KindInvalidValue,
	agentmode.KindFlagConflict,
	agentmode.KindValidation,
	agentmode.KindInvalidQuery,
	agentmode.KindInvalidJSON,
	agentmode.KindUnreadableInput,
}

func TestCodes_ShapeAndUniqueness(t *testing.T) {
	t.Parallel()

	shape := regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	seen := make(map[agentmode.Code]bool, len(allCodes))
	for _, c := range allCodes {
		if !shape.MatchString(string(c)) {
			t.Errorf("code %q does not match %s", c, shape)
		}
		if seen[c] {
			t.Errorf("duplicate code %q", c)
		}
		seen[c] = true
	}
	if len(seen) != 16 {
		t.Errorf("got %d distinct codes, want 16", len(seen))
	}
}

func TestKinds_ShapeAndUniqueness(t *testing.T) {
	t.Parallel()

	shape := regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	seen := make(map[string]bool, len(allKinds))
	for _, k := range allKinds {
		if !shape.MatchString(k) {
			t.Errorf("kind %q does not match %s", k, shape)
		}
		if seen[k] {
			t.Errorf("duplicate kind %q", k)
		}
		seen[k] = true
	}
	if len(seen) != 10 {
		t.Errorf("got %d distinct kinds, want 10", len(seen))
	}
}
