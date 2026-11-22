package agentmode

// Code is a stable, machine-readable error identifier emitted in agent mode
// as error.code. Values are a public contract: never change or reuse one.
// Values shared with the stderr "idsec: <event>" lines are the upper-cased
// event (missing_required_input → MISSING_REQUIRED_INPUT).
type Code string

const (
	CodeProfileNotFound  Code = "PROFILE_NOT_FOUND"
	CodeConfigError      Code = "CONFIG_ERROR"
	CodeUsernameRequired Code = "USERNAME_REQUIRED"
	CodeSecretRequired   Code = "SECRET_REQUIRED"
	CodeAuthFailed       Code = "AUTH_FAILED"
	// Mirror idsec-sdk-golang pkg/auth/common Reason* (drift-tested in pkg/actions).
	CodeMFARequired          Code = "MFA_REQUIRED"
	CodeEndpointUnreachable  Code = "ENDPOINT_UNREACHABLE"
	CodeKeyringFailure       Code = "KEYRING_FAILURE"
	CodeCertificateError     Code = "CERTIFICATE_ERROR"
	CodeMissingRequiredInput Code = "MISSING_REQUIRED_INPUT"
	CodeInteractiveRequired  Code = "INTERACTIVE_REQUIRED"
	CodeUnknownCommand       Code = "UNKNOWN_COMMAND"
	CodeInvalidInput         Code = "INVALID_INPUT"
	CodeNotAuthenticated     Code = "NOT_AUTHENTICATED"
	CodeActionFailed         Code = "ACTION_FAILED"
	CodeInternalError        Code = "INTERNAL_ERROR"
)

// details.kind values for UNKNOWN_COMMAND and INVALID_INPUT; same contract as Code.
const (
	KindUnknownCommand    = "unknown_command"
	KindIncompleteCommand = "incomplete_command"
	KindUnknownFlag       = "unknown_flag"
	KindMissingValue      = "missing_value"
	KindInvalidValue      = "invalid_value"
	KindFlagConflict      = "flag_conflict"
	KindValidation        = "validation"
	KindInvalidQuery      = "invalid_query"
	KindInvalidJSON       = "invalid_json"
	KindUnreadableInput   = "unreadable_input"
)
