package actions

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/cyberark/idsec-cli-golang/pkg/agentmode"
	commonargs "github.com/cyberark/idsec-cli-golang/pkg/common/args"
	"github.com/cyberark/idsec-cli-golang/pkg/credentials"
	authcommon "github.com/cyberark/idsec-sdk-golang/pkg/auth/common"
)

// Agent-mode hints. An agent may run a hint verbatim, so hints are constants
// with <placeholders>; the only values spliced in (by the *Hint functions)
// are CLI constants such as flag names and registered command paths.
const (
	hintProfilesList             = "run `idsec profiles list` to see configured profiles"
	hintProfileCreate            = "create it with `idsec configure --silent --profile-name <profile> ...` or `idsec profiles add --profile-path <file>`"
	hintMFARequired              = "MFA can't be completed non-interactively; log in once in an interactive terminal (`idsec login`), or use a service user"
	hintEndpointUnreachable      = "check network, proxy and DNS settings, then retry"
	hintKeyringFailure           = "the OS keyring / token cache is unavailable; unlock it and retry"
	hintCertificateError         = "TLS verification failed; check the system CA trust store or proxy"
	hintInternalError            = "rerun with IDSEC_DEBUG=true for a stack trace on stderr"
	hintProfileUnreadable        = "the profile file exists but can't be read; run `idsec profiles show --profile-name <profile>` to see the error, then fix the file or replace it with `idsec profiles add --profile-path <file> --yes`"
	hintProfilesFolderUnreadable = "the profiles folder can't be read; make sure IDSEC_PROFILES_FOLDER (default ~/.idsec/profiles) is a readable directory"
	hintInvalidQuery             = "fix the jq expression; bind shell values with --arg/--argjson"
	hintFlagsAfterCommand        = "a flag before the full command path may have taken the next word as its value; put flags after the command, e.g. `idsec <service> <resource> <action> --<flag> <value>`"

	hintPassFlagPrefix     = "agent mode never prompts; pass --"
	hintRunPrefix          = "run `"
	hintListFlagsSuffix    = " --help` to list flags"
	hintListCommandsSuffix = " --help` to list available commands"
	hintLoginPrefix        = "run `idsec login --profile-name <profile> --agent` with --"
	hintLoginUsernameInfix = "-username/--"
	hintLoginSecretInfix   = "-secret or IDSEC_"
	hintLoginEnvSuffix     = "_* env vars"
	hintCredPassPrefix     = "pass --"
	hintUsernameSetInfix   = "-username, set "
	hintSecretSetInfix     = "-secret, set "
	hintCredOrInfix        = " or "
	hintRCAddInfix         = ", or add "
	hintRCUsernameSuffix   = "_username to an .idsecrc file"
	hintRCSecretSuffix     = "_secret to an .idsecrc file"

	hintProfilesEditAlternative = "use `idsec profiles add --profile-path <file>` or `idsec configure` flags instead"
)

// defaultHints apply to a classified failure that carries no hints of its own.
var defaultHints = map[agentmode.Code][]string{
	agentmode.CodeProfileNotFound:     {hintProfilesList, hintProfileCreate},
	agentmode.CodeMFARequired:         {hintMFARequired},
	agentmode.CodeEndpointUnreachable: {hintEndpointUnreachable},
	agentmode.CodeKeyringFailure:      {hintKeyringFailure},
	agentmode.CodeCertificateError:    {hintCertificateError},
	agentmode.CodeInternalError:       {hintInternalError},
}

// Hint template inputs can come from error text, so each template returns ""
// (dropped by agentmode.WithHint) unless its input has the strict shape of a
// CLI flag name, command path or authenticator key.
var (
	reHintFlagName      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	reHintCommandPath   = regexp.MustCompile(`^idsec( [a-z0-9][a-z0-9-]*)*$`)
	reHintAuthenticator = regexp.MustCompile(`^[a-z0-9_-]+$`)
)

// passFlagHint: flag must be a CLI flag name.
func passFlagHint(flag string) string {
	if !reHintFlagName.MatchString(flag) {
		return ""
	}
	return hintPassFlagPrefix + flag
}

// listFlagsHint: commandPath must be a registered command path.
func listFlagsHint(commandPath string) string {
	if !reHintCommandPath.MatchString(commandPath) {
		return ""
	}
	return hintRunPrefix + commandPath + hintListFlagsSuffix
}

// listCommandsHint: parent must be a registered command path.
func listCommandsHint(parent string) string {
	if !reHintCommandPath.MatchString(parent) {
		return ""
	}
	return hintRunPrefix + parent + hintListCommandsSuffix
}

// loginHint: authenticator must be a supported-authenticator key.
func loginHint(authenticator string) string {
	if !reHintAuthenticator.MatchString(authenticator) {
		return ""
	}
	return hintLoginPrefix + authenticator + hintLoginUsernameInfix + authenticator +
		hintLoginSecretInfix + strings.ToUpper(authenticator) + hintLoginEnvSuffix
}

// usernameRequiredHint: authenticator must be a supported-authenticator key.
func usernameRequiredHint(authenticator string) string {
	if !reHintAuthenticator.MatchString(authenticator) {
		return ""
	}
	return hintCredPassPrefix + authenticator + hintUsernameSetInfix + credentials.EnvUsernameVar(authenticator) +
		hintRCAddInfix + authenticator + hintRCUsernameSuffix
}

// secretRequiredHint: authenticator must be a supported-authenticator key.
func secretRequiredHint(authenticator string) string {
	if !reHintAuthenticator.MatchString(authenticator) {
		return ""
	}
	return hintCredPassPrefix + authenticator + hintSecretSetInfix + credentials.EnvSecretVar(authenticator) +
		hintCredOrInfix + credentials.EnvSecretFileVar(authenticator) +
		hintRCAddInfix + authenticator + hintRCSecretSuffix
}

// withDefaultHints appends defaultHints[code].
func withDefaultHints(code agentmode.Code) agentmode.FailureOption {
	return func(f *agentmode.Failure) { f.Hints = append(f.Hints, defaultHints[code]...) }
}

const fallbackFailureMessage = "command failed; see stderr for details"

// lastFailureMessage, when set, returns the most recent PrintFailure text so
// already-reported failures without a Failure still carry their message.
var lastFailureMessage = func() string {
	msg, _ := lastPrintedFailure.Load().(string)
	return msg
}

var lastPrintedFailure atomic.Value

func init() {
	commonargs.SetFailureObserver(func(msg string) { lastPrintedFailure.Store(msg) })
}

// Cobra and pflag return untyped errors, so their messages are matched here
// and nowhere else. quoted matches one Go %q string or rune literal.
const quoted = `("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)+')`

var (
	reRequiredFlags   = regexp.MustCompile(`^required flag\(s\) "(.+)" not set$`)
	reUnknownCommand  = regexp.MustCompile(`^unknown command ` + quoted + ` for ` + quoted)
	reFlagGroup       = regexp.MustCompile(`^(?:if any flags in the group|at least one of the flags in the group) \[([^\]]*)\]`)
	reUnknownLongFlag = regexp.MustCompile(`^unknown flag: --(.+)$`)
	reUnknownShort    = regexp.MustCompile(`^unknown shorthand flag: ` + quoted + ` in -`)
	reMissingLong     = regexp.MustCompile(`^flag needs an argument: --(.+)$`)
	reMissingShort    = regexp.MustCompile(`^flag needs an argument: ` + quoted + ` in -`)
	reInvalidValue    = regexp.MustCompile(`^invalid argument ` + quoted + ` for ` + quoted + ` flag: `)
	reBadFlagSyntax   = regexp.MustCompile(`^bad flag syntax: (.*)$`)
)

// ClassifyError maps any error that reached the top level to a Failure.
// Precedence (first match wins):
//  1. errors.As *agentmode.Failure              → as-is (most specific wins)
//  2. errors.As *args.MissingRequiredInputError → MISSING_REQUIRED_INPUT, details.missing_flags=[Flag]
//  3. Cobra "required flag(s) \"a\", \"b\" not set" → MISSING_REQUIRED_INPUT, details.missing_flags=[a b]
//  4. Cobra "unknown command \"x\" for \"p\""   → UNKNOWN_COMMAND kind=unknown_command
//  5. Cobra flag-group messages                → INVALID_INPUT kind=flag_conflict
//  6. authcommon.Classify(err)                 → that reason
//  7. *ExitCodeError without Failure           → ACTION_FAILED, message = last PrintFailure text
//     or "command failed; see stderr for details"
//  8. anything else                            → ACTION_FAILED, message = err.Error()
//
// A result without hints gets defaultHints for its code.
func ClassifyError(err error) *agentmode.Failure {
	f := classify(err)
	if len(f.Hints) == 0 && len(defaultHints[f.Code]) > 0 {
		withHints := *f
		withHints.Hints = defaultHints[f.Code]
		f = &withHints
	}
	return f
}

func classify(err error) *agentmode.Failure {
	if err == nil {
		return agentmode.NewFailure(agentmode.CodeActionFailed, nil, agentmode.WithMessage(fallbackFailureMessage))
	}
	var failure *agentmode.Failure
	if errors.As(err, &failure) {
		return failure
	}
	var missing *commonargs.MissingRequiredInputError
	if errors.As(err, &missing) {
		return agentmode.NewFailure(agentmode.CodeMissingRequiredInput, err, missingFlagOptions(missing.Flag)...)
	}
	text := err.Error()
	if m := reRequiredFlags.FindStringSubmatch(text); m != nil {
		return agentmode.NewFailure(agentmode.CodeMissingRequiredInput, err,
			missingFlagOptions(strings.Split(m[1], `", "`)...)...)
	}
	if m := reUnknownCommand.FindStringSubmatch(text); m != nil {
		token, tokErr := strconv.Unquote(m[1])
		parent, parentErr := strconv.Unquote(m[2])
		if tokErr == nil && parentErr == nil {
			return agentmode.NewFailure(agentmode.CodeUnknownCommand, err,
				agentmode.WithDetail("kind", agentmode.KindUnknownCommand),
				agentmode.WithDetail("token", token),
				agentmode.WithDetail("parent", parent),
				agentmode.WithHint(listCommandsHint(parent)))
		}
	}
	if m := reFlagGroup.FindStringSubmatch(text); m != nil {
		return agentmode.NewFailure(agentmode.CodeInvalidInput, err,
			agentmode.WithDetail("kind", agentmode.KindFlagConflict),
			agentmode.WithDetail("flags", strings.Fields(m[1])))
	}
	if reason, ok := authcommon.Classify(err); ok {
		return agentmode.NewFailure(agentmode.Code(reason), err)
	}
	var exitErr *ExitCodeError
	if errors.As(err, &exitErr) {
		msg := fallbackFailureMessage
		if lastFailureMessage != nil {
			if last := lastFailureMessage(); last != "" {
				msg = last
			}
		}
		return agentmode.NewFailure(agentmode.CodeActionFailed, err, agentmode.WithMessage(msg))
	}
	if text == "" {
		return agentmode.NewFailure(agentmode.CodeActionFailed, err, agentmode.WithMessage(fallbackFailureMessage))
	}
	return agentmode.NewFailure(agentmode.CodeActionFailed, err)
}

// classifiedOr returns the code of a Failure wrapped by err, else the
// authcommon.Classify reason, else fallback.
func classifiedOr(err error, fallback agentmode.Code) agentmode.Code {
	var failure *agentmode.Failure
	if errors.As(err, &failure) {
		return failure.Code
	}
	if reason, ok := authcommon.Classify(err); ok {
		return agentmode.Code(reason)
	}
	return fallback
}

// FlagError is installed as root's FlagErrorFunc (inherited by all subcommands).
// It wraps pflag parse errors as INVALID_INPUT with details kind
// (unknown_flag | missing_value | invalid_value), flag (name) and command.
// The returned error's text is err's text unchanged.
func FlagError(cmd *cobra.Command, err error) error {
	if err == nil || errors.Is(err, pflag.ErrHelp) {
		return err
	}
	var opts []agentmode.FailureOption
	commandPath := ""
	if cmd != nil {
		commandPath = cmd.CommandPath()
		opts = append(opts, agentmode.WithDetail("command", commandPath))
	}
	kind, flag, short := parseFlagError(cmd, err.Error())
	opts = append(opts, agentmode.WithRedactedMessage(flagErrorMessage(kind, flag, short)))
	if kind != "" {
		opts = append(opts, agentmode.WithDetail("kind", kind))
	}
	// An unknown flag's name is whatever was typed, so it is kept only when it
	// has the shape of a flag name; known flags are registered names.
	if flag != "" && (kind != agentmode.KindUnknownFlag || safeFlagName(flag, short)) {
		opts = append(opts, agentmode.WithDetail("flag", flag))
	}
	if kind == agentmode.KindUnknownFlag && commandPath != "" {
		opts = append(opts, agentmode.WithHint(listFlagsHint(commandPath)))
	}
	return agentmode.NewFailure(agentmode.CodeInvalidInput, err, opts...)
}

// parseFlagError extracts the kind and flag name from a pflag error; short
// reports that flag is an unresolved shorthand rather than a long name.
func parseFlagError(cmd *cobra.Command, text string) (kind, flag string, short bool) {
	if m := reUnknownLongFlag.FindStringSubmatch(text); m != nil {
		return agentmode.KindUnknownFlag, m[1], false
	}
	if m := reUnknownShort.FindStringSubmatch(text); m != nil {
		return agentmode.KindUnknownFlag, unquoteOrEmpty(m[1]), true
	}
	if m := reMissingLong.FindStringSubmatch(text); m != nil {
		return agentmode.KindMissingValue, m[1], false
	}
	if m := reMissingShort.FindStringSubmatch(text); m != nil {
		shorthand := unquoteOrEmpty(m[1])
		name := longFlagName(cmd, shorthand)
		return agentmode.KindMissingValue, name, name == shorthand
	}
	if m := reInvalidValue.FindStringSubmatch(text); m != nil {
		// pflag names the flag "--name" or "-s, --name".
		name := unquoteOrEmpty(m[2])
		if i := strings.LastIndex(name, "--"); i >= 0 {
			name = name[i+2:]
		}
		return agentmode.KindInvalidValue, name, false
	}
	if m := reBadFlagSyntax.FindStringSubmatch(text); m != nil {
		// "---x" or "--=x": report the name only when one is cleanly left.
		name, _, _ := strings.Cut(strings.TrimLeft(m[1], "-"), "=")
		if !reHintFlagName.MatchString(name) {
			name = ""
		}
		return agentmode.KindUnknownFlag, name, false
	}
	return "", "", false
}

// reSafeShorthand matches a flag shorthand that is safe to echo.
var reSafeShorthand = regexp.MustCompile(`^[A-Za-z0-9]$`)

// safeFlagName reports whether flag has the shape of a flag name (or, when
// short, a shorthand), so it can be echoed without quoting typed input.
func safeFlagName(flag string, short bool) bool {
	if short {
		return reSafeShorthand.MatchString(flag)
	}
	return reHintFlagName.MatchString(flag)
}

// flagErrorMessage is the envelope message for a pflag parse error. pflag's
// own text can quote raw argv (a flag value, or a whole "-abc" or "---x"
// token), so the message names the flag only, and only when it looks like one.
func flagErrorMessage(kind, flag string, short bool) string {
	name := ""
	if safeFlagName(flag, short) {
		name = " --" + flag
		if short {
			name = " -" + flag
		}
	}
	switch kind {
	case agentmode.KindUnknownFlag:
		if name == "" {
			return "unknown flag or bad flag syntax"
		}
		return "unknown flag:" + name
	case agentmode.KindMissingValue:
		if name == "" {
			return "flag needs an argument"
		}
		return "flag needs an argument:" + name
	case agentmode.KindInvalidValue:
		if name == "" {
			return "invalid flag argument"
		}
		return "invalid argument for" + name
	}
	return "invalid flag usage; see stderr for details"
}

func unquoteOrEmpty(lit string) string {
	s, err := strconv.Unquote(lit)
	if err != nil {
		return ""
	}
	return s
}

// longFlagName maps a shorthand to its long name when cmd defines it.
func longFlagName(cmd *cobra.Command, shorthand string) string {
	if cmd == nil || shorthand == "" {
		return shorthand
	}
	if f := cmd.Flags().ShorthandLookup(shorthand); f != nil {
		return f.Name
	}
	return shorthand
}

// WriteErrorEnvelope classifies err and writes exactly one envelope per
// process; later calls write nothing.
func WriteErrorEnvelope(w io.Writer, err error) {
	if !agentmode.ClaimEnvelope() {
		return
	}
	_ = agentmode.Write(w, agentmode.NewErrorEnvelope(ClassifyError(err)))
}

// UnknownCommandFailure reports that token matched no subcommand of parent.
// Its text is `unknown command "<token>" for "<parent path>"`.
//
// mayBeFlagValue marks a token that directly follows a flag parent doesn't
// define: it may be that flag's value (a secret, say), so the envelope omits
// it and names only parent. The error text, printed to stderr, is unchanged.
func UnknownCommandFailure(token string, parent *cobra.Command, mayBeFlagValue bool) error {
	path := parent.CommandPath()
	opts := []agentmode.FailureOption{
		agentmode.WithDetail("kind", agentmode.KindUnknownCommand),
		agentmode.WithDetail("parent", path),
		agentmode.WithDetail("available", availableSubcommands(parent)),
		agentmode.WithHint(listCommandsHint(path)),
	}
	if mayBeFlagValue {
		opts = append(opts,
			agentmode.WithRedactedMessage(fmt.Sprintf("unknown command for %q", path)),
			agentmode.WithHint(hintFlagsAfterCommand))
	} else {
		opts = append(opts, agentmode.WithDetail("token", token))
	}
	return agentmode.NewFailure(agentmode.CodeUnknownCommand,
		fmt.Errorf("unknown command %q for %q", token, path), opts...)
}

// IncompleteCommandFailure reports that the group command cmd was invoked
// without one of its subcommands.
func IncompleteCommandFailure(cmd *cobra.Command) error {
	path := cmd.CommandPath()
	return agentmode.NewFailure(agentmode.CodeUnknownCommand,
		fmt.Errorf("%q requires a subcommand", path),
		agentmode.WithDetail("kind", agentmode.KindIncompleteCommand),
		agentmode.WithDetail("parent", path),
		agentmode.WithDetail("available", availableSubcommands(cmd)),
		agentmode.WithHint(listCommandsHint(path)))
}

func availableSubcommands(cmd *cobra.Command) []string {
	names := []string{}
	for _, c := range cmd.Commands() {
		if c.IsAvailableCommand() {
			names = append(names, c.Name())
		}
	}
	sort.Strings(names)
	return names
}
