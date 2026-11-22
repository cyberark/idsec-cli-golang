package actions

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/cyberark/idsec-cli-golang/pkg/actions/testutils"
	"github.com/cyberark/idsec-cli-golang/pkg/agentmode"
	"github.com/cyberark/idsec-cli-golang/pkg/cli"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authcommon "github.com/cyberark/idsec-sdk-golang/pkg/auth/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/models"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
)

const agentExecCommandPath = "idsec exec pcloud accounts list"

// setExecAgentMode resets agent mode, config and envelope state around a test
// and, when agent is true, enables agent mode through IDSEC_AGENT_MODE (which
// runExecAction re-resolves). Must not be called from a t.Parallel() test.
func setExecAgentMode(t *testing.T, agent bool) {
	t.Helper()
	// Registered first so it runs last (LIFO), after t.Setenv restores the env.
	t.Cleanup(func() {
		resetAgentModeBaseline()
		agentmode.ResetEnvelopeState()
	})
	clearAgentEnv(t)
	if agent {
		t.Setenv(agentmode.EnvVar, "1")
	}
	agentmode.ResetEnvelopeState()
	resetLastPrintedFailure(t)
}

// stubLoadAuthentication replaces loadAuthentication with load, keyed by
// authenticator name. Must not be called from a t.Parallel() test.
func stubLoadAuthentication(t *testing.T, load func(name string) (*authmodels.IdsecToken, error)) {
	t.Helper()
	prev := loadAuthentication
	t.Cleanup(func() { loadAuthentication = prev })
	loadAuthentication = func(a auth.IdsecAuth, _ *models.IdsecProfile, _ bool) (*authmodels.IdsecToken, error) {
		return load(a.AuthenticatorName())
	}
}

func tokenExpiringIn(d time.Duration) *authmodels.IdsecToken {
	return &authmodels.IdsecToken{Token: "t", ExpiresIn: commonmodels.IdsecRFC3339Time(time.Now().Add(d))}
}

func profileWithAuthenticators(name string, authenticators ...string) *models.IdsecProfile {
	p := &models.IdsecProfile{ProfileName: name, AuthProfiles: map[string]*authmodels.IdsecAuthProfile{}}
	for _, a := range authenticators {
		p.AuthProfiles[a] = &authmodels.IdsecAuthProfile{Username: "u", AuthMethod: authmodels.Identity}
	}
	return p
}

// newAgentExecAction returns an exec action over profile "dev" (built by
// loadProfile) and the leaf command idsec exec pcloud accounts list.
func newAgentExecAction(loadProfile func(string) (*models.IdsecProfile, error), run func() error) (*IdsecBaseExecAction, *cobra.Command) {
	loader := testutils.NewMockProfileLoader()
	loader.LoadProfileFunc = loadProfile
	action := NewIdsecBaseExecAction(execActionPtr(&mockExecAction{
		runExecActionFunc: func(*cli.IdsecCLIAPI, *cobra.Command, *cobra.Command, []string) error { return run() },
	}), "test-action", loader.AsProfileLoader())

	root := &cobra.Command{Use: "idsec"}
	execCmd := &cobra.Command{Use: "exec"}
	execCmd.Flags().String("profile-name", "dev", "")
	execCmd.Flags().Bool("refresh-auth", false, "")
	execCmd.Flags().Int("retry-count", 1, "")
	pcloud := &cobra.Command{Use: "pcloud"}
	accounts := &cobra.Command{Use: "accounts"}
	leaf := &cobra.Command{Use: "list"}
	accounts.AddCommand(leaf)
	pcloud.AddCommand(accounts)
	execCmd.AddCommand(pcloud)
	root.AddCommand(execCmd)
	return action, leaf
}

func loggedInProfile(name string) (*models.IdsecProfile, error) {
	return profileWithAuthenticators(name, "isp"), nil
}

func runAndCapture(t *testing.T, action *IdsecBaseExecAction, leaf *cobra.Command) (stdout, stderr string, err error) {
	t.Helper()
	stdout = withCapturedOutput(func() {
		stderr = withCapturedStderr(func() { err = action.runExecAction(leaf, nil) })
	})
	return stdout, stderr, err
}

func TestRunExecAction_ActionFailureCodes(t *testing.T) {
	validationErr := validateActionInput("create", &struct {
		Name string `validate:"required"`
	}{})
	jqErr := applyGojqQuery(map[string]any{}, ".[", false)

	tests := []struct {
		name        string
		actionErr   error
		wantCode    agentmode.Code
		wantDetails map[string]any
		wantHints   []string
		// wantEnvMsg is the redacted envelope message; empty means the stderr text.
		wantEnvMsg string
	}{
		{
			name:        "success_unclassified_is_action_failed",
			actionErr:   errors.New("failed to get account [999]: 404 Not Found"),
			wantCode:    agentmode.CodeActionFailed,
			wantDetails: map[string]any{"command": agentExecCommandPath},
		},
		{
			name:        "success_keyring_wrapped_is_keyring_failure",
			actionErr:   fmt.Errorf("x: %w", authcommon.ErrKeyringFailure),
			wantCode:    agentmode.CodeKeyringFailure,
			wantDetails: map[string]any{"command": agentExecCommandPath},
		},
		{
			name:      "success_validation_failure_merges_command",
			actionErr: validationErr,
			wantCode:  agentmode.CodeInvalidInput,
			wantDetails: map[string]any{
				"kind": agentmode.KindValidation, "action": "create", "command": agentExecCommandPath,
			},
		},
		{
			name:      "success_jq_failure_merges_command",
			actionErr: jqErr,
			wantCode:  agentmode.CodeInvalidInput,
			wantDetails: map[string]any{
				"kind": agentmode.KindInvalidQuery, "flag": "query", "stage": "parse", "command": agentExecCommandPath,
			},
			wantHints:  []string{hintInvalidQuery},
			wantEnvMsg: "invalid jq query: parse error; see stderr for details",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setExecAgentMode(t, false)
			stubLoadAuthentication(t, func(string) (*authmodels.IdsecToken, error) { return tokenExpiringIn(time.Hour), nil })
			action, leaf := newAgentExecAction(loggedInProfile, func() error { return tt.actionErr })

			stdout, stderr, err := runAndCapture(t, action, leaf)

			wantMsg := "Failed to execute action: " + tt.actionErr.Error()
			if stderr != wantMsg+"\n" || stdout != "" {
				t.Errorf("stderr = %q, stdout = %q; want stderr %q and empty stdout", stderr, stdout, wantMsg+"\n")
			}
			if !errors.Is(err, ErrActionFailed) {
				t.Errorf("errors.Is(err, ErrActionFailed) = false")
			}
			f := failureOf(t, err)
			wantEnvMsg := wantMsg
			if tt.wantEnvMsg != "" {
				wantEnvMsg = tt.wantEnvMsg
			}
			if f.Code != tt.wantCode || f.Message != wantEnvMsg {
				t.Errorf("Failure code/message = %q %q, want %q %q", f.Code, f.Message, tt.wantCode, wantEnvMsg)
			}
			if !reflect.DeepEqual(f.Details, tt.wantDetails) {
				t.Errorf("Details = %#v, want %#v", f.Details, tt.wantDetails)
			}
			if !reflect.DeepEqual(f.Hints, tt.wantHints) {
				t.Errorf("Hints = %#v, want %#v", f.Hints, tt.wantHints)
			}
		})
	}
}

func TestRunExecAction_NotAuthenticated(t *testing.T) {
	keyringErr := fmt.Errorf("load token: %w", authcommon.ErrKeyringFailure)
	ispLogin := "run `idsec login --profile-name <profile> --agent` with --isp-username/--isp-secret or IDSEC_ISP_* env vars"
	pvwaLogin := "run `idsec login --profile-name <profile> --agent` with --pvwa-username/--pvwa-secret or IDSEC_PVWA_* env vars"

	tests := []struct {
		name       string
		auths      []string
		load       func(name string) (*authmodels.IdsecToken, error)
		wantStates map[string]string
		wantHints  []string
	}{
		{
			name:       "success_all_keyring_puts_keyring_hint_first",
			auths:      []string{"isp", "pvwa"},
			load:       func(string) (*authmodels.IdsecToken, error) { return nil, keyringErr },
			wantStates: map[string]string{"isp": "KEYRING_FAILURE", "pvwa": "KEYRING_FAILURE"},
			wantHints:  []string{hintKeyringFailure, ispLogin, pvwaLogin},
		},
		{
			name:  "success_mixed_states_get_login_hints_only",
			auths: []string{"isp", "pvwa"},
			load: func(name string) (*authmodels.IdsecToken, error) {
				if name == "isp" {
					return nil, keyringErr
				}
				return nil, nil
			},
			wantStates: map[string]string{"isp": "KEYRING_FAILURE", "pvwa": "NOT_AUTHENTICATED"},
			wantHints:  []string{ispLogin, pvwaLogin},
		},
		{
			name:       "success_expired_token",
			auths:      []string{"isp"},
			load:       func(string) (*authmodels.IdsecToken, error) { return tokenExpiringIn(-time.Hour), nil },
			wantStates: map[string]string{"isp": "TOKEN_EXPIRED"},
			wantHints:  []string{ispLogin},
		},
		{
			name:       "success_unclassified_load_error_is_recorded",
			auths:      []string{"isp"},
			load:       func(string) (*authmodels.IdsecToken, error) { return nil, errors.New("decode cache") },
			wantStates: map[string]string{"isp": "NOT_AUTHENTICATED"},
			wantHints:  []string{ispLogin},
		},
		{
			name:       "edge_case_all_not_authenticated_gets_no_reason_hint",
			auths:      []string{"isp", "pvwa"},
			load:       func(string) (*authmodels.IdsecToken, error) { return nil, nil },
			wantStates: map[string]string{"isp": "NOT_AUTHENTICATED", "pvwa": "NOT_AUTHENTICATED"},
			wantHints:  []string{ispLogin, pvwaLogin},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setExecAgentMode(t, false)
			stubLoadAuthentication(t, tt.load)
			action, leaf := newAgentExecAction(func(name string) (*models.IdsecProfile, error) {
				return profileWithAuthenticators(name, tt.auths...), nil
			}, func() error { t.Fatal("action ran without authenticators"); return nil })

			stdout, stderr, err := runAndCapture(t, action, leaf)

			if stderr != notAuthenticatedMessage+"\n" || stdout != "" {
				t.Errorf("stderr = %q, stdout = %q", stderr, stdout)
			}
			f := failureOf(t, err)
			if f.Code != agentmode.CodeNotAuthenticated || f.Message != notAuthenticatedMessage {
				t.Errorf("Failure code/message = %q %q", f.Code, f.Message)
			}
			if f.Details["profile"] != "dev" || !reflect.DeepEqual(f.Details["authenticators"], tt.wantStates) {
				t.Errorf("Details = %#v, want profile dev and authenticators %#v", f.Details, tt.wantStates)
			}
			if !reflect.DeepEqual(f.Hints, tt.wantHints) {
				t.Errorf("Hints = %#v, want %#v", f.Hints, tt.wantHints)
			}
		})
	}
}

func TestRunExecAction_NotAuthenticatedEnvelopeGolden(t *testing.T) {
	setExecAgentMode(t, false)
	stubLoadAuthentication(t, func(string) (*authmodels.IdsecToken, error) { return tokenExpiringIn(-time.Hour), nil })
	action, leaf := newAgentExecAction(loggedInProfile, func() error { return nil })

	_, _, err := runAndCapture(t, action, leaf)

	var buf bytes.Buffer
	WriteErrorEnvelope(&buf, err)
	want := "{\"status\":\"error\",\"error\":{\"code\":\"NOT_AUTHENTICATED\",\"message\":\"Failed to load authenticators, tokens are either expired or authenticators are not logged in, please login first\",\"details\":{\"authenticators\":{\"isp\":\"TOKEN_EXPIRED\"},\"profile\":\"dev\"}},\"hints\":[\"run `idsec login --profile-name <profile> --agent` with --isp-username/--isp-secret or IDSEC_ISP_* env vars\"]}\n"
	if buf.String() != want {
		t.Errorf("envelope =\n%s\nwant\n%s", buf.String(), want)
	}
}

func TestRunExecAction_ProfileFailures(t *testing.T) {
	tests := []struct {
		name        string
		load        func(string) (*models.IdsecProfile, error)
		wantCode    agentmode.Code
		wantDetails map[string]any
		wantHints   []string
	}{
		{
			name:        "success_missing_profile",
			load:        func(string) (*models.IdsecProfile, error) { return nil, nil },
			wantCode:    agentmode.CodeProfileNotFound,
			wantDetails: map[string]any{"profile": "dev"},
			wantHints:   []string{hintProfilesList, hintProfileCreate},
		},
		{
			name:        "success_unreadable_profile",
			load:        func(string) (*models.IdsecProfile, error) { return nil, errors.New("invalid character '}'") },
			wantCode:    agentmode.CodeConfigError,
			wantDetails: map[string]any{"profile": "dev", "source": "profile"},
			wantHints:   []string{hintProfileUnreadable},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setExecAgentMode(t, false)
			action, leaf := newAgentExecAction(tt.load, func() error { return nil })

			stdout, stderr, err := runAndCapture(t, action, leaf)

			if stderr != "Please configure a profile before trying to execute actions\n" || stdout != "" {
				t.Errorf("stderr = %q, stdout = %q", stderr, stdout)
			}
			f := failureOf(t, err)
			if f.Code != tt.wantCode || f.Message != profileRequiredMessage {
				t.Errorf("Failure code/message = %q %q", f.Code, f.Message)
			}
			if !reflect.DeepEqual(f.Details, tt.wantDetails) {
				t.Errorf("Details = %#v, want %#v", f.Details, tt.wantDetails)
			}
			if !reflect.DeepEqual(f.Hints, tt.wantHints) {
				t.Errorf("Hints = %#v, want %#v", f.Hints, tt.wantHints)
			}
		})
	}
}

func TestRunExecAction_CLIAPIFailure(t *testing.T) {
	tests := []struct {
		name     string
		apiErr   error
		wantCode agentmode.Code
	}{
		{"success_unclassified_is_internal_error", errors.New("boom"), agentmode.CodeInternalError},
		{"success_classified_reason_wins", fmt.Errorf("x: %w", authcommon.ErrKeyringFailure), agentmode.CodeKeyringFailure},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setExecAgentMode(t, false)
			stubLoadAuthentication(t, func(string) (*authmodels.IdsecToken, error) { return tokenExpiringIn(time.Hour), nil })
			prev := newCLIAPI
			t.Cleanup(func() { newCLIAPI = prev })
			newCLIAPI = func([]auth.IdsecAuth, *models.IdsecProfile) (*cli.IdsecCLIAPI, error) { return nil, tt.apiErr }
			action, leaf := newAgentExecAction(loggedInProfile, func() error { return nil })

			_, stderr, err := runAndCapture(t, action, leaf)

			wantMsg := "Failed to create CLI API: " + tt.apiErr.Error()
			if stderr != wantMsg+"\n" {
				t.Errorf("stderr = %q, want %q", stderr, wantMsg+"\n")
			}
			if f := failureOf(t, err); f.Code != tt.wantCode || f.Message != wantMsg {
				t.Errorf("Failure code/message = %q %q", f.Code, f.Message)
			}
		})
	}
}

func TestRunExecAction_PartialAuth(t *testing.T) {
	partial := func(name string) (*authmodels.IdsecToken, error) {
		if name == "isp" {
			return tokenExpiringIn(time.Hour), nil
		}
		return nil, nil
	}
	twoAuthProfile := func(name string) (*models.IdsecProfile, error) {
		return profileWithAuthenticators(name, "isp", "pvwa"), nil
	}

	t.Run("success_agent_mode_collects_warning_once", func(t *testing.T) {
		setExecAgentMode(t, true)
		stubLoadAuthentication(t, partial)
		action, leaf := newAgentExecAction(twoAuthProfile, func() error { return nil })

		_, stderr, err := runAndCapture(t, action, leaf)

		if err != nil {
			t.Fatalf("runExecAction() = %v", err)
		}
		if !agentmode.IsEnabled() {
			t.Fatal("agent mode was not enabled by IDSEC_AGENT_MODE")
		}
		if strings.Contains(stderr, partialAuthMessage) {
			t.Errorf("stderr = %q, want no interactive notice in agent mode", stderr)
		}
		if got := agentmode.DrainWarnings(); !reflect.DeepEqual(got, []string{partialAuthMessage}) {
			t.Errorf("DrainWarnings() = %#v", got)
		}
		if got := agentmode.DrainWarnings(); got != nil {
			t.Errorf("second DrainWarnings() = %#v, want nil", got)
		}
	})

	t.Run("success_human_mode_prints_notice_and_collects_nothing", func(t *testing.T) {
		setExecAgentMode(t, false)
		stubLoadAuthentication(t, partial)
		action, leaf := newAgentExecAction(twoAuthProfile, func() error { return nil })

		stdout, stderr, err := runAndCapture(t, action, leaf)

		if err != nil {
			t.Fatalf("runExecAction() = %v", err)
		}
		if stderr != partialAuthMessage+"\n" || stdout != "" {
			t.Errorf("stderr = %q, stdout = %q", stderr, stdout)
		}
		if got := agentmode.DrainWarnings(); got != nil {
			t.Errorf("DrainWarnings() = %#v, want nil in human mode", got)
		}
	})
}
