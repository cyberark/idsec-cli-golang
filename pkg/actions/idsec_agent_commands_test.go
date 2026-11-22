package actions

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/cyberark/idsec-cli-golang/pkg/actions/testutils"
	"github.com/cyberark/idsec-cli-golang/pkg/agentmode"
	commonargs "github.com/cyberark/idsec-cli-golang/pkg/common/args"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/keyring"
	"github.com/cyberark/idsec-sdk-golang/pkg/models"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
)

// agentCommandCase runs one failure path in human mode (exact stdout/stderr)
// and in agent mode (the Failure's code, details and hints).
type agentCommandCase struct {
	name  string
	setup func(t *testing.T)
	run   func(t *testing.T) error
	// Human mode.
	wantStderr string
	wantStdout string
	// humanErr checks the human-mode error; by default it must be ErrActionFailed.
	humanErr func(t *testing.T, err error)
	// Agent mode.
	wantCode    agentmode.Code
	wantDetails map[string]any
	wantHints   []string
	// wantMessage, when set, is the expected Failure message.
	wantMessage string
	// agentStderr, when set, replaces wantStderr in agent mode.
	agentStderr *string
}

// setResolvedAgentMode is setExecAgentMode for actions called directly, which
// skip the CommonActionsExecution that would resolve agent mode.
func setResolvedAgentMode(t *testing.T, agent bool) {
	t.Helper()
	setExecAgentMode(t, agent)
	agentmode.Resolve(false, false)
}

// chdirTemp makes relative paths in messages deterministic.
func chdirTemp(t *testing.T) {
	t.Helper()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(orig) })
}

func runAgentCommandCases(t *testing.T, cases []agentCommandCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name+"/human", func(t *testing.T) {
			setResolvedAgentMode(t, false)
			if tc.setup != nil {
				tc.setup(t)
			}
			var err error
			var stderr string
			stdout := withCapturedOutput(func() {
				stderr = withCapturedStderr(func() { err = tc.run(t) })
			})
			if stderr != tc.wantStderr {
				t.Errorf("human stderr = %q, want %q", stderr, tc.wantStderr)
			}
			if stdout != tc.wantStdout {
				t.Errorf("human stdout = %q, want %q", stdout, tc.wantStdout)
			}
			if tc.humanErr != nil {
				tc.humanErr(t, err)
			} else if !errors.Is(err, ErrActionFailed) {
				t.Errorf("human err = %v, want ErrActionFailed", err)
			}
		})
		t.Run(tc.name+"/agent", func(t *testing.T) {
			setResolvedAgentMode(t, true)
			if tc.setup != nil {
				tc.setup(t)
			}
			var err error
			var stderr string
			_ = withCapturedOutput(func() {
				stderr = withCapturedStderr(func() { err = tc.run(t) })
			})
			wantStderr := tc.wantStderr
			if tc.agentStderr != nil {
				wantStderr = *tc.agentStderr
			}
			if stderr != wantStderr {
				t.Errorf("agent stderr = %q, want %q", stderr, wantStderr)
			}
			var f *agentmode.Failure
			if !errors.As(err, &f) {
				t.Fatalf("agent err = %#v, want a *agentmode.Failure", err)
			}
			if f.Code != tc.wantCode {
				t.Errorf("code = %q, want %q", f.Code, tc.wantCode)
			}
			if !reflect.DeepEqual(f.Details, tc.wantDetails) {
				t.Errorf("details = %#v, want %#v", f.Details, tc.wantDetails)
			}
			if tc.wantHints != nil && !reflect.DeepEqual(f.Hints, tc.wantHints) {
				t.Errorf("hints = %#v, want %#v", f.Hints, tc.wantHints)
			}
			if tc.wantMessage != "" && f.Message != tc.wantMessage {
				t.Errorf("message = %q, want %q", f.Message, tc.wantMessage)
			}
			var exitErr *ExitCodeError
			if errors.As(err, &exitErr) && exitErr.Code != 1 {
				t.Errorf("exit code = %d, want 1", exitErr.Code)
			}
		})
	}
}

func strPtr(s string) *string { return &s }

// 8a
func TestLoginFailures_AgentCodes(t *testing.T) {
	pvwaProfile := func(name string) (*models.IdsecProfile, error) {
		return testutils.CreateTestProfileWithAuth(name, "pvwa", authmodels.PVWA), nil
	}
	runLogin := func(load func(string) (*models.IdsecProfile, error), flags map[string]string) func(t *testing.T) error {
		return func(t *testing.T) error {
			mockLoader := testutils.NewMockProfileLoader()
			mockLoader.LoadProfileFunc = load
			cmd := newSilentLoginCmd("test-profile")
			for k, v := range flags {
				_ = cmd.Flags().Set(k, v)
			}
			return NewIdsecLoginAction(mockLoader.AsProfileLoader()).runLoginAction(cmd, nil)
		}
	}
	runAgentCommandCases(t, []agentCommandCase{
		{
			name:        "profile_not_found",
			setup:       isolateCredentialEnv,
			run:         runLogin(func(string) (*models.IdsecProfile, error) { return nil, nil }, nil),
			wantStderr:  "Failed to load or configure profile: no profile found. Please run 'idsec configure' to set up a profile before using login\nidsec: login failed reason=PROFILE_NOT_FOUND\n",
			wantCode:    agentmode.CodeProfileNotFound,
			wantDetails: map[string]any{"profile": "test-profile"},
			wantHints:   []string{hintProfilesList, hintProfileCreate},
		},
		{
			name:  "profile_unreadable",
			setup: isolateCredentialEnv,
			run: runLogin(func(string) (*models.IdsecProfile, error) {
				return nil, errors.New("unexpected end of JSON input")
			}, nil),
			wantStderr:  "Failed to load or configure profile: no profile found. Please run 'idsec configure' to set up a profile before using login\nidsec: login failed reason=CONFIG_ERROR\n",
			wantCode:    agentmode.CodeConfigError,
			wantDetails: map[string]any{"profile": "test-profile", "source": "profile"},
			wantHints:   []string{hintProfileUnreadable},
			wantMessage: profileUnreadableMessage,
		},
		{
			name:        "credentials_file_unreadable",
			setup:       isolateCredentialEnv,
			run:         runLogin(pvwaProfile, map[string]string{"credentials-file": "missing.idsecrc"}),
			wantStderr:  "Failed to load credentials file: credentials file \"missing.idsecrc\" does not exist\nidsec: login failed reason=CONFIG_ERROR\n",
			wantCode:    agentmode.CodeConfigError,
			wantDetails: map[string]any{"path": "missing.idsecrc", "source": "credentials_file"},
		},
		{
			name: "secret_env_unreadable",
			setup: func(t *testing.T) {
				isolateCredentialEnv(t)
				t.Setenv("IDSEC_PVWA_SECRET_FILE", "missing-secret")
			},
			run:         runLogin(pvwaProfile, nil),
			wantStderr:  "Failed to resolve pvwa secret: failed to read secret file \"missing-secret\" from IDSEC_PVWA_SECRET_FILE: open missing-secret: no such file or directory\nidsec: login failed reason=CONFIG_ERROR authenticator=pvwa\n",
			wantCode:    agentmode.CodeConfigError,
			wantDetails: map[string]any{"authenticator": "pvwa", "source": "secret_env"},
		},
		{
			name:  "username_required",
			setup: isolateCredentialEnv,
			run: runLogin(func(name string) (*models.IdsecProfile, error) {
				profile, _ := pvwaProfile(name)
				profile.AuthProfiles["pvwa"].Username = ""
				return profile, nil
			}, nil),
			wantStderr: "A username is required to authenticate to Password Vault Web Access when running silently. Provide --pvwa-username, set the IDSEC_PVWA_USERNAME environment variable, or add pvwa_username to an .idsecrc file\nidsec: login failed reason=USERNAME_REQUIRED authenticator=pvwa\n",
			wantCode:   agentmode.CodeUsernameRequired,
			wantDetails: map[string]any{
				"authenticator": "pvwa",
				"missing_flags": []string{"pvwa-username"},
				"env":           []string{"IDSEC_PVWA_USERNAME"},
			},
			wantHints: []string{"pass --pvwa-username, set IDSEC_PVWA_USERNAME, or add pvwa_username to an .idsecrc file"},
		},
		{
			name: "secret_required_with_credentials_file",
			setup: func(t *testing.T) {
				isolateCredentialEnv(t)
				if err := os.WriteFile("my.idsecrc", []byte("[other-profile]\npvwa_secret = x\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			run:        runLogin(pvwaProfile, map[string]string{"credentials-file": "my.idsecrc"}),
			wantStderr: "A secret is required to authenticate to Password Vault Web Access when running silently. Provide --pvwa-secret, set the IDSEC_PVWA_SECRET or IDSEC_PVWA_SECRET_FILE environment variable, or add pvwa_secret to an .idsecrc file\nidsec: login failed reason=SECRET_REQUIRED authenticator=pvwa rc_available=my.idsecrc\n",
			wantCode:   agentmode.CodeSecretRequired,
			wantDetails: map[string]any{
				"authenticator": "pvwa",
				"missing_flags": []string{"pvwa-secret"},
				"env":           []string{"IDSEC_PVWA_SECRET", "IDSEC_PVWA_SECRET_FILE"},
				"rc_available":  "my.idsecrc",
			},
			wantHints: []string{"pass --pvwa-secret, set IDSEC_PVWA_SECRET or IDSEC_PVWA_SECRET_FILE, or add pvwa_secret to an .idsecrc file"},
		},
	})
}

// 8a: the Authenticate failure branch needs a live tenant, so loginFailure's
// reason-to-code mapping is checked directly.
func TestLoginFailure_AuthReasons(t *testing.T) {
	cases := []struct {
		reason string
		want   agentmode.Code
	}{
		{reason: loginReasonAuthFailed, want: agentmode.CodeAuthFailed},
		{reason: "MFA_REQUIRED", want: agentmode.CodeMFARequired},
		{reason: "ENDPOINT_UNREACHABLE", want: agentmode.CodeEndpointUnreachable},
	}
	for _, c := range cases {
		t.Run(c.reason, func(t *testing.T) {
			setResolvedAgentMode(t, true)
			var err error
			stderr := withCapturedStderr(func() {
				err = loginFailure("Failed to authenticate with PVWA: x", c.reason, "pvwa", nil)
			})
			want := "Failed to authenticate with PVWA: x\nidsec: login failed reason=" + c.reason + " authenticator=pvwa\n"
			if stderr != want {
				t.Errorf("stderr = %q, want %q", stderr, want)
			}
			f := failureOf(t, err)
			if f.Code != c.want || f.Message != "Failed to authenticate with PVWA: x" ||
				!reflect.DeepEqual(f.Details, map[string]any{"authenticator": "pvwa"}) {
				t.Errorf("Failure = %q %q %#v", f.Code, f.Message, f.Details)
			}
			if got, want := ClassifyError(err).Hints, defaultHints[c.want]; !reflect.DeepEqual(got, want) {
				t.Errorf("envelope hints = %#v, want %#v", got, want)
			}
		})
	}
}

// A go-ini parse error quotes the offending line, which can hold a secret:
// stderr keeps it as today, the envelope must not carry it.
func TestLoginCredentialsFileParseError_SecretNotInEnvelope(t *testing.T) {
	const secret = "Hunter2-SUPERSECRET"
	run := func(t *testing.T) (err error, stdout, stderr string) {
		isolateCredentialEnv(t)
		chdirTemp(t)
		if werr := os.WriteFile("rc", []byte("isp_secret "+secret+"\n"), 0o600); werr != nil {
			t.Fatal(werr)
		}
		mockLoader := testutils.NewMockProfileLoader()
		mockLoader.LoadProfileFunc = func(name string) (*models.IdsecProfile, error) {
			return testutils.CreateTestProfileWithAuth(name, "pvwa", authmodels.PVWA), nil
		}
		cmd := newSilentLoginCmd("test-profile")
		_ = cmd.Flags().Set("credentials-file", "rc")
		stdout = withCapturedOutput(func() {
			stderr = withCapturedStderr(func() {
				err = NewIdsecLoginAction(mockLoader.AsProfileLoader()).runLoginAction(cmd, nil)
			})
		})
		return err, stdout, stderr
	}
	wantStderr := "Failed to load credentials file: failed to parse credentials file \"rc\": key-value delimiter not found: isp_secret " + secret + "\n\nidsec: login failed reason=CONFIG_ERROR\n"

	t.Run("human", func(t *testing.T) {
		setResolvedAgentMode(t, false)
		err, stdout, stderr := run(t)
		if stderr != wantStderr || stdout != "" {
			t.Errorf("stderr = %q, stdout = %q, want stderr %q", stderr, stdout, wantStderr)
		}
		if !errors.Is(err, ErrActionFailed) {
			t.Errorf("err = %v, want ErrActionFailed", err)
		}
	})
	t.Run("agent", func(t *testing.T) {
		setResolvedAgentMode(t, true)
		err, _, stderr := run(t)
		if stderr != wantStderr {
			t.Errorf("stderr = %q, want %q", stderr, wantStderr)
		}
		var buf bytes.Buffer
		WriteErrorEnvelope(&buf, err)
		if strings.Contains(buf.String(), secret) {
			t.Fatalf("envelope leaks the secret: %s", buf.String())
		}
		want := "{\"status\":\"error\",\"error\":{\"code\":\"CONFIG_ERROR\",\"message\":\"" + credentialsFileMessage +
			"\",\"details\":{\"path\":\"rc\",\"problem\":\"line_format\",\"source\":\"credentials_file\"}}}\n"
		if buf.String() != want {
			t.Errorf("envelope =\n%s\nwant\n%s", buf.String(), want)
		}
	})
}

// 8c
func TestStatusQuiet_ExitCodeOnlyInEveryMode(t *testing.T) {
	t.Setenv("IDSEC_BASIC_KEYRING", "true")
	cases := []struct {
		name     string
		profile  func(string) (*models.IdsecProfile, error)
		wantCode int
	}{
		{name: "profile_missing", profile: func(string) (*models.IdsecProfile, error) { return nil, nil }, wantCode: exitStatusProfileMissing},
		{name: "no_authenticators", profile: func(name string) (*models.IdsecProfile, error) {
			return &models.IdsecProfile{ProfileName: name, AuthProfiles: map[string]*authmodels.IdsecAuthProfile{}}, nil
		}, wantCode: exitStatusNoAuthenticators},
		{name: "not_authenticated", profile: func(name string) (*models.IdsecProfile, error) {
			return testutils.CreateTestProfile(name), nil
		}, wantCode: exitStatusNotAuthenticated},
	}
	for _, c := range cases {
		for _, agent := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/agent=%v", c.name, agent), func(t *testing.T) {
				setResolvedAgentMode(t, agent)
				mock := testutils.NewMockProfileLoader()
				mock.LoadProfileFunc = c.profile
				var err error
				var stderr string
				stdout := withCapturedOutput(func() {
					stderr = withCapturedStderr(func() {
						err = NewIdsecStatusAction(mock.AsProfileLoader()).runStatusAction(newStatusQuietCmd("p"), nil)
					})
				})
				var exitErr *ExitCodeError
				if !errors.As(err, &exitErr) || exitErr.Code != c.wantCode || !exitErr.Quiet || exitErr.Failure != nil {
					t.Fatalf("err = %#v, want quietExit(%d)", err, c.wantCode)
				}
				if stdout != "" || stderr != "" {
					t.Errorf("stdout = %q, stderr = %q, want both empty", stdout, stderr)
				}
			})
		}
	}
}

// 8c: --query still takes precedence over --quiet.
func TestStatusQuiet_QueryFailureIsNotQuiet(t *testing.T) {
	setResolvedAgentMode(t, true)
	mock := testutils.NewMockProfileLoader()
	mock.LoadProfileFunc = func(string) (*models.IdsecProfile, error) { return nil, nil }
	cmd := newStatusQuietCmd("p")
	cmd.Flags().String("query", "", "")
	cmd.Flags().Bool("raw", false, "")
	registerQueryVarFlags(cmd.Flags())
	_ = cmd.Flags().Set("query", ".[")

	err := NewIdsecStatusAction(mock.AsProfileLoader()).runStatusAction(cmd, nil)

	var exitErr *ExitCodeError
	if errors.As(err, &exitErr) {
		t.Fatalf("err = %#v, want the query failure, not an exit code", err)
	}
	f := ClassifyError(err)
	if f.Code != agentmode.CodeInvalidInput || f.Details["kind"] != agentmode.KindInvalidQuery || f.Details["stage"] != "parse" {
		t.Errorf("Failure = %q %#v", f.Code, f.Details)
	}
}

// 8d
func TestQueryActionFailures_AgentCodes(t *testing.T) {
	runQuery := func(path, query string, flags map[string]string) func(t *testing.T) error {
		return func(t *testing.T) error {
			cmd := newQueryCmd(path, query, false)
			for k, v := range flags {
				_ = cmd.Flags().Set(k, v)
			}
			return NewIdsecQueryAction().runQueryAction(cmd, nil)
		}
	}
	writeFile := func(name, content string) func(t *testing.T) {
		return func(t *testing.T) {
			chdirTemp(t)
			if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
				t.Fatalf("write %s: %v", name, err)
			}
		}
	}
	runAgentCommandCases(t, []agentCommandCase{
		{
			name:        "invalid_arg",
			run:         runQuery("", ".", map[string]string{"null-input": "true", "arg": "1x=2"}),
			wantStderr:  "invalid --arg \"1x=2\", expected name=value with a valid variable name\n",
			wantCode:    agentmode.CodeInvalidInput,
			wantDetails: map[string]any{"kind": agentmode.KindInvalidValue, "flag": "arg"},
		},
		{
			name:        "unreadable_file",
			setup:       chdirTemp,
			run:         runQuery("missing.json", ".", nil),
			wantStderr:  "Failed to read \"missing.json\": open missing.json: no such file or directory\n",
			wantCode:    agentmode.CodeInvalidInput,
			wantDetails: map[string]any{"kind": agentmode.KindUnreadableInput, "flag": "path", "input": "file"},
		},
		{
			name:        "invalid_json_file",
			setup:       writeFile("bad.json", "nope"),
			run:         runQuery("bad.json", ".", nil),
			wantStderr:  "Failed to parse \"bad.json\" as JSON: invalid character 'o' in literal null (expecting 'u')\n",
			wantCode:    agentmode.CodeInvalidInput,
			wantDetails: map[string]any{"kind": agentmode.KindInvalidJSON, "flag": "path", "input": "file"},
		},
		{
			name: "invalid_json_stdin",
			run: func(t *testing.T) error {
				var err error
				withStdin(t, "nope", func() { err = runQuery("-", ".", nil)(t) })
				return err
			},
			wantStderr:  "Failed to parse stdin as JSON: invalid character 'o' in literal null (expecting 'u')\n",
			wantCode:    agentmode.CodeInvalidInput,
			wantDetails: map[string]any{"kind": agentmode.KindInvalidJSON, "flag": "path", "input": "stdin"},
		},
		{
			name:        "invalid_query",
			setup:       writeFile("ok.json", "{}"),
			run:         runQuery("ok.json", ".[", nil),
			wantStderr:  "invalid jq query \".[\": unexpected EOF\n",
			wantCode:    agentmode.CodeInvalidInput,
			wantDetails: map[string]any{"kind": agentmode.KindInvalidQuery, "flag": "query", "stage": "parse"},
			wantHints:   []string{hintInvalidQuery},
		},
	})
}

// 8e
func TestProfilesFailures_AgentCodes(t *testing.T) {
	loadErr := func(string) (*models.IdsecProfile, error) { return nil, errors.New("unexpected end of JSON input") }
	loadNil := func(string) (*models.IdsecProfile, error) { return nil, nil }
	show := func(load func(string) (*models.IdsecProfile, error)) func(t *testing.T) error {
		return func(t *testing.T) error {
			mock := testutils.NewMockProfileLoader()
			mock.LoadProfileFunc = load
			return NewIdsecProfilesAction(mock.AsProfileLoader()).runShowAction(newProfileLookupCmd("dev"), nil)
		}
	}
	add := func(path string) func(t *testing.T) error {
		return func(t *testing.T) error {
			mock := testutils.NewMockProfileLoader()
			return NewIdsecProfilesAction(mock.AsProfileLoader()).runAddAction(newAddCmd(path, true), nil)
		}
	}
	writeFile := func(name string, data []byte) func(t *testing.T) {
		return func(t *testing.T) {
			chdirTemp(t)
			if err := os.WriteFile(name, data, 0o600); err != nil {
				t.Fatalf("write %s: %v", name, err)
			}
		}
	}
	profileFile := func(path string) map[string]any {
		return map[string]any{"source": "profile_file", "path": path}
	}
	runAgentCommandCases(t, []agentCommandCase{
		{
			name:        "show_unreadable_profile",
			run:         show(loadErr),
			wantStderr:  "Failed to load profile \"dev\": \"unexpected end of JSON input\"\n",
			wantCode:    agentmode.CodeConfigError,
			wantDetails: map[string]any{"source": "profile", "profile": "dev"},
			wantHints:   []string{hintProfileUnreadable},
		},
		{
			name: "list_unreadable_folder",
			run: func(t *testing.T) error {
				mock := testutils.NewMockProfileLoader()
				mock.LoadAllProfilesFunc = func() ([]*models.IdsecProfile, error) {
					return nil, errors.New("open /x: not a directory")
				}
				return NewIdsecProfilesAction(mock.AsProfileLoader()).runListAction(newListCmd(), nil)
			},
			wantStderr:  "Failed to load profiles: open /x: not a directory\n",
			wantCode:    agentmode.CodeConfigError,
			wantDetails: map[string]any{"source": "profiles_folder"},
			wantHints:   []string{hintProfilesFolderUnreadable},
		},
		{
			name:        "show_missing_profile",
			run:         show(loadNil),
			wantStderr:  "No profile was found for the name \"dev\"\n",
			wantCode:    agentmode.CodeProfileNotFound,
			wantDetails: map[string]any{"profile": "dev"},
			wantHints:   []string{hintProfilesList, hintProfileCreate},
		},
		{
			name:        "add_missing_path",
			setup:       chdirTemp,
			run:         add("missing.json"),
			wantStderr:  "Profile path [missing.json] does not exist, aborting\n",
			wantCode:    agentmode.CodeConfigError,
			wantDetails: profileFile("missing.json"),
		},
		{
			name: "add_not_regular_file",
			setup: func(t *testing.T) {
				chdirTemp(t)
				if err := os.Mkdir("dir.json", 0o700); err != nil {
					t.Fatal(err)
				}
			},
			run:         add("dir.json"),
			wantStderr:  "Profile path [dir.json] is not a regular file, aborting\n",
			wantCode:    agentmode.CodeConfigError,
			wantDetails: profileFile("dir.json"),
		},
		{
			name:        "add_unparsable",
			setup:       writeFile("bad.json", []byte("{")),
			run:         add("bad.json"),
			wantStderr:  "Profile path [bad.json] failed to be parsed, aborting\n",
			wantCode:    agentmode.CodeConfigError,
			wantDetails: profileFile("bad.json"),
		},
		{
			name:        "add_invalid_name",
			setup:       writeFile("name.json", []byte(`{"profile_name":"../x"}`)),
			run:         add("name.json"),
			wantStderr:  "Profile path [name.json] has invalid profile_name \"../x\": must be a non-empty name without path separators\n",
			wantCode:    agentmode.CodeConfigError,
			wantDetails: profileFile("name.json"),
		},
		{
			name:        "add_invalid_profile",
			setup:       writeFile("invalid.json", []byte(`{"profile_name":"noauth"}`)),
			run:         add("invalid.json"),
			wantStderr:  "Profile path [invalid.json] contains an invalid profile: \"profile must have at least one auth profile configured\"\n",
			wantCode:    agentmode.CodeConfigError,
			wantDetails: profileFile("invalid.json"),
		},
		{
			name:  "edit_requires_interactive",
			setup: withSilentMode,
			run: func(t *testing.T) error {
				root := &cobra.Command{Use: "idsec"}
				profilesCmd := &cobra.Command{Use: "profiles"}
				edit := &cobra.Command{Use: "edit"}
				profilesCmd.AddCommand(edit)
				root.AddCommand(profilesCmd)
				return NewIdsecProfilesAction(testutils.NewMockProfileLoader().AsProfileLoader()).runEditAction(edit, nil)
			},
			wantStderr:  "profiles edit requires an interactive terminal; use `idsec profiles add --profile-path <file>` or `idsec configure` flags instead\nidsec: interactive_required\n",
			wantCode:    agentmode.CodeInteractiveRequired,
			wantDetails: map[string]any{"command": "idsec profiles edit"},
			wantHints:   []string{hintProfilesEditAlternative},
		},
	})
}

// 8f
func TestConfigureDryRunFailures_AgentCodes(t *testing.T) {
	configure := func(save func(*models.IdsecProfile) error, flags map[string]string) func(t *testing.T) error {
		return func(t *testing.T) error {
			mock := testutils.NewMockProfileLoader()
			mock.LoadProfileFunc = func(string) (*models.IdsecProfile, error) { return nil, nil }
			if save != nil {
				mock.SaveProfileFunc = save
			}
			cmd := newConfigureCmd("cfg")
			for k, v := range flags {
				_ = cmd.Flags().Set(k, v)
			}
			return NewIdsecConfigureAction(mock.AsProfileLoader()).runConfigureCommand(cmd, nil)
		}
	}
	stage := func(s string) map[string]any { return map[string]any{"source": "configure", "stage": s} }
	runAgentCommandCases(t, []agentCommandCase{
		{
			name:        "invalid_arg",
			setup:       withSilentMode,
			run:         configure(nil, map[string]string{"query": ".", "arg": "not-a-pair"}),
			wantStderr:  "invalid --arg \"not-a-pair\", expected name=value with a valid variable name\n",
			wantCode:    agentmode.CodeInvalidInput,
			wantDetails: map[string]any{"kind": agentmode.KindInvalidValue, "flag": "arg"},
		},
		{
			name:        "build",
			setup:       withSilentMode,
			run:         configure(nil, map[string]string{"dry-run": "true", "isp-username": ""}),
			wantStderr:  "Dry run: failed to build profile: missing username for authenticator [Identity Security Platform]\n",
			wantCode:    agentmode.CodeConfigError,
			wantDetails: stage("build"),
		},
		{
			name:        "validate",
			setup:       withSilentMode,
			run:         configure(nil, map[string]string{"dry-run": "true", "work-with-isp": "false"}),
			wantStderr:  "Dry run: profile is invalid: profile must have at least one auth profile configured\n",
			wantCode:    agentmode.CodeConfigError,
			wantDetails: stage("validate"),
		},
		{
			name:        "save",
			setup:       withSilentMode,
			run:         configure(func(*models.IdsecProfile) error { return errors.New("disk full") }, map[string]string{"query": "."}),
			wantStderr:  "Failed to save profile: disk full\n",
			wantCode:    agentmode.CodeConfigError,
			wantDetails: stage("save"),
		},
	})
}

// 8f/8g: build errors that are MissingRequiredInputError keep their own code.
func TestConfigureFailure_MissingRequiredInput(t *testing.T) {
	setResolvedAgentMode(t, true)
	var err error
	stderr := withCapturedStderr(func() {
		err = configureFailure(configureStageBuild, "failed to build profile: x", fmt.Errorf("wrapped: %w", commonargs.NewMissingRequiredInputError("isp-username")))
	})
	if stderr != "failed to build profile: x\n" {
		t.Errorf("stderr = %q", stderr)
	}
	f := failureOf(t, err)
	if f.Code != agentmode.CodeMissingRequiredInput || !reflect.DeepEqual(f.Details, map[string]any{"missing_flags": []string{"isp-username"}}) {
		t.Errorf("Failure = %q %#v", f.Code, f.Details)
	}
}

// 8g: the plain path keeps its human behavior (panic on build/validate
// errors, exit 0 on save errors) and reports a Failure in agent mode.
func TestConfigurePlainFailures_AgentCodes(t *testing.T) {
	configure := func(save func(*models.IdsecProfile) error, flags map[string]string) func(t *testing.T) error {
		return func(t *testing.T) (err error) {
			mock := testutils.NewMockProfileLoader()
			mock.LoadProfileFunc = func(string) (*models.IdsecProfile, error) { return nil, nil }
			if save != nil {
				mock.SaveProfileFunc = save
			}
			cmd := newConfigureCmd("cfg")
			for k, v := range flags {
				_ = cmd.Flags().Set(k, v)
			}
			defer func() {
				if r := recover(); r != nil {
					err = &panicked{value: r}
				}
			}()
			return NewIdsecConfigureAction(mock.AsProfileLoader()).runConfigureCommand(cmd, nil)
		}
	}
	wantPanic := func(t *testing.T, err error) {
		var p *panicked
		if !errors.As(err, &p) {
			t.Errorf("human err = %v, want the existing panic", err)
		}
	}
	wantNil := func(t *testing.T, err error) {
		if err != nil {
			t.Errorf("human err = %v, want nil (exit 0)", err)
		}
	}
	stage := func(s string) map[string]any { return map[string]any{"source": "configure", "stage": s} }
	runAgentCommandCases(t, []agentCommandCase{
		{
			name:        "build",
			setup:       withSilentMode,
			run:         configure(nil, map[string]string{"isp-username": ""}),
			wantStderr:  "",
			humanErr:    wantPanic,
			wantCode:    agentmode.CodeConfigError,
			wantDetails: stage("build"),
			agentStderr: strPtr("failed to build profile: missing username for authenticator [Identity Security Platform]\n"),
		},
		{
			name:        "validate",
			setup:       withSilentMode,
			run:         configure(nil, map[string]string{"work-with-isp": "false"}),
			wantStderr:  "",
			humanErr:    wantPanic,
			wantCode:    agentmode.CodeConfigError,
			wantDetails: stage("validate"),
			agentStderr: strPtr("profile is invalid: profile must have at least one auth profile configured\n"),
		},
		{
			name:        "save",
			setup:       withSilentMode,
			run:         configure(func(*models.IdsecProfile) error { return errors.New("disk full") }, nil),
			wantStderr:  "",
			humanErr:    wantNil,
			wantCode:    agentmode.CodeConfigError,
			wantDetails: stage("save"),
			agentStderr: strPtr("Failed to save profile: disk full\n"),
		},
	})
}

type panicked struct{ value any }

func (p *panicked) Error() string { return fmt.Sprintf("panic: %v", p.value) }

// 8h
func TestCacheClearFailures_AgentCodes(t *testing.T) {
	stub := func(resolveErr, clearErr error) func(t *testing.T) {
		return func(t *testing.T) {
			original := resolveCacheKeyring
			t.Cleanup(func() { resolveCacheKeyring = original })
			resolveCacheKeyring = func() (keyring.IdsecKeyringImpl, error) {
				if resolveErr != nil {
					return nil, resolveErr
				}
				return &stubKeyring{clearErr: clearErr}, nil
			}
		}
	}
	run := func(t *testing.T) error { return NewIdsecCacheAction().runClearCacheAction(&cobra.Command{}, nil) }
	wantText := func(text string) func(t *testing.T, err error) {
		return func(t *testing.T, err error) {
			if err == nil || err.Error() != text {
				t.Errorf("human err = %v, want text %q", err, text)
			}
		}
	}
	runAgentCommandCases(t, []agentCommandCase{
		{
			name:     "open",
			setup:    stub(errors.New("locked"), nil),
			run:      run,
			humanErr: wantText("failed to open credential cache: locked"),
			wantCode: agentmode.CodeKeyringFailure,
		},
		{
			name:     "clear",
			setup:    stub(nil, errors.New("denied")),
			run:      run,
			humanErr: wantText("failed to clear credential cache: denied"),
			wantCode: agentmode.CodeKeyringFailure,
		},
	})
}
