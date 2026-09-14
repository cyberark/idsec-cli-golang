package actions

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/cyberark/idsec-cli-golang/pkg/actions/testutils"
	"github.com/cyberark/idsec-sdk-golang/pkg/models"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/profiles"
)

func TestNewIdsecStatusAction(t *testing.T) {
	tests := []struct {
		name           string
		profilesLoader *profiles.ProfileLoader
		validateFunc   func(t *testing.T, action *IdsecStatusAction)
	}{
		{
			name:           "success_normal_profile_loader",
			profilesLoader: testutils.NewMockProfileLoader().AsProfileLoader(),
			validateFunc: func(t *testing.T, action *IdsecStatusAction) {
				if action.IdsecBaseAction == nil {
					t.Error("Expected IdsecBaseAction to be initialized")
				}
				if action.profilesLoader == nil {
					t.Error("Expected profilesLoader to be set")
				}
			},
		},
		{
			name:           "success_nil_profile_loader",
			profilesLoader: nil,
			validateFunc: func(t *testing.T, action *IdsecStatusAction) {
				if action.IdsecBaseAction == nil {
					t.Error("Expected IdsecBaseAction to be initialized")
				}
				if action.profilesLoader != nil {
					t.Error("Expected profilesLoader to remain nil")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			action := NewIdsecStatusAction(tt.profilesLoader)
			if action == nil {
				t.Fatal("Expected non-nil action")
			}
			if tt.validateFunc != nil {
				tt.validateFunc(t, action)
			}
		})
	}
}

func TestIdsecStatusAction_DefineAction(t *testing.T) {
	t.Parallel()

	action := NewIdsecStatusAction(testutils.NewMockProfileLoader().AsProfileLoader())
	rootCmd := &cobra.Command{Use: "idsec"}
	action.DefineAction(rootCmd)

	statusCmd, _, err := rootCmd.Find([]string{"status"})
	if err != nil {
		t.Fatalf("Expected to find status command, got error: %v", err)
	}
	if statusCmd == nil || statusCmd.Use != "status" {
		t.Fatalf("Expected a 'status' command to be added, got %+v", statusCmd)
	}
	if statusCmd.Short == "" {
		t.Error("Expected a short description on the status command")
	}
	if statusCmd.RunE == nil {
		t.Error("Expected the status command to have a RunE function")
	}
	if statusCmd.PersistentPreRun == nil {
		t.Error("Expected the status command to have a PersistentPreRun function")
	}

	for _, flagName := range []string{"profile-name", "json", "quiet"} {
		if statusCmd.Flags().Lookup(flagName) == nil {
			t.Errorf("Expected flag '%s' to be defined on the status command", flagName)
		}
	}
}

func TestIdsecStatusAction_IdsecActionInterface(t *testing.T) {
	t.Parallel()

	action := NewIdsecStatusAction(testutils.NewMockProfileLoader().AsProfileLoader())

	// Compile-time assertion that the action satisfies the IdsecAction interface.
	var _ IdsecAction = action

	rootCmd := &cobra.Command{Use: "idsec"}
	action.DefineAction(rootCmd)
	if _, _, err := rootCmd.Find([]string{"status"}); err != nil {
		t.Errorf("Expected status command to be registered, got error: %v", err)
	}
}

func TestIdsecStatusAction_StructFields(t *testing.T) {
	t.Parallel()

	action := NewIdsecStatusAction(testutils.NewMockProfileLoader().AsProfileLoader())
	actionType := reflect.ValueOf(action).Elem().Type()

	expectedFields := []string{"IdsecBaseAction", "profilesLoader"}
	for _, expected := range expectedFields {
		if _, ok := actionType.FieldByName(expected); !ok {
			t.Errorf("Expected field '%s' not found in struct", expected)
		}
	}
}

func TestFormatTimeLeft(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		duration time.Duration
		expected string
	}{
		{name: "negative_is_expired", duration: -5 * time.Second, expected: "expired"},
		{name: "zero_is_expired", duration: 0, expected: "expired"},
		{name: "seconds_only", duration: 30 * time.Second, expected: "30s"},
		{name: "minutes_and_seconds", duration: 90 * time.Second, expected: "1m30s"},
		{name: "hours_minutes_seconds", duration: time.Hour + time.Minute + time.Second, expected: "1h1m1s"},
		{name: "rounds_to_nearest_second", duration: 1400 * time.Millisecond, expected: "1s"},
		{name: "rounds_up_to_nearest_second", duration: 1600 * time.Millisecond, expected: "2s"},
		{name: "hours_with_zero_minutes", duration: 2 * time.Hour, expected: "2h0m0s"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := formatTimeLeft(tt.duration); got != tt.expected {
				t.Errorf("formatTimeLeft(%v) = %q, want %q", tt.duration, got, tt.expected)
			}
		})
	}
}

func TestIdsecStatusAction_runStatusAction_ProfileNotFound(t *testing.T) {
	mock := testutils.NewMockProfileLoader()
	mock.LoadProfileFunc = func(string) (*models.IdsecProfile, error) {
		return nil, nil
	}
	action := NewIdsecStatusAction(mock.AsProfileLoader())

	cmd := &cobra.Command{}
	cmd.Flags().String("profile-name", "", "")
	cmd.Flags().Bool("json", false, "")
	_ = cmd.Flags().Set("profile-name", "missing-profile")

	output := withCapturedOutput(func() {
		action.runStatusAction(cmd, []string{})
	})

	if !strings.Contains(output, "missing-profile") {
		t.Errorf("Expected warning to mention the profile name, got %q", output)
	}
	if !strings.Contains(output, "idsec configure") {
		t.Errorf("Expected warning to suggest 'idsec configure', got %q", output)
	}
}

func TestIdsecStatusAction_runStatusAction_ProfileNotFoundJSON(t *testing.T) {
	mock := testutils.NewMockProfileLoader()
	mock.LoadProfileFunc = func(string) (*models.IdsecProfile, error) {
		return nil, nil
	}
	action := NewIdsecStatusAction(mock.AsProfileLoader())

	cmd := &cobra.Command{}
	cmd.Flags().String("profile-name", "", "")
	cmd.Flags().Bool("json", false, "")
	_ = cmd.Flags().Set("profile-name", "missing-profile")
	_ = cmd.Flags().Set("json", "true")

	output := withCapturedOutput(func() {
		action.runStatusAction(cmd, []string{})
	})

	var status profileStatus
	if err := json.Unmarshal([]byte(output), &status); err != nil {
		t.Fatalf("Expected valid JSON output, got error %v for output %q", err, output)
	}
	if status.Profile != "missing-profile" {
		t.Errorf("Expected profile 'missing-profile', got %q", status.Profile)
	}
	if status.Authenticated {
		t.Error("Expected authenticated=false for a missing profile")
	}
	if len(status.Authenticators) != 0 {
		t.Errorf("Expected no authenticators, got %d", len(status.Authenticators))
	}
}

func TestIdsecStatusAction_runStatusAction_LoadError(t *testing.T) {
	mock := testutils.NewMockProfileLoader()
	mock.LoadProfileFunc = func(string) (*models.IdsecProfile, error) {
		return nil, fmt.Errorf("boom")
	}
	action := NewIdsecStatusAction(mock.AsProfileLoader())

	cmd := &cobra.Command{}
	cmd.Flags().String("profile-name", "", "")
	cmd.Flags().Bool("json", false, "")
	_ = cmd.Flags().Set("profile-name", "broken")

	output := withCapturedOutput(func() {
		action.runStatusAction(cmd, []string{})
	})

	if !strings.Contains(output, "broken") {
		t.Errorf("Expected warning to mention the profile name on load error, got %q", output)
	}
}

func TestIdsecStatusAction_runStatusAction_EmptyAuthProfiles(t *testing.T) {
	mock := testutils.NewMockProfileLoader()
	mock.LoadProfileFunc = func(name string) (*models.IdsecProfile, error) {
		return &models.IdsecProfile{
			ProfileName:  name,
			AuthProfiles: map[string]*authmodels.IdsecAuthProfile{},
		}, nil
	}
	action := NewIdsecStatusAction(mock.AsProfileLoader())

	cmd := &cobra.Command{}
	cmd.Flags().String("profile-name", "", "")
	cmd.Flags().Bool("json", false, "")
	_ = cmd.Flags().Set("profile-name", "empty")

	output := withCapturedOutput(func() {
		action.runStatusAction(cmd, []string{})
	})

	if !strings.Contains(output, "empty") {
		t.Errorf("Expected the profile name in the output, got %q", output)
	}
	if !strings.Contains(output, "No authenticators") {
		t.Errorf("Expected a 'No authenticators' message, got %q", output)
	}
}

func TestIdsecStatusAction_runStatusAction_UnknownAuthenticatorJSON(t *testing.T) {
	mock := testutils.NewMockProfileLoader()
	mock.LoadProfileFunc = func(name string) (*models.IdsecProfile, error) {
		return &models.IdsecProfile{
			ProfileName: name,
			AuthProfiles: map[string]*authmodels.IdsecAuthProfile{
				"bogus": {
					Username:   "someone",
					AuthMethod: authmodels.Identity,
				},
			},
		}, nil
	}
	action := NewIdsecStatusAction(mock.AsProfileLoader())

	cmd := &cobra.Command{}
	cmd.Flags().String("profile-name", "", "")
	cmd.Flags().Bool("json", false, "")
	_ = cmd.Flags().Set("profile-name", "unknown-auth")
	_ = cmd.Flags().Set("json", "true")

	output := withCapturedOutput(func() {
		action.runStatusAction(cmd, []string{})
	})

	var status profileStatus
	if err := json.Unmarshal([]byte(output), &status); err != nil {
		t.Fatalf("Expected valid JSON output, got error %v for output %q", err, output)
	}
	if status.Authenticated {
		t.Error("Expected authenticated=false when an authenticator is unknown")
	}
	if len(status.Authenticators) != 1 {
		t.Fatalf("Expected exactly one authenticator entry, got %d", len(status.Authenticators))
	}
	entry := status.Authenticators[0]
	if entry.Authenticator != "bogus" {
		t.Errorf("Expected authenticator 'bogus', got %q", entry.Authenticator)
	}
	if entry.Authenticated {
		t.Error("Expected the unknown authenticator to report not authenticated")
	}
	if entry.Username != "someone" {
		t.Errorf("Expected username 'someone', got %q", entry.Username)
	}
}

// TestIdsecStatusAction_runStatusAction_KnownAuthenticatorDoesNotPanic exercises the real
// SDK authenticator path (isp) for a profile that has no cached token. In a test environment
// IsAuthenticated returns false without any network call, so the command must simply report
// "not authenticated" without panicking.
func TestIdsecStatusAction_runStatusAction_KnownAuthenticatorDoesNotPanic(t *testing.T) {
	cleanup := testutils.SetEnvVar("IDSEC_BASIC_KEYRING", "true")
	defer cleanup()

	mock := testutils.NewMockProfileLoader()
	mock.LoadProfileFunc = func(name string) (*models.IdsecProfile, error) {
		return testutils.CreateTestProfile(name), nil
	}
	action := NewIdsecStatusAction(mock.AsProfileLoader())

	cmd := &cobra.Command{}
	cmd.Flags().String("profile-name", "", "")
	cmd.Flags().Bool("json", false, "")
	_ = cmd.Flags().Set("profile-name", "with-isp")
	_ = cmd.Flags().Set("json", "true")

	output := withCapturedOutput(func() {
		action.runStatusAction(cmd, []string{})
	})

	var status profileStatus
	if err := json.Unmarshal([]byte(output), &status); err != nil {
		t.Fatalf("Expected valid JSON output, got error %v for output %q", err, output)
	}
	if len(status.Authenticators) != 1 || status.Authenticators[0].Authenticator != "isp" {
		t.Fatalf("Expected a single 'isp' authenticator entry, got %+v", status.Authenticators)
	}
	if status.Authenticators[0].Authenticated {
		t.Error("Expected 'isp' to report not authenticated without a cached token")
	}
	if status.Authenticated {
		t.Error("Expected the profile to report not authenticated overall")
	}
}

func TestStatusQuietExitCode(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name            string
		authenticated   bool
		noAuthenticator bool
		hasNoToken      bool
		hasExpired      bool
		want            int
	}{
		{name: "authenticated", authenticated: true, want: 0},
		{name: "no_authenticators", noAuthenticator: true, want: exitStatusNoAuthenticators},
		{name: "no_token", hasNoToken: true, want: exitStatusNotAuthenticated},
		{name: "expired", hasExpired: true, want: exitStatusTokenExpired},
		{name: "none_defaults_to_not_authenticated", want: exitStatusNotAuthenticated},
		{name: "no_token_beats_expired", hasNoToken: true, hasExpired: true, want: exitStatusNotAuthenticated},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got := statusQuietExitCode(c.authenticated, c.noAuthenticator, c.hasNoToken, c.hasExpired)
			if got != c.want {
				t.Errorf("statusQuietExitCode(%v,%v,%v,%v) = %d, want %d",
					c.authenticated, c.noAuthenticator, c.hasNoToken, c.hasExpired, got, c.want)
			}
		})
	}
}

func newStatusQuietCmd(profileName string) *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String("profile-name", "", "")
	cmd.Flags().Bool("json", false, "")
	cmd.Flags().Bool("quiet", false, "")
	_ = cmd.Flags().Set("profile-name", profileName)
	_ = cmd.Flags().Set("quiet", "true")
	return cmd
}

// TestRunStatusActionQuietExitCodes verifies the granular --quiet exit codes
// that let scripts branch on auth state without parsing JSON.
func TestRunStatusActionQuietExitCodes(t *testing.T) {
	cleanup := testutils.SetEnvVar("IDSEC_BASIC_KEYRING", "true")
	defer cleanup()

	cases := []struct {
		name     string
		profile  func(string) (*models.IdsecProfile, error)
		wantCode int
	}{
		{
			name:     "profile_missing",
			profile:  func(string) (*models.IdsecProfile, error) { return nil, nil },
			wantCode: exitStatusProfileMissing,
		},
		{
			name: "no_authenticators",
			profile: func(name string) (*models.IdsecProfile, error) {
				return &models.IdsecProfile{ProfileName: name, AuthProfiles: map[string]*authmodels.IdsecAuthProfile{}}, nil
			},
			wantCode: exitStatusNoAuthenticators,
		},
		{
			name: "not_authenticated_no_token",
			profile: func(name string) (*models.IdsecProfile, error) {
				return testutils.CreateTestProfile(name), nil
			},
			wantCode: exitStatusNotAuthenticated,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mock := testutils.NewMockProfileLoader()
			mock.LoadProfileFunc = c.profile
			action := NewIdsecStatusAction(mock.AsProfileLoader())

			err := action.runStatusAction(newStatusQuietCmd("p"), []string{})

			var exitErr *ExitCodeError
			if !errors.As(err, &exitErr) {
				t.Fatalf("expected *ExitCodeError, got %v", err)
			}
			if exitErr.Code != c.wantCode {
				t.Errorf("expected exit code %d, got %d", c.wantCode, exitErr.Code)
			}
		})
	}
}

// newStatusQueryCmd builds a status command carrying the flags runStatusAction
// reads, with a --query set.
func newStatusQueryCmd(profileName, query string, raw bool) *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String("profile-name", "", "")
	cmd.Flags().Bool("json", false, "")
	cmd.Flags().Bool("quiet", false, "")
	cmd.Flags().String("query", "", "")
	cmd.Flags().Bool("raw", false, "")
	_ = cmd.Flags().Set("profile-name", profileName)
	_ = cmd.Flags().Set("query", query)
	if raw {
		_ = cmd.Flags().Set("raw", "true")
	}
	return cmd
}

// TestIdsecStatusAction_runStatusAction_Query verifies --query is applied to the
// status document, and that it takes precedence over --quiet and works on the
// profile-not-found document too.
func TestIdsecStatusAction_runStatusAction_Query(t *testing.T) {
	t.Run("existing_profile_raw_name", func(t *testing.T) {
		mock := testutils.NewMockProfileLoader()
		mock.LoadProfileFunc = func(name string) (*models.IdsecProfile, error) {
			return &models.IdsecProfile{ProfileName: name, AuthProfiles: map[string]*authmodels.IdsecAuthProfile{}}, nil
		}
		action := NewIdsecStatusAction(mock.AsProfileLoader())

		var err error
		out := withCapturedOutput(func() {
			err = action.runStatusAction(newStatusQueryCmd("prod", ".profile", true), []string{})
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := strings.TrimSpace(out); got != "prod" {
			t.Errorf("expected raw 'prod', got %q", got)
		}
	})

	t.Run("missing_profile_exists_false", func(t *testing.T) {
		mock := testutils.NewMockProfileLoader()
		mock.LoadProfileFunc = func(string) (*models.IdsecProfile, error) { return nil, nil }
		action := NewIdsecStatusAction(mock.AsProfileLoader())

		var err error
		out := withCapturedOutput(func() {
			err = action.runStatusAction(newStatusQueryCmd("missing", ".exists", false), []string{})
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := strings.TrimSpace(out); got != "false" {
			t.Errorf("expected 'false' for a missing profile, got %q", got)
		}
	})
}

func TestIdsecStatusAction_printHumanReadable(t *testing.T) {
	action := NewIdsecStatusAction(testutils.NewMockProfileLoader().AsProfileLoader())

	tests := []struct {
		name        string
		status      profileStatus
		wantContain []string
		wantAbsent  []string
	}{
		{
			name: "authenticated_with_expiry",
			status: profileStatus{
				Profile:       "prod",
				Authenticated: true,
				Authenticators: []authenticatorStatus{
					{
						Authenticator: "isp",
						Name:          "Identity Security Platform",
						Username:      "user@example.com",
						Authenticated: true,
						Endpoint:      "https://tenant.example.com",
						ExpiresAt:     "2030-01-01T00:00:00Z",
						TimeLeft:      "1h0m0s",
					},
				},
			},
			wantContain: []string{
				"Profile: prod",
				"Authenticated as user@example.com",
				"Endpoint: https://tenant.example.com",
				"Expires:",
				"1h0m0s left",
			},
		},
		{
			name: "expired_token",
			status: profileStatus{
				Profile:       "prod",
				Authenticated: false,
				Authenticators: []authenticatorStatus{
					{
						Authenticator: "isp",
						Name:          "Identity Security Platform",
						Authenticated: true,
						Expired:       true,
					},
				},
			},
			wantContain: []string{"Token Expired", "idsec login"},
		},
		{
			name: "not_authenticated",
			status: profileStatus{
				Profile:       "prod",
				Authenticated: false,
				Authenticators: []authenticatorStatus{
					{
						Authenticator: "pvwa",
						Name:          "Password Vault Web Access",
						Authenticated: false,
					},
				},
			},
			wantContain: []string{"Not Authenticated", "idsec login"},
		},
		{
			name: "no_authenticators",
			status: profileStatus{
				Profile:        "prod",
				Authenticated:  false,
				Authenticators: []authenticatorStatus{},
			},
			wantContain: []string{"No authenticators"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := withCapturedOutput(func() {
				action.printHumanReadable(tt.status)
			})
			for _, want := range tt.wantContain {
				if !strings.Contains(output, want) {
					t.Errorf("Expected output to contain %q, got %q", want, output)
				}
			}
			for _, absent := range tt.wantAbsent {
				if strings.Contains(output, absent) {
					t.Errorf("Expected output NOT to contain %q, got %q", absent, output)
				}
			}
		})
	}
}
