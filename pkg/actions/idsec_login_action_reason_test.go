package actions

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/cyberark/idsec-cli-golang/pkg/actions/testutils"
	"github.com/cyberark/idsec-sdk-golang/pkg/models"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
)

// captureLoginRun runs runLoginAction with stdout and stderr captured, so tests
// can assert both the human message (stdout) and the machine-readable reason
// line (stderr).
func captureLoginRun(t *testing.T, action *IdsecLoginAction, cmd *cobra.Command) (stdout, stderr string, runErr error) {
	t.Helper()
	origOut, origErr := os.Stdout, os.Stderr
	rOut, wOut, _ := os.Pipe()
	rErr, wErr, _ := os.Pipe()
	os.Stdout, os.Stderr = wOut, wErr

	runErr = action.runLoginAction(cmd, []string{})

	_ = wOut.Close()
	_ = wErr.Close()
	os.Stdout, os.Stderr = origOut, origErr

	var bo, be bytes.Buffer
	_, _ = bo.ReadFrom(rOut)
	_, _ = be.ReadFrom(rErr)
	return bo.String(), be.String(), runErr
}

// writeDiscoverableRC writes an .idsecrc into the current directory, which
// isolateCredentialEnv has already pointed at a temp dir, so credential
// auto-discovery finds it.
func writeDiscoverableRC(t *testing.T, contents string) {
	t.Helper()
	if err := os.WriteFile(".idsecrc", []byte(contents), 0o600); err != nil {
		t.Fatalf("failed to write .idsecrc: %v", err)
	}
}

// TestRunLoginActionSilentReasonLines verifies that deterministic pre-flight
// failures emit a stable, greppable machine-readable reason line on stderr and
// exit non-zero (code 1), so consumers do not have to classify prose.
func TestRunLoginActionSilentReasonLines(t *testing.T) {
	// A profile whose single pvwa authenticator has no username configured, so
	// the silent username check is what fails first.
	profileWithoutUsername := func(name string) (*models.IdsecProfile, error) {
		profile := testutils.CreateTestProfileWithAuth(name, "pvwa", authmodels.PVWA)
		profile.AuthProfiles["pvwa"].Username = ""
		return profile, nil
	}

	cases := []struct {
		name        string
		setup       func(*testing.T)
		profileFunc func(string) (*models.IdsecProfile, error)
		wantReason  string
		wantAuth    string
		wantFields  []string
		notFields   []string
	}{
		{
			name: "missing_secret",
			profileFunc: func(name string) (*models.IdsecProfile, error) {
				return testutils.CreateTestProfileWithAuth(name, "pvwa", authmodels.PVWA), nil
			},
			wantReason: "SECRET_REQUIRED",
			wantAuth:   "pvwa",
			// No credentials file was discovered, so no rc_available field.
			notFields: []string{"rc_available="},
		},
		{
			name: "missing_secret_with_credentials_file",
			setup: func(t *testing.T) {
				writeDiscoverableRC(t, "[other-profile]\npvwa_secret = x\n")
			},
			profileFunc: func(name string) (*models.IdsecProfile, error) {
				return testutils.CreateTestProfileWithAuth(name, "pvwa", authmodels.PVWA), nil
			},
			wantReason: "SECRET_REQUIRED",
			wantAuth:   "pvwa",
			// A file was loaded but holds nothing for this profile, which
			// rc_available lets a script tell apart from "no file at all".
			wantFields: []string{"rc_available="},
		},
		{
			name:        "missing_username",
			profileFunc: profileWithoutUsername,
			wantReason:  "USERNAME_REQUIRED",
			wantAuth:    "pvwa",
		},
		{
			name: "unreadable_secret_file",
			setup: func(t *testing.T) {
				t.Setenv("IDSEC_PVWA_SECRET_FILE", filepath.Join(t.TempDir(), "missing-secret"))
			},
			profileFunc: func(name string) (*models.IdsecProfile, error) {
				return testutils.CreateTestProfileWithAuth(name, "pvwa", authmodels.PVWA), nil
			},
			wantReason: "CONFIG_ERROR",
			wantAuth:   "pvwa",
		},
		{
			name: "profile_not_found",
			profileFunc: func(string) (*models.IdsecProfile, error) {
				return nil, errors.New("no profile found")
			},
			wantReason: "PROFILE_NOT_FOUND",
			wantAuth:   "",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			isolateCredentialEnv(t)
			if c.setup != nil {
				c.setup(t)
			}
			mockLoader := testutils.NewMockProfileLoader()
			mockLoader.LoadProfileFunc = c.profileFunc
			action := NewIdsecLoginAction(mockLoader.AsProfileLoader())
			cmd := newSilentLoginCmd("test-profile")

			_, stderr, runErr := captureLoginRun(t, action, cmd)

			var exitErr *ExitCodeError
			if !errors.As(runErr, &exitErr) {
				t.Fatalf("expected *ExitCodeError, got %v", runErr)
			}
			if exitErr.Code != 1 {
				t.Errorf("expected exit code 1, got %d", exitErr.Code)
			}
			if want := "reason=" + c.wantReason; !strings.Contains(stderr, want) {
				t.Errorf("expected stderr to contain %q, got:\n%s", want, stderr)
			}
			if c.wantAuth != "" {
				if want := "authenticator=" + c.wantAuth; !strings.Contains(stderr, want) {
					t.Errorf("expected stderr to contain %q, got:\n%s", want, stderr)
				}
			}
			for _, want := range c.wantFields {
				if !strings.Contains(stderr, want) {
					t.Errorf("expected stderr to contain %q, got:\n%s", want, stderr)
				}
			}
			for _, unwanted := range c.notFields {
				if strings.Contains(stderr, unwanted) {
					t.Errorf("expected stderr not to contain %q, got:\n%s", unwanted, stderr)
				}
			}
		})
	}
}
