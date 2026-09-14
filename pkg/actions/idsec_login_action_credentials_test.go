package actions

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/cyberark/idsec-cli-golang/pkg/actions/testutils"
	"github.com/cyberark/idsec-cli-golang/pkg/credentials"
	"github.com/cyberark/idsec-sdk-golang/pkg/models"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
)

func TestFirstNonEmpty(t *testing.T) {
	cases := []struct {
		name   string
		values []string
		want   string
	}{
		{"all empty", []string{"", "", ""}, ""},
		{"first wins", []string{"a", "b"}, "a"},
		{"skips empty", []string{"", "", "c"}, "c"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := firstNonEmpty(c.values...); got != c.want {
				t.Errorf("firstNonEmpty(%v) = %q, want %q", c.values, got, c.want)
			}
		})
	}
}

func TestFirstNonEmptyWithSource(t *testing.T) {
	value, source := firstNonEmptyWithSource(
		credSource{"", credSourceFlag},
		credSource{"from-env", credSourceEnv},
		credSource{"from-file", credSourceFile},
	)
	if value != "from-env" || source != credSourceEnv {
		t.Errorf("expected (from-env, env), got (%q, %v)", value, source)
	}

	value, source = firstNonEmptyWithSource(
		credSource{"", credSourceFlag},
		credSource{"", credSourceEnv},
		credSource{"", credSourceFile},
	)
	if value != "" || source != credSourceNone {
		t.Errorf("expected empty/none, got (%q, %v)", value, source)
	}

	value, source = firstNonEmptyWithSource(
		credSource{"flagval", credSourceFlag},
		credSource{"envval", credSourceEnv},
	)
	if value != "flagval" || source != credSourceFlag {
		t.Errorf("expected (flagval, flag), got (%q, %v)", value, source)
	}
}

func TestAnnotateSecretPrompt(t *testing.T) {
	base := "ISP Secret"

	if got := annotateSecretPrompt(base, credSourceNone, "isp", nil); got != base {
		t.Errorf("none source should not annotate, got %q", got)
	}
	if got := annotateSecretPrompt(base, credSourceFlag, "isp", nil); got != base {
		t.Errorf("flag source should not annotate, got %q", got)
	}

	envAnnotated := annotateSecretPrompt(base, credSourceEnv, "isp", nil)
	if !strings.Contains(envAnnotated, "IDSEC_ISP_SECRET") {
		t.Errorf("env annotation should mention IDSEC_ISP_SECRET, got %q", envAnnotated)
	}

	// For the file source, load a real file so Path() is populated.
	dir := t.TempDir()
	path := filepath.Join(dir, ".idsecrc")
	if err := os.WriteFile(path, []byte("[default]\nisp_secret = x\n"), 0o600); err != nil {
		t.Fatalf("failed to write temp rc: %v", err)
	}
	file, err := credentials.Load(path, false)
	if err != nil {
		t.Fatalf("failed to load temp rc: %v", err)
	}
	fileAnnotated := annotateSecretPrompt(base, credSourceFile, "isp", file)
	if !strings.Contains(fileAnnotated, path) {
		t.Errorf("file annotation should mention the file path %q, got %q", path, fileAnnotated)
	}
}

// isolateCredentialEnv points HOME and the working directory at empty temp
// directories and clears credential env vars, so credential resolution is not
// influenced by the developer's real environment.
func isolateCredentialEnv(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	cwd := t.TempDir()
	t.Setenv("HOME", home)
	orig, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get cwd: %v", err)
	}
	if err := os.Chdir(cwd); err != nil {
		t.Fatalf("failed to chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(orig) })

	for _, name := range []string{
		credentials.CredentialsFileEnvVar,
		"IDSEC_ISP_USERNAME", "IDSEC_ISP_SECRET",
		"IDSEC_PVWA_USERNAME", "IDSEC_PVWA_SECRET",
	} {
		t.Setenv(name, "")
		_ = os.Unsetenv(name)
	}
}

// newSilentLoginCmd builds a login command with the flags runLoginAction reads,
// configured for silent execution with output allowed (so failures are printed).
func newSilentLoginCmd(profileName string) *cobra.Command {
	cmd := &cobra.Command{Use: "login"}
	cmd.Flags().String("profile-name", profileName, "Profile name")
	cmd.Flags().Bool("force", true, "Force login")
	cmd.Flags().Bool("refresh-auth", false, "Refresh auth")
	cmd.Flags().Bool("no-shared-secrets", false, "No shared secrets")
	cmd.Flags().Bool("show-tokens", false, "Show tokens")
	cmd.Flags().String("credentials-file", "", "Credentials file")
	cmd.Flags().Bool("no-credentials-file", false, "Suppress .idsecrc discovery")
	cmd.Flags().Bool("silent", true, "Silent mode")
	cmd.Flags().Bool("allow-output", true, "Allow output")
	cmd.Flags().String("pvwa-username", "", "PVWA username")
	cmd.Flags().String("pvwa-secret", "", "PVWA secret")
	return cmd
}

func TestRunLoginActionSilentMissingSecretMessage(t *testing.T) {
	isolateCredentialEnv(t)

	mockLoader := testutils.NewMockProfileLoader()
	mockLoader.LoadProfileFunc = func(name string) (*models.IdsecProfile, error) {
		return testutils.CreateTestProfileWithAuth(name, "pvwa", authmodels.PVWA), nil
	}
	action := NewIdsecLoginAction(mockLoader.AsProfileLoader())
	cmd := newSilentLoginCmd("test-profile")

	originalStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	_ = action.runLoginAction(cmd, []string{})

	_ = w.Close()
	os.Stdout = originalStdout
	var out bytes.Buffer
	_, _ = out.ReadFrom(r)
	output := out.String()

	for _, want := range []string{"IDSEC_PVWA_SECRET", "IDSEC_PVWA_SECRET_FILE", "--pvwa-secret", "pvwa_secret"} {
		if !strings.Contains(output, want) {
			t.Errorf("expected silent missing-secret message to contain %q, got:\n%s", want, output)
		}
	}
}

// TestRunLoginActionSilentUsernameResolution verifies the silent-mode username
// precedence wiring: with no username anywhere the run reports the
// username-required guidance, and setting the env var satisfies it (the run
// then falls through to the missing-secret guidance instead).
func TestRunLoginActionSilentUsernameResolution(t *testing.T) {
	newAction := func() *IdsecLoginAction {
		mockLoader := testutils.NewMockProfileLoader()
		mockLoader.LoadProfileFunc = func(name string) (*models.IdsecProfile, error) {
			profile := testutils.CreateTestProfileWithAuth(name, "pvwa", authmodels.PVWA)
			profile.AuthProfiles["pvwa"].Username = ""
			return profile, nil
		}
		return NewIdsecLoginAction(mockLoader.AsProfileLoader())
	}

	capture := func(action *IdsecLoginAction, cmd *cobra.Command) string {
		originalStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w
		_ = action.runLoginAction(cmd, []string{})
		_ = w.Close()
		os.Stdout = originalStdout
		var out bytes.Buffer
		_, _ = out.ReadFrom(r)
		return out.String()
	}

	t.Run("no_username_anywhere", func(t *testing.T) {
		isolateCredentialEnv(t)
		output := capture(newAction(), newSilentLoginCmd("test-profile"))
		if !strings.Contains(output, "A username is required") {
			t.Errorf("expected the username-required guidance, got:\n%s", output)
		}
	})

	t.Run("username_from_env_var", func(t *testing.T) {
		isolateCredentialEnv(t)
		t.Setenv("IDSEC_PVWA_USERNAME", "alice@example.com")
		output := capture(newAction(), newSilentLoginCmd("test-profile"))
		if strings.Contains(output, "A username is required") {
			t.Errorf("expected the env-var username to satisfy the username check, got:\n%s", output)
		}
		if !strings.Contains(output, "A secret is required") {
			t.Errorf("expected the run to proceed to the secret check, got:\n%s", output)
		}
	})
}
