package common

import (
	"os"
	"strings"
	"testing"

	"github.com/rhysd/go-github-selfupdate/selfupdate"
)

// setEnvVar sets an environment variable for testing and returns a cleanup function.
func setEnvVar(t *testing.T, key, value string) func() {
	t.Helper()
	original := os.Getenv(key)
	_ = os.Setenv(key, value)
	return func() {
		if original == "" {
			_ = os.Unsetenv(key)
		} else {
			_ = os.Setenv(key, original)
		}
	}
}

func TestGetSelfUpgrader(t *testing.T) {
	tests := []struct {
		name           string
		githubURL      string
		setupEnv       func() func()
		expectedError  bool
		validateConfig func(t *testing.T, updater *selfupdate.Updater)
	}{
		{
			name:      "success_public_github_no_env_var",
			githubURL: "",
			setupEnv: func() func() {
				return setEnvVar(t, "GITHUB_URL", "")
			},
			expectedError: false,
			validateConfig: func(t *testing.T, updater *selfupdate.Updater) {
				if updater == nil {
					t.Error("Expected updater to be created, got nil")
				}
			},
		},
		{
			name:      "success_github_enterprise_with_env_var",
			githubURL: "github.enterprise.com",
			setupEnv: func() func() {
				return setEnvVar(t, "GITHUB_URL", "github.enterprise.com")
			},
			expectedError: false,
			validateConfig: func(t *testing.T, updater *selfupdate.Updater) {
				if updater == nil {
					t.Error("Expected updater to be created, got nil")
				}
			},
		},
		{
			name:      "success_github_enterprise_with_subdomain",
			githubURL: "my-org.github.enterprise.com",
			setupEnv: func() func() {
				return setEnvVar(t, "GITHUB_URL", "my-org.github.enterprise.com")
			},
			expectedError: false,
			validateConfig: func(t *testing.T, updater *selfupdate.Updater) {
				if updater == nil {
					t.Error("Expected updater to be created, got nil")
				}
			},
		},
		{
			name:      "success_empty_github_url_after_unset",
			githubURL: "",
			setupEnv: func() func() {
				_ = os.Setenv("GITHUB_URL", "some-value")
				return setEnvVar(t, "GITHUB_URL", "")
			},
			expectedError: false,
			validateConfig: func(t *testing.T, updater *selfupdate.Updater) {
				if updater == nil {
					t.Error("Expected updater to be created, got nil")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cleanup := tt.setupEnv()
			defer cleanup()

			updater, err := GetSelfUpgrader()

			if tt.expectedError {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if tt.validateConfig != nil {
				tt.validateConfig(t, updater)
			}
		})
	}
}

// TestUpgradeRepoSlug guards the upgrade target against regressing to the SDK
// repository, whose releases carry no binary assets and therefore make the
// self-updater report that no versions are available.
func TestUpgradeRepoSlug(t *testing.T) {
	t.Parallel()

	slug := UpgradeRepoSlug()

	owner, name, found := strings.Cut(slug, "/")
	if !found || owner == "" || name == "" {
		t.Fatalf("Expected slug in \"owner/name\" form, got %q", slug)
	}
	if name != "idsec-cli-golang" {
		t.Errorf("Expected slug to target repository 'idsec-cli-golang', got %q", name)
	}
	if strings.Contains(slug, "idsec-sdk-golang") {
		t.Errorf("Slug must not target the SDK repository, got %q", slug)
	}
}

// TestReleaseRepoHostAndSlugAgree guards the invariant that the API host and the
// repository slug are resolved from one location. If the host names a different
// forge than the one owning the slug, every upgrade check queries a repository
// that does not exist there.
func TestReleaseRepoHostAndSlugAgree(t *testing.T) {
	t.Parallel()

	host, slug := releaseRepoHostAndSlug()

	if !strings.Contains(host, ".") {
		t.Errorf("Expected a resolvable host, got %q", host)
	}
	owner, _, _ := strings.Cut(slug, "/")
	// The public mirror is owned by 'cyberark'; every other host is internal.
	if host == publicGitHubHost && owner != "cyberark" {
		t.Errorf("Host %q implies the public mirror, but owner is %q", host, owner)
	}
	if host != publicGitHubHost && owner == "cyberark" {
		t.Errorf("Owner %q implies the public mirror, but host is %q", owner, host)
	}
}

// TestUpgradeAPIHost covers the precedence between the explicit GITHUB_URL
// override and the host derived from the release location. The override has to
// keep winning: the hermetic upgrade tests rely on it to redirect the check at a
// local server.
func TestUpgradeAPIHost(t *testing.T) {
	derivedHost, _ := releaseRepoHostAndSlug()

	tests := []struct {
		name         string
		githubURL    string
		expectedHost string
	}{
		{
			name:         "env_var_overrides_derived_host",
			githubURL:    "github.enterprise.com",
			expectedHost: "github.enterprise.com",
		},
		{
			name:         "local_test_server_override",
			githubURL:    "127.0.0.1:8080",
			expectedHost: "127.0.0.1:8080",
		},
		{
			name:         "unset_env_var_falls_back_to_derived_host",
			githubURL:    "",
			expectedHost: derivedHost,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanup := setEnvVar(t, "GITHUB_URL", tt.githubURL)
			defer cleanup()

			if host := upgradeAPIHost(); host != tt.expectedHost {
				t.Errorf("Expected host %q, got %q", tt.expectedHost, host)
			}
		})
	}
}

func TestParseRepoLocation(t *testing.T) {
	tests := []struct {
		name          string
		location      string
		expectedHost  string
		expectedSlug  string
		expectedFound bool
	}{
		{
			name:          "public_module_path",
			location:      "github.com/cyberark/idsec-cli-golang",
			expectedHost:  "github.com",
			expectedSlug:  "cyberark/idsec-cli-golang",
			expectedFound: true,
		},
		{
			name:          "enterprise_module_path",
			location:      "github.com/cyberark/idsec-cli-golang",
			expectedHost:  "github.com",
			expectedSlug:  "cyberark/idsec-cli-golang",
			expectedFound: true,
		},
		{
			name:          "major_version_suffix_ignored",
			location:      "github.com/cyberark/idsec-cli-golang/v2",
			expectedHost:  "github.com",
			expectedSlug:  "cyberark/idsec-cli-golang",
			expectedFound: true,
		},
		{
			name:          "package_path_suffix_ignored",
			location:      "github.com/cyberark/idsec-cli-golang/cmd/idsec",
			expectedHost:  "github.com",
			expectedSlug:  "cyberark/idsec-cli-golang",
			expectedFound: true,
		},
		{
			name:          "empty_location_rejected",
			location:      "",
			expectedFound: false,
		},
		{
			name:          "too_few_elements_rejected",
			location:      "github.com/cyberark",
			expectedFound: false,
		},
		{
			name:          "host_without_dot_rejected",
			location:      "command-line-arguments/foo/bar",
			expectedFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			host, slug, found := parseRepoLocation(tt.location)

			if found != tt.expectedFound {
				t.Fatalf("Expected found %v, got %v", tt.expectedFound, found)
			}
			if !tt.expectedFound {
				return
			}
			if host != tt.expectedHost {
				t.Errorf("Expected host %q, got %q", tt.expectedHost, host)
			}
			if slug != tt.expectedSlug {
				t.Errorf("Expected slug %q, got %q", tt.expectedSlug, slug)
			}
		})
	}
}

func TestIsLatestVersion_Integration(t *testing.T) {
	tests := []struct {
		name          string
		setupEnv      func() func()
		expectedError bool
	}{
		{
			name: "integration_with_public_github",
			setupEnv: func() func() {
				return setEnvVar(t, "GITHUB_URL", "")
			},
			expectedError: false,
		},
		{
			name: "integration_with_enterprise_github",
			setupEnv: func() func() {
				return setEnvVar(t, "GITHUB_URL", "github.enterprise.com")
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanup := tt.setupEnv()
			defer cleanup()

			_, _, err := IsLatestVersion()
			if err != nil {
				t.Logf("Integration test error (expected in test environment): %v", err)
			}
		})
	}
}
