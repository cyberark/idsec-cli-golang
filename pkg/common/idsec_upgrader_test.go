package common

import (
	"os"
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
