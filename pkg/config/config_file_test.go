package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigFile_success_sets_env_vars(t *testing.T) {
	configContent := `
IDSEC_FILE_LOG_LEVEL: DEBUG
IDSEC_PROFILE: myprofile
IDSEC_DISABLE_TELEMETRY_COLLECTION: true
`
	path := writeTestConfig(t, configContent)

	for _, key := range []string{"IDSEC_FILE_LOG_LEVEL", "IDSEC_PROFILE", "IDSEC_DISABLE_TELEMETRY_COLLECTION"} {
		t.Setenv(key, "")
		_ = os.Unsetenv(key)
	}

	LoadConfigFile(path)

	assertEnv(t, "IDSEC_FILE_LOG_LEVEL", "DEBUG")
	assertEnv(t, "IDSEC_PROFILE", "myprofile")
	assertEnv(t, "IDSEC_DISABLE_TELEMETRY_COLLECTION", "true")
}

func TestLoadConfigFile_success_does_not_override_existing_env(t *testing.T) {
	configContent := `
IDSEC_PROFILE: config-profile
`
	path := writeTestConfig(t, configContent)

	t.Setenv("IDSEC_PROFILE", "env-profile")

	LoadConfigFile(path)

	assertEnv(t, "IDSEC_PROFILE", "env-profile")
}

func TestLoadConfigFile_success_missing_file_no_error(t *testing.T) {
	t.Parallel()
	LoadConfigFile(filepath.Join(t.TempDir(), "nonexistent.yaml"))
}

func TestLoadConfigFile_success_empty_path(t *testing.T) {
	t.Parallel()
	LoadConfigFile("")
}

func TestLoadConfigFile_success_empty_file(t *testing.T) {
	t.Parallel()
	path := writeTestConfig(t, "")
	LoadConfigFile(path)
}

func TestLoadConfigFile_success_invalid_yaml_no_crash(t *testing.T) {
	t.Parallel()
	path := writeTestConfig(t, "::invalid yaml::")
	LoadConfigFile(path)
}

func TestLoadConfigFile_success_ignores_non_idsec_keys(t *testing.T) {
	configContent := `
IDSEC_PROFILE: valid-profile
NOT_IDSEC: bad-prefix
PATH: /should/be/ignored
`
	path := writeTestConfig(t, configContent)

	t.Setenv("IDSEC_PROFILE", "")
	_ = os.Unsetenv("IDSEC_PROFILE")
	t.Setenv("NOT_IDSEC", "")
	_ = os.Unsetenv("NOT_IDSEC")

	originalPath := os.Getenv("PATH")
	LoadConfigFile(path)

	assertEnv(t, "IDSEC_PROFILE", "valid-profile")
	if os.Getenv("NOT_IDSEC") != "" {
		t.Errorf("Expected NOT_IDSEC to not be set, got %q", os.Getenv("NOT_IDSEC"))
	}
	assertEnv(t, "PATH", originalPath)
}

func TestLoadConfigFile_success_accepts_any_idsec_prefixed_key(t *testing.T) {
	configContent := `
IDSEC_CUSTOM_FUTURE_VAR: hello
`
	path := writeTestConfig(t, configContent)

	t.Setenv("IDSEC_CUSTOM_FUTURE_VAR", "")
	_ = os.Unsetenv("IDSEC_CUSTOM_FUTURE_VAR")

	LoadConfigFile(path)

	assertEnv(t, "IDSEC_CUSTOM_FUTURE_VAR", "hello")
}

func TestLoadConfigFile_success_accepts_standard_proxy_keys(t *testing.T) {
	configContent := `
HTTP_PROXY: http://proxy.corp:8080
HTTPS_PROXY: http://proxy.corp:8443
NO_PROXY: localhost,127.0.0.1
http_proxy: http://lower.corp:8080
https_proxy: http://lower.corp:8443
no_proxy: lower.local
`
	path := writeTestConfig(t, configContent)

	for _, key := range []string{
		"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
		"http_proxy", "https_proxy", "no_proxy",
	} {
		t.Setenv(key, "")
		_ = os.Unsetenv(key)
	}

	LoadConfigFile(path)

	assertEnv(t, "HTTP_PROXY", "http://proxy.corp:8080")
	assertEnv(t, "HTTPS_PROXY", "http://proxy.corp:8443")
	assertEnv(t, "NO_PROXY", "localhost,127.0.0.1")
	assertEnv(t, "http_proxy", "http://lower.corp:8080")
	assertEnv(t, "https_proxy", "http://lower.corp:8443")
	assertEnv(t, "no_proxy", "lower.local")
}

func TestLoadConfigFile_success_typo_proxy_key_is_rejected(t *testing.T) {
	configContent := `
HTTPSPROXY: http://typo.corp:8080
`
	path := writeTestConfig(t, configContent)

	t.Setenv("HTTPSPROXY", "")
	_ = os.Unsetenv("HTTPSPROXY")

	LoadConfigFile(path)

	if got := os.Getenv("HTTPSPROXY"); got != "" {
		t.Errorf("Expected HTTPSPROXY to be ignored (typo), got %q", got)
	}
}

func TestLoadConfigFile_success_boolean_values(t *testing.T) {
	configContent := `
IDSEC_DISABLE_CERTIFICATE_VERIFICATION: true
IDSEC_BASIC_KEYRING: false
`
	path := writeTestConfig(t, configContent)

	t.Setenv("IDSEC_DISABLE_CERTIFICATE_VERIFICATION", "")
	_ = os.Unsetenv("IDSEC_DISABLE_CERTIFICATE_VERIFICATION")
	t.Setenv("IDSEC_BASIC_KEYRING", "")
	_ = os.Unsetenv("IDSEC_BASIC_KEYRING")

	LoadConfigFile(path)

	assertEnv(t, "IDSEC_DISABLE_CERTIFICATE_VERIFICATION", "true")
	assertEnv(t, "IDSEC_BASIC_KEYRING", "false")
}

func TestLoadConfigFile_success_numeric_values(t *testing.T) {
	configContent := `
IDSEC_SUPPRESS_UPGRADE_CHECK: 1
`
	path := writeTestConfig(t, configContent)

	t.Setenv("IDSEC_SUPPRESS_UPGRADE_CHECK", "")
	_ = os.Unsetenv("IDSEC_SUPPRESS_UPGRADE_CHECK")

	LoadConfigFile(path)

	assertEnv(t, "IDSEC_SUPPRESS_UPGRADE_CHECK", "1")
}

func TestLoadConfigFile_success_multiple_keys(t *testing.T) {
	expected := map[string]string{
		"IDSEC_FILE_LOG_PATH":                      "/tmp/test.log",
		"IDSEC_FILE_LOG_LEVEL":                     "WARNING",
		"IDSEC_LOG_LEVEL":                          "ERROR",
		"IDSEC_PROFILE":                            "testprofile",
		"IDSEC_PROFILES_FOLDER":                    "/tmp/profiles",
		"IDSEC_BASIC_KEYRING":                      "true",
		"IDSEC_KEYRING_FOLDER":                     "/tmp/keyring",
		"IDSEC_DISABLE_CERTIFICATE_VERIFICATION":   "true",
		"IDSEC_DISABLE_TELEMETRY_COLLECTION":       "true",
		"IDSEC_EXTRA_TRUSTED_CA_CERTS_BUNDLE_PATH": "/tmp/ca.pem",
		"IDSEC_PROXY_ADDRESS":                      "http://proxy:8080",
		"IDSEC_PROXY_USERNAME":                     "user",
		"IDSEC_PROXY_PASSWORD":                     "pass",
		"IDSEC_SUPPRESS_UPGRADE_CHECK":             "true",
	}

	configContent := `
IDSEC_FILE_LOG_PATH: /tmp/test.log
IDSEC_FILE_LOG_LEVEL: WARNING
IDSEC_LOG_LEVEL: ERROR
IDSEC_PROFILE: testprofile
IDSEC_PROFILES_FOLDER: /tmp/profiles
IDSEC_BASIC_KEYRING: true
IDSEC_KEYRING_FOLDER: /tmp/keyring
IDSEC_DISABLE_CERTIFICATE_VERIFICATION: true
IDSEC_DISABLE_TELEMETRY_COLLECTION: true
IDSEC_EXTRA_TRUSTED_CA_CERTS_BUNDLE_PATH: /tmp/ca.pem
IDSEC_PROXY_ADDRESS: http://proxy:8080
IDSEC_PROXY_USERNAME: user
IDSEC_PROXY_PASSWORD: pass
IDSEC_SUPPRESS_UPGRADE_CHECK: true
`
	path := writeTestConfig(t, configContent)

	for key := range expected {
		t.Setenv(key, "")
		_ = os.Unsetenv(key)
	}

	LoadConfigFile(path)

	for key, want := range expected {
		assertEnv(t, key, want)
	}
}

func TestResolveConfigFilePath_success_flag_takes_precedence(t *testing.T) {
	t.Setenv(ConfigFileEnvVar, "/env/config.yaml")
	got := ResolveConfigFilePath("/flag/config.yaml")
	if got != "/flag/config.yaml" {
		t.Fatalf("Expected /flag/config.yaml, got %s", got)
	}
}

func TestResolveConfigFilePath_success_env_var_fallback(t *testing.T) {
	t.Setenv(ConfigFileEnvVar, "/env/config.yaml")
	got := ResolveConfigFilePath("")
	if got != "/env/config.yaml" {
		t.Fatalf("Expected /env/config.yaml, got %s", got)
	}
}

func TestResolveConfigFilePath_success_default_path(t *testing.T) {
	t.Setenv(ConfigFileEnvVar, "")
	_ = os.Unsetenv(ConfigFileEnvVar)
	got := ResolveConfigFilePath("")
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("Failed to get home dir: %v", err)
	}
	want := filepath.Join(home, ".idsec", "config.yaml")
	if got != want {
		t.Fatalf("Expected %s, got %s", want, got)
	}
}

func TestExtractConfigFlag_success_separate_arg(t *testing.T) {
	original := os.Args
	defer func() { os.Args = original }()
	os.Args = []string{"idsec", "--config", "/custom/config.yaml", "login"}
	got := ExtractConfigFlag()
	if got != "/custom/config.yaml" {
		t.Fatalf("Expected /custom/config.yaml, got %s", got)
	}
}

func TestExtractConfigFlag_success_equals_syntax(t *testing.T) {
	original := os.Args
	defer func() { os.Args = original }()
	os.Args = []string{"idsec", "--config=/custom/config.yaml", "login"}
	got := ExtractConfigFlag()
	if got != "/custom/config.yaml" {
		t.Fatalf("Expected /custom/config.yaml, got %s", got)
	}
}

func TestExtractConfigFlag_success_no_flag(t *testing.T) {
	original := os.Args
	defer func() { os.Args = original }()
	os.Args = []string{"idsec", "login"}
	got := ExtractConfigFlag()
	if got != "" {
		t.Fatalf("Expected empty string, got %s", got)
	}
}

func TestExtractConfigFlag_edge_case_dangling_flag(t *testing.T) {
	original := os.Args
	defer func() { os.Args = original }()
	os.Args = []string{"idsec", "--config"}
	got := ExtractConfigFlag()
	if got != "" {
		t.Fatalf("Expected empty string for dangling --config, got %s", got)
	}
}

func writeTestConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}
	return path
}

func assertEnv(t *testing.T, key, want string) {
	t.Helper()
	got := os.Getenv(key)
	if got != want {
		t.Errorf("Expected %s=%q, got %q", key, want, got)
	}
}
