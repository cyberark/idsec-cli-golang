package credentials

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// captureStderr redirects os.Stderr while fn runs and returns what was written.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stderr = w
	fn()
	_ = w.Close()
	os.Stderr = orig
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	return buf.String()
}

// writeFile writes content to path (creating parent dirs) with the given mode.
func writeFile(t *testing.T, path, content string, perm os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("failed to create dir for %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), perm); err != nil {
		t.Fatalf("failed to write %s: %v", path, err)
	}
}

// chdir changes the working directory to dir and restores it on cleanup.
func chdir(t *testing.T, dir string) {
	t.Helper()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get cwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("failed to chdir to %s: %v", dir, err)
	}
	t.Cleanup(func() { _ = os.Chdir(orig) })
}

// clearCredentialEnv unsets the credential-related environment variables so tests
// are not influenced by the developer's real environment.
func clearCredentialEnv(t *testing.T) {
	t.Helper()
	t.Setenv(CredentialsFileEnvVar, "")
	_ = os.Unsetenv(CredentialsFileEnvVar)
	for _, name := range []string{
		"IDSEC_ISP_USERNAME", "IDSEC_ISP_SECRET", "IDSEC_ISP_SECRET_FILE",
		"IDSEC_PVWA_USERNAME", "IDSEC_PVWA_SECRET", "IDSEC_PVWA_SECRET_FILE",
	} {
		t.Setenv(name, "")
		_ = os.Unsetenv(name)
	}
}

func TestEnvVarNames(t *testing.T) {
	cases := []struct {
		authName     string
		wantUsername string
		wantSecret   string
	}{
		{"isp", "IDSEC_ISP_USERNAME", "IDSEC_ISP_SECRET"},
		{"pvwa", "IDSEC_PVWA_USERNAME", "IDSEC_PVWA_SECRET"},
	}
	for _, c := range cases {
		if got := EnvUsernameVar(c.authName); got != c.wantUsername {
			t.Errorf("EnvUsernameVar(%q) = %q, want %q", c.authName, got, c.wantUsername)
		}
		if got := EnvSecretVar(c.authName); got != c.wantSecret {
			t.Errorf("EnvSecretVar(%q) = %q, want %q", c.authName, got, c.wantSecret)
		}
	}
}

func TestEnvUsernameAndSecret(t *testing.T) {
	clearCredentialEnv(t)
	t.Setenv("IDSEC_ISP_USERNAME", "alice@example.com")
	t.Setenv("IDSEC_ISP_SECRET", "s3cr3t")

	if got := EnvUsername("isp"); got != "alice@example.com" {
		t.Errorf("EnvUsername(isp) = %q, want alice@example.com", got)
	}
	if got, err := EnvSecret("isp"); err != nil || got != "s3cr3t" {
		t.Errorf("EnvSecret(isp) = %q (err %v), want s3cr3t", got, err)
	}
	if got := EnvUsername("pvwa"); got != "" {
		t.Errorf("EnvUsername(pvwa) = %q, want empty", got)
	}
}

func TestEnvSecretFromFile(t *testing.T) {
	clearCredentialEnv(t)
	dir := t.TempDir()
	secretPath := filepath.Join(dir, "isp.secret")
	// A trailing newline is common from editors and must be stripped.
	writeFile(t, secretPath, "file-s3cr3t\n", 0o600)
	t.Setenv("IDSEC_ISP_SECRET_FILE", secretPath)

	got, err := EnvSecret("isp")
	if err != nil {
		t.Fatalf("EnvSecret(isp) returned error: %v", err)
	}
	if got != "file-s3cr3t" {
		t.Errorf("EnvSecret(isp) = %q, want file-s3cr3t", got)
	}
	if src := EnvSecretSourceVar("isp"); src != "IDSEC_ISP_SECRET_FILE" {
		t.Errorf("EnvSecretSourceVar(isp) = %q, want IDSEC_ISP_SECRET_FILE", src)
	}
}

func TestEnvSecretLiteralBeatsFile(t *testing.T) {
	clearCredentialEnv(t)
	dir := t.TempDir()
	secretPath := filepath.Join(dir, "isp.secret")
	writeFile(t, secretPath, "from-file", 0o600)
	t.Setenv("IDSEC_ISP_SECRET", "from-literal")
	t.Setenv("IDSEC_ISP_SECRET_FILE", secretPath)

	got, err := EnvSecret("isp")
	if err != nil {
		t.Fatalf("EnvSecret(isp) returned error: %v", err)
	}
	if got != "from-literal" {
		t.Errorf("EnvSecret(isp) = %q, want from-literal (literal beats file)", got)
	}
	if src := EnvSecretSourceVar("isp"); src != "IDSEC_ISP_SECRET" {
		t.Errorf("EnvSecretSourceVar(isp) = %q, want IDSEC_ISP_SECRET", src)
	}
}

func TestEnvSecretUnreadableFileIsError(t *testing.T) {
	clearCredentialEnv(t)
	missing := filepath.Join(t.TempDir(), "nope.secret")
	t.Setenv("IDSEC_ISP_SECRET_FILE", missing)

	if _, err := EnvSecret("isp"); err == nil {
		t.Error("expected an error for an unreadable secret file, got nil (must never silently drop the secret)")
	}
}

func TestLoadNoDiscoverySuppressesAutoDiscovery(t *testing.T) {
	clearCredentialEnv(t)
	home := t.TempDir()
	cwd := t.TempDir()
	t.Setenv("HOME", home)
	chdir(t, cwd)
	// A discoverable file exists in the cwd, but noDiscovery must ignore it.
	writeFile(t, filepath.Join(cwd, credentialsFileName), "[default]\nisp_secret = discovered\n", 0o600)

	file, err := Load("", true)
	if err != nil {
		t.Fatalf("Load with noDiscovery returned error: %v", err)
	}
	if file != nil {
		t.Errorf("expected no file when auto-discovery is suppressed, got %v", file.Path())
	}
}

func TestLoadNoDiscoveryStillHonorsExplicitPath(t *testing.T) {
	clearCredentialEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, ".idsecrc")
	writeFile(t, path, "[default]\nisp_secret = explicit\n", 0o600)

	file, err := Load(path, true)
	if err != nil {
		t.Fatalf("Load with explicit path and noDiscovery returned error: %v", err)
	}
	if file == nil || file.Secret("default", "isp") != "explicit" {
		t.Errorf("explicit path must still load under noDiscovery, got %v", file)
	}
}

func TestFileUsernameSecretSectionAndDefaultFallback(t *testing.T) {
	clearCredentialEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, ".idsecrc")
	writeFile(t, path, `
[default]
isp_username  = default-user
isp_secret    = default-secret
pvwa_username = default-pvwa-user
pvwa_secret   = default-pvwa-secret

[prod]
isp_username = prod-user
isp_secret   = prod-secret
`, 0o600)

	file, err := Load(path, false)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if file == nil {
		t.Fatal("Load returned nil file for an existing path")
	}

	// prod section takes precedence for isp.
	if got := file.Username("prod", "isp"); got != "prod-user" {
		t.Errorf("Username(prod, isp) = %q, want prod-user", got)
	}
	if got := file.Secret("prod", "isp"); got != "prod-secret" {
		t.Errorf("Secret(prod, isp) = %q, want prod-secret", got)
	}
	// prod section has no pvwa keys -> fall back to default.
	if got := file.Username("prod", "pvwa"); got != "default-pvwa-user" {
		t.Errorf("Username(prod, pvwa) = %q, want default-pvwa-user (default fallback)", got)
	}
	// Unknown profile -> default section.
	if got := file.Secret("missing-profile", "isp"); got != "default-secret" {
		t.Errorf("Secret(missing-profile, isp) = %q, want default-secret", got)
	}
	// Unknown authenticator -> empty.
	if got := file.Username("prod", "ldap"); got != "" {
		t.Errorf("Username(prod, ldap) = %q, want empty", got)
	}
}

func TestNilFileIsSafe(t *testing.T) {
	var file *IdsecRCFile
	if got := file.Username("prod", "isp"); got != "" {
		t.Errorf("nil File Username = %q, want empty", got)
	}
	if got := file.Secret("prod", "isp"); got != "" {
		t.Errorf("nil File Secret = %q, want empty", got)
	}
	if got := file.Path(); got != "" {
		t.Errorf("nil File Path = %q, want empty", got)
	}
}

func TestLoadExplicitMissingIsError(t *testing.T) {
	clearCredentialEnv(t)
	missing := filepath.Join(t.TempDir(), "does-not-exist.idsecrc")
	if _, err := Load(missing, false); err == nil {
		t.Error("expected an error loading an explicit missing file, got nil")
	}
}

func TestLoadExplicitViaEnvMissingIsError(t *testing.T) {
	clearCredentialEnv(t)
	missing := filepath.Join(t.TempDir(), "does-not-exist.idsecrc")
	t.Setenv(CredentialsFileEnvVar, missing)
	if _, err := Load("", false); err == nil {
		t.Error("expected an error loading an explicit (env) missing file, got nil")
	}
}

func TestLoadAutoDiscoveredMissingReturnsNil(t *testing.T) {
	clearCredentialEnv(t)
	emptyHome := t.TempDir()
	emptyCwd := t.TempDir()
	t.Setenv("HOME", emptyHome)
	chdir(t, emptyCwd)

	file, err := Load("", false)
	if err != nil {
		t.Fatalf("expected nil error for auto-discovery with no file, got %v", err)
	}
	if file != nil {
		t.Errorf("expected nil file for auto-discovery with no file, got %v", file.Path())
	}
}

func TestLoadFromEnvPath(t *testing.T) {
	clearCredentialEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.ini")
	writeFile(t, path, "[default]\nisp_secret = env-path-secret\n", 0o600)
	t.Setenv(CredentialsFileEnvVar, path)

	file, err := Load("", false)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if file == nil || file.Path() != path {
		t.Fatalf("expected file loaded from env path %s, got %v", path, file)
	}
	if got := file.Secret("default", "isp"); got != "env-path-secret" {
		t.Errorf("Secret(default, isp) = %q, want env-path-secret", got)
	}
}

func TestResolveFilePathPrecedence(t *testing.T) {
	clearCredentialEnv(t)
	home := t.TempDir()
	cwd := t.TempDir()
	t.Setenv("HOME", home)
	chdir(t, cwd)
	// os.Getwd() may resolve symlinks (e.g. /var -> /private/var on macOS), and
	// ResolveFilePath uses os.Getwd(); align the expected cwd with it.
	if resolved, err := os.Getwd(); err == nil {
		cwd = resolved
	}

	homeRC := filepath.Join(home, credentialsFileName)
	homeIdsecRC := filepath.Join(home, credentialsDir, credentialsFileName)
	cwdIdsecRC := filepath.Join(cwd, credentialsDir, credentialsFileName)
	cwdRC := filepath.Join(cwd, credentialsFileName)

	// Start with only the lowest-precedence location present, then add
	// higher-precedence ones and assert each takes over.
	writeFile(t, homeRC, "[default]\n", 0o600)
	if path, explicit, found := ResolveFilePath("", false); !found || explicit || path != homeRC {
		t.Fatalf("expected %s (auto), got path=%s explicit=%v found=%v", homeRC, path, explicit, found)
	}

	writeFile(t, homeIdsecRC, "[default]\n", 0o600)
	if path, _, _ := ResolveFilePath("", false); path != homeIdsecRC {
		t.Fatalf("expected %s to win over home rc, got %s", homeIdsecRC, path)
	}

	writeFile(t, cwdIdsecRC, "[default]\n", 0o600)
	if path, _, _ := ResolveFilePath("", false); path != cwdIdsecRC {
		t.Fatalf("expected %s to win, got %s", cwdIdsecRC, path)
	}

	writeFile(t, cwdRC, "[default]\n", 0o600)
	if path, _, _ := ResolveFilePath("", false); path != cwdRC {
		t.Fatalf("expected %s to win, got %s", cwdRC, path)
	}

	// Env var beats all auto-discovery.
	envPath := filepath.Join(t.TempDir(), "env.idsecrc")
	writeFile(t, envPath, "[default]\n", 0o600)
	t.Setenv(CredentialsFileEnvVar, envPath)
	if path, explicit, found := ResolveFilePath("", false); !found || !explicit || path != envPath {
		t.Fatalf("expected env path %s explicit, got path=%s explicit=%v found=%v", envPath, path, explicit, found)
	}

	// Flag beats env var.
	flagPath := filepath.Join(t.TempDir(), "flag.idsecrc")
	writeFile(t, flagPath, "[default]\n", 0o600)
	if path, explicit, found := ResolveFilePath(flagPath, false); !found || !explicit || path != flagPath {
		t.Fatalf("expected flag path %s explicit, got path=%s explicit=%v found=%v", flagPath, path, explicit, found)
	}
}

func TestLoadIgnoresUnknownKeys(t *testing.T) {
	clearCredentialEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, ".idsecrc")
	writeFile(t, path, `
[default]
isp_secret     = keep-me
unrelated_key  = ignore-me
`, 0o600)

	file, err := Load(path, false)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if got := file.Secret("default", "isp"); got != "keep-me" {
		t.Errorf("Secret(default, isp) = %q, want keep-me", got)
	}
}

func TestLoadWithInsecurePermissionsStillLoads(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits are not meaningful on Windows")
	}
	clearCredentialEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, ".idsecrc")
	writeFile(t, path, "[default]\nisp_secret = perm-secret\n", 0o644)

	file, err := Load(path, false)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if got := file.Secret("default", "isp"); got != "perm-secret" {
		t.Errorf("Secret(default, isp) = %q, want perm-secret", got)
	}
}

// TestWarnInsecurePermissionsWritesToStderr verifies the insecure-permissions
// warning reaches stderr without any --verbose flag, so a 0644 .idsecrc is not
// accepted silently in the non-interactive mode automation uses.
func TestWarnInsecurePermissionsWritesToStderr(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits are not meaningful on Windows")
	}
	clearCredentialEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, ".idsecrc")
	writeFile(t, path, "[default]\nisp_secret = perm-secret\n", 0o644)

	stderr := captureStderr(t, func() {
		if _, err := Load(path, false); err != nil {
			t.Fatalf("Load returned error: %v", err)
		}
	})

	if !strings.Contains(stderr, "idsec: warning:") {
		t.Errorf("expected an 'idsec: warning:' prefix on stderr, got: %q", stderr)
	}
	if !strings.Contains(stderr, "group/world-readable") {
		t.Errorf("expected an insecure-permissions warning on stderr, got: %q", stderr)
	}
}

// TestWarnUnknownKeysWritesToStderr verifies the unrecognized-key warning
// reaches stderr without any --verbose flag.
func TestWarnUnknownKeysWritesToStderr(t *testing.T) {
	clearCredentialEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, ".idsecrc")
	writeFile(t, path, "[default]\nisp_secret = keep\nunrelated_key = x\n", 0o600)

	stderr := captureStderr(t, func() {
		if _, err := Load(path, false); err != nil {
			t.Fatalf("Load returned error: %v", err)
		}
	})

	if !strings.Contains(stderr, "ignoring unrecognized key") || !strings.Contains(stderr, "unrelated_key") {
		t.Errorf("expected an unrecognized-key warning on stderr, got: %q", stderr)
	}
}
