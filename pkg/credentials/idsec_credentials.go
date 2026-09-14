// Package credentials resolves idsec login credentials from environment
// variables and an INI ".idsecrc" credentials file.
//
// Credentials are looked up per authenticator (for example "isp" or "pvwa").
// Two sources are supported, both layered beneath explicit CLI flags by the
// caller:
//
//   - Environment variables: IDSEC_<AUTH>_USERNAME and IDSEC_<AUTH>_SECRET
//     (the authenticator name is uppercased), e.g. IDSEC_ISP_USERNAME. The
//     secret may instead be read from a file via IDSEC_<AUTH>_SECRET_FILE,
//     which is preferred because the secret can live in a 0600 file rather than
//     the environment. The literal IDSEC_<AUTH>_SECRET wins when both are set;
//     an unreadable IDSEC_<AUTH>_SECRET_FILE is a hard error, never silent.
//   - An INI file (".idsecrc"), AWS-credentials style, with one section per
//     profile and keys "<auth>_username" / "<auth>_secret". The section matching
//     the active profile is used, falling back to a "default" section.
//
// The file is discovered, in order, from an explicit path (flag or the
// IDSEC_CREDENTIALS_FILE environment variable), then ./.idsecrc,
// ./.idsec/.idsecrc, ~/.idsec/.idsecrc, and ~/.idsecrc. The first existing file
// wins; there is no merging across locations. Auto-discovery can be suppressed
// (leaving only an explicit path) so callers can require consent before reading
// a credentials file they did not name.
package credentials

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	ini "gopkg.in/ini.v1"
)

const (
	// CredentialsFileEnvVar is the environment variable that overrides the
	// default credentials file discovery with an explicit path.
	CredentialsFileEnvVar = "IDSEC_CREDENTIALS_FILE"

	// credentialsFileName is the base name of the credentials file.
	credentialsFileName = ".idsecrc"

	// credentialsDir is the directory searched under the current and home
	// directories for the credentials file.
	credentialsDir = ".idsec"

	// defaultSectionName is the INI section used when no section matches the
	// active profile name.
	defaultSectionName = "default"

	// envVarPrefix is the shared prefix for all idsec environment variables.
	envVarPrefix = "IDSEC_"

	usernameKeySuffix   = "_username"
	secretKeySuffix     = "_secret"
	secretFileKeySuffix = "_secret_file"
)

// EnvUsernameVar returns the environment variable name that holds the username
// for the given authenticator (e.g. "isp" -> "IDSEC_ISP_USERNAME").
func EnvUsernameVar(authName string) string {
	return fmt.Sprintf("%s%s%s", envVarPrefix, strings.ToUpper(authName), strings.ToUpper(usernameKeySuffix))
}

// EnvSecretVar returns the environment variable name that holds the secret for
// the given authenticator (e.g. "isp" -> "IDSEC_ISP_SECRET").
func EnvSecretVar(authName string) string {
	return fmt.Sprintf("%s%s%s", envVarPrefix, strings.ToUpper(authName), strings.ToUpper(secretKeySuffix))
}

// EnvSecretFileVar returns the environment variable name that holds the path to
// a file containing the secret for the given authenticator
// (e.g. "isp" -> "IDSEC_ISP_SECRET_FILE").
func EnvSecretFileVar(authName string) string {
	return fmt.Sprintf("%s%s%s", envVarPrefix, strings.ToUpper(authName), strings.ToUpper(secretFileKeySuffix))
}

// EnvUsername returns the username configured via environment variable for the
// given authenticator, or an empty string when unset.
func EnvUsername(authName string) string {
	return os.Getenv(EnvUsernameVar(authName))
}

// EnvSecret returns the secret configured via environment variable for the
// given authenticator. The literal IDSEC_<AUTH>_SECRET takes precedence; when
// it is unset, IDSEC_<AUTH>_SECRET_FILE is read and its contents (minus a
// trailing newline) are returned. An empty string is returned when neither is
// set. A configured-but-unreadable secret file returns an error rather than
// silently falling back to no secret.
func EnvSecret(authName string) (string, error) {
	if v := os.Getenv(EnvSecretVar(authName)); v != "" {
		return v, nil
	}
	if path := os.Getenv(EnvSecretFileVar(authName)); path != "" {
		content, err := os.ReadFile(path) // #nosec G304 -- path is operator-provided
		if err != nil {
			return "", fmt.Errorf("failed to read secret file %q from %s: %w", path, EnvSecretFileVar(authName), err)
		}
		return strings.TrimRight(string(content), "\r\n"), nil
	}
	return "", nil
}

// EnvSecretSourceVar returns the name of the environment variable that actually
// supplied the secret for the given authenticator, so prompts and messages can
// name the right source. It prefers the literal secret var, then the secret
// file var, defaulting to the literal var name when neither is set.
func EnvSecretSourceVar(authName string) string {
	if os.Getenv(EnvSecretVar(authName)) != "" {
		return EnvSecretVar(authName)
	}
	if os.Getenv(EnvSecretFileVar(authName)) != "" {
		return EnvSecretFileVar(authName)
	}
	return EnvSecretVar(authName)
}

// IdsecRCFile represents a parsed ".idsecrc" credentials file. A nil
// *IdsecRCFile is valid to use: its lookup methods return empty strings.
type IdsecRCFile struct {
	path string
	ini  *ini.File
}

// ResolveFilePath determines which credentials file to use.
//
// It returns the resolved path, whether the path came from an explicit source
// (the flag value or the IDSEC_CREDENTIALS_FILE environment variable), and
// whether an existing regular file was found at that path. For explicit sources
// the returned path is reported even when the file does not exist, so callers
// can treat a missing explicit file as a fatal error.
//
// When noDiscovery is true, only an explicit path (flag or environment
// variable) is honored; the ./.idsecrc, ./.idsec/.idsecrc, ~/.idsec/.idsecrc,
// and ~/.idsecrc auto-discovery search is skipped entirely.
func ResolveFilePath(flagValue string, noDiscovery bool) (path string, explicit bool, found bool) {
	if flagValue != "" {
		return flagValue, true, fileExists(flagValue)
	}
	if envPath := os.Getenv(CredentialsFileEnvVar); envPath != "" {
		return envPath, true, fileExists(envPath)
	}
	if noDiscovery {
		return "", false, false
	}
	for _, candidate := range discoveryCandidates() {
		if fileExists(candidate) {
			return candidate, false, true
		}
	}
	return "", false, false
}

// discoveryCandidates returns the auto-discovery search paths in precedence
// order: current dir, current dir/.idsec, home/.idsec, home.
func discoveryCandidates() []string {
	var candidates []string
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates,
			filepath.Join(cwd, credentialsFileName),
			filepath.Join(cwd, credentialsDir, credentialsFileName),
		)
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates,
			filepath.Join(home, credentialsDir, credentialsFileName),
			filepath.Join(home, credentialsFileName),
		)
	}
	return candidates
}

// Load resolves and loads the credentials file for the given flag value.
//
// When the file was requested explicitly (via the flag or the
// IDSEC_CREDENTIALS_FILE environment variable) it must exist and parse, or an
// error is returned. An auto-discovered file that is missing or fails to parse
// is treated as absent: Load returns (nil, nil) after logging a warning for a
// parse failure. A non-fatal warning is emitted for group/world-readable files
// on non-Windows platforms. When noDiscovery is true, auto-discovery is
// suppressed and only an explicit path (flag or IDSEC_CREDENTIALS_FILE) is
// loaded.
func Load(flagValue string, noDiscovery bool) (*IdsecRCFile, error) {
	path, explicit, found := ResolveFilePath(flagValue, noDiscovery)
	if !found {
		if explicit {
			return nil, fmt.Errorf("credentials file %q does not exist", path)
		}
		return nil, nil
	}

	warnIfInsecurePermissions(path)

	iniFile, err := ini.LoadSources(ini.LoadOptions{Insensitive: true}, path)
	if err != nil {
		if explicit {
			return nil, fmt.Errorf("failed to parse credentials file %q: %w", path, err)
		}
		warnCredentialsFile("failed to parse credentials file %s: %v", path, err)
		return nil, nil
	}

	file := &IdsecRCFile{path: path, ini: iniFile}
	file.warnUnknownKeys()
	return file, nil
}

// Path returns the file system path this credentials file was loaded from.
func (f *IdsecRCFile) Path() string {
	if f == nil {
		return ""
	}
	return f.path
}

// Username returns the username for the given profile and authenticator, reading
// the profile's section and falling back to the "default" section.
func (f *IdsecRCFile) Username(profileName, authName string) string {
	return f.value(profileName, authName+usernameKeySuffix)
}

// Secret returns the secret for the given profile and authenticator, reading the
// profile's section and falling back to the "default" section.
func (f *IdsecRCFile) Secret(profileName, authName string) string {
	return f.value(profileName, authName+secretKeySuffix)
}

// value looks up key in the profile's section, then in the default section.
func (f *IdsecRCFile) value(profileName, key string) string {
	if f == nil || f.ini == nil {
		return ""
	}
	if profileName != "" {
		if v, ok := sectionValue(f.ini, profileName, key); ok {
			return v
		}
	}
	if v, ok := sectionValue(f.ini, defaultSectionName, key); ok {
		return v
	}
	return ""
}

// sectionValue returns the value of key within the named section, if present.
func sectionValue(iniFile *ini.File, sectionName, key string) (string, bool) {
	section, err := iniFile.GetSection(sectionName)
	if err != nil {
		return "", false
	}
	if !section.HasKey(key) {
		return "", false
	}
	return section.Key(key).String(), true
}

// warnUnknownKeys emits a non-fatal warning for keys that do not follow the
// "<auth>_username" / "<auth>_secret" naming convention.
func (f *IdsecRCFile) warnUnknownKeys() {
	for _, section := range f.ini.Sections() {
		for _, key := range section.Keys() {
			name := key.Name()
			if !strings.HasSuffix(name, usernameKeySuffix) && !strings.HasSuffix(name, secretKeySuffix) {
				warnCredentialsFile("credentials file %s: ignoring unrecognized key %q in section %q", f.path, name, section.Name())
			}
		}
	}
}

// warnIfInsecurePermissions emits a non-fatal warning when the credentials file
// is readable by group or others. The check is skipped on Windows.
func warnIfInsecurePermissions(path string) {
	if runtime.GOOS == "windows" {
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		return
	}
	if info.Mode().Perm()&0o077 != 0 {
		warnCredentialsFile("credentials file %s is group/world-readable (%#o); restrict its permissions to 0600", path, info.Mode().Perm())
	}
}

// fileExists reports whether path exists and is a regular file (not a directory).
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// warnCredentialsFile writes a non-fatal credentials-file warning to stderr.
//
// It is intentionally NOT gated by --verbose or by the --silent/--allow-output
// output configuration: an insecure or malformed .idsecrc must be visible even
// in the non-interactive mode automation uses, where a verbose-only log would
// pass silently. It writes to stderr (never stdout) so it cannot corrupt a
// command's machine-readable output.
func warnCredentialsFile(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "idsec: warning: "+format+"\n", args...)
}
