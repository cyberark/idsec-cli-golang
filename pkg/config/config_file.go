// Package config provides configuration file support for the Idsec CLI.
//
// It loads a YAML configuration file that sets default values for IDSEC_*
// environment variables. Environment variables already set in the process
// take precedence over config file values.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	sdkcommon "github.com/cyberark/idsec-sdk-golang/pkg/common"
	"gopkg.in/yaml.v3"
)

const (
	defaultConfigFileName = "config.yaml"
	defaultConfigDir      = ".idsec"
	envVarPrefix          = "IDSEC_"

	// ConfigFileEnvVar is the environment variable that overrides the default config file path.
	ConfigFileEnvVar = "IDSEC_CONFIG_FILE"
)

// allowedNonPrefixedKeys lists the well-known non-IDSEC_ environment variables
// that are also accepted from the config file. These are standard POSIX/Go
// network variables honored by Go's net/http package.
var allowedNonPrefixedKeys = map[string]bool{
	"HTTP_PROXY":  true,
	"HTTPS_PROXY": true,
	"NO_PROXY":    true,
	"http_proxy":  true,
	"https_proxy": true,
	"no_proxy":    true,
}

// ResolveConfigFilePath determines the configuration file path using the
// following precedence: CLI flag value, IDSEC_CONFIG_FILE env var, default path.
func ResolveConfigFilePath(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if envPath := os.Getenv(ConfigFileEnvVar); envPath != "" {
		return envPath
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, defaultConfigDir, defaultConfigFileName)
}

// LoadConfigFile reads the YAML config file and sets environment variables for
// recognized keys that are not already present in the environment. Accepted
// keys are any key starting with IDSEC_, plus the standard proxy variables
// HTTP_PROXY, HTTPS_PROXY, and NO_PROXY (and their lowercase forms).
// A missing file is silently ignored. Parse errors or unrecognized keys produce
// warnings but do not cause the CLI to fail.
func LoadConfigFile(path string) {
	if path == "" {
		return
	}

	data, err := os.ReadFile(path) // #nosec G304
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		logger().Warning("Failed to read config file %s: %v", path, err)
		return
	}

	if len(data) == 0 {
		return
	}

	var configMap map[string]interface{}
	if err := yaml.Unmarshal(data, &configMap); err != nil {
		logger().Warning("Failed to parse config file %s: %v", path, err)
		return
	}

	for key, value := range configMap {
		if !strings.HasPrefix(key, envVarPrefix) && !allowedNonPrefixedKeys[key] {
			logger().Warning("Config file: ignoring key %q (must start with %s or be a standard proxy variable)", key, envVarPrefix)
			continue
		}
		if os.Getenv(key) != "" {
			continue
		}
		_ = os.Setenv(key, fmt.Sprintf("%v", value))
	}
}

// ExtractConfigFlag scans os.Args for a --config flag value before Cobra
// parses the command line, so the config file can be loaded early in startup.
func ExtractConfigFlag() string {
	for i, arg := range os.Args {
		if arg == "--config" && i+1 < len(os.Args) {
			return os.Args[i+1]
		}
		if strings.HasPrefix(arg, "--config=") {
			return strings.TrimPrefix(arg, "--config=")
		}
	}
	return ""
}

// logger returns a lazily-initialised logger for the config package.
func logger() *sdkcommon.IdsecLogger {
	return sdkcommon.GetLogger("ConfigFile", sdkcommon.Unknown)
}
