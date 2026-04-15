package actions

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/cyberark/idsec-cli-golang/pkg/common/args"
)

func normalizeCSP(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func isValidCSP(csp string) bool {
	switch csp {
	case "aws", "azure", "gcp":
		return true
	default:
		return false
	}
}

func isBoolString(s string) bool {
	lower := strings.ToLower(strings.TrimSpace(s))
	return lower == "true" || lower == "false"
}

// argvAfterSubcommand returns argv starting at the first token equal to name.
func argvAfterSubcommand(argv []string, name string) []string {
	for i, arg := range argv {
		if arg == name {
			return argv[i:]
		}
	}
	return argv
}

// parseAllFlagFromArgv returns the effective --all value from argv. The last occurrence wins.
// Supports --all=false, --all=true, --all false, --all true, and bare --all (same as true).
func parseAllFlagFromArgv(argv []string) (string, bool) {
	for i := len(argv) - 1; i >= 0; i-- {
		if after, ok := strings.CutPrefix(argv[i], "--all="); ok {
			return after, true
		}
		if argv[i] != "--all" {
			continue
		}
		if i+1 < len(argv) && isBoolString(argv[i+1]) {
			return strings.ToLower(argv[i+1]), true
		}
		return "true", true
	}
	return "", false
}

func isValidKubeconfig(value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return false
	}
	var parsed map[string]interface{}
	if err := yaml.Unmarshal([]byte(trimmed), &parsed); err != nil {
		return false
	}
	_, hasAPIVersion := parsed["apiVersion"]
	return hasAPIVersion
}

func resolveOutputPath(customLocation, csp, homeDir string) string {
	if customLocation == "" {
		return filepath.Join(homeDir, ".kube", "idsec-cli", csp+".yaml")
	}
	customLocation = filepath.Clean(customLocation)

	if fi, err := os.Stat(customLocation); err == nil {
		if fi.IsDir() {
			return filepath.Join(customLocation, csp+".yml")
		}
		return customLocation
	}

	if hasYAMLExtension(customLocation) {
		return customLocation
	}
	return filepath.Join(customLocation, csp+".yml")
}

func hasYAMLExtension(p string) bool {
	ext := strings.ToLower(filepath.Ext(p))
	return ext == ".yaml" || ext == ".yml"
}

// normalizeGenerateKubeconfigResult remaps a single-entry response to the requested CSP,
// then expands any nested JSON "all" key into per-CSP entries.
func normalizeGenerateKubeconfigResult(csp string, in map[string]string) map[string]string {
	if len(in) == 1 && csp != "" {
		for _, value := range in {
			in = map[string]string{normalizeCSP(csp): value}
		}
	}

	out := make(map[string]string, len(in))
	for key, value := range in {
		key = normalizeCSP(key)
		if key == "" {
			continue
		}
		if key == "all" {
			if expanded := tryParseJSONMap(value); len(expanded) > 0 {
				mapsCopy(out, expanded)
				continue
			}
		}
		out[key] = value
	}
	return out
}

func tryParseJSONMap(value string) map[string]string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || trimmed[0] != '{' {
		return nil
	}
	var parsed map[string]string
	if err := json.Unmarshal([]byte(trimmed), &parsed); err != nil || len(parsed) == 0 {
		return nil
	}
	return normalizeMapKeys(parsed)
}

func normalizeMapKeys(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for key, value := range in {
		if key = normalizeCSP(key); key != "" {
			out[key] = value
		}
	}
	return out
}

func mapsCopy(dst, src map[string]string) {
	for key, value := range src {
		dst[key] = value
	}
}

// writeKubeconfigs validates each CSP entry, writes valid kubeconfigs to disk,
// logs per-CSP errors, prints the summary, and exits non-zero if every entry failed.
func writeKubeconfigs(result map[string]string, kubeconfigLocation string) (summary map[string]string, successCount, failureCount int) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		args.PrintFailure(fmt.Sprintf("idsec generate-kubeconfig: failed to resolve home directory: %v", err))
		os.Exit(1)
	}

	summary = make(map[string]string, len(result))
	for cspKey, value := range result {
		cspKey = normalizeCSP(cspKey)
		if cspKey == "" {
			continue
		}

		if !isValidKubeconfig(value) {
			summary[cspKey] = value
			failureCount++
			args.PrintFailure(fmt.Sprintf("idsec generate-kubeconfig [%s]: %s", cspKey, value))
			continue
		}

		outputPath := resolveOutputPath(kubeconfigLocation, cspKey, homeDir)
		if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
			msg := fmt.Sprintf("failed to create directory %q: %v", filepath.Dir(outputPath), err)
			summary[cspKey] = msg
			failureCount++
			args.PrintFailure(fmt.Sprintf("idsec generate-kubeconfig [%s]: %s", cspKey, msg))
			continue
		}
		if err := os.WriteFile(outputPath, []byte(value), 0600); err != nil {
			msg := fmt.Sprintf("failed to write kubeconfig: %v", err)
			summary[cspKey] = msg
			failureCount++
			args.PrintFailure(fmt.Sprintf("idsec generate-kubeconfig [%s]: %s", cspKey, msg))
			continue
		}

		summary[cspKey] = fmt.Sprintf("file created at location %s", outputPath)
		successCount++
	}

	summaryJSON, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		args.PrintWarning(fmt.Sprintf("error serializing generate-kubeconfig summary to JSON: %v", err))
		args.PrintSuccess(summary)
	} else {
		args.PrintSuccess(string(summaryJSON))
	}
	if failureCount > 0 && successCount == 0 {
		os.Exit(1)
	}
	return summary, successCount, failureCount
}
