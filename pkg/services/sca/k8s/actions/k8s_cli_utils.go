package actions

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/cyberark/idsec-cli-golang/pkg/common/args"
	"github.com/cyberark/idsec-sdk-golang/pkg/config"
	k8smodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s/models"
)

// emptyKubeconfigContent is a minimal valid kubeconfig written when no eligible targets are found for a CSP.
const emptyKubeconfigContent = "apiVersion: v1\nkind: Config\nclusters: []\ncontexts: []\nusers: []\ncurrent-context: \"\"\npreferences: {}\n"

func normalizeCSP(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// normalizeConnectionMethod canonicalizes the evaluate connectionMethod for comparison and caching.
func normalizeConnectionMethod(method string) string {
	return strings.ToLower(strings.TrimSpace(method))
}

// notEligibleMessage returns the exit message for an evaluate response with no matching target.
func notEligibleMessage(results []k8smodels.IdsecSCAK8sEvaluateResult, fqdn, roleID, namespace string) string {
	switch {
	case len(results) == 0:
		return "Cluster not found in eligibility evaluation."
	case strings.TrimSpace(namespace) != "":
		return fmt.Sprintf("user is not eligible for target (no evaluate result matched fqdn=%q roleId=%q namespace=%q)", fqdn, roleID, namespace)
	default:
		return fmt.Sprintf("user is not eligible for target (no evaluate result matched fqdn=%q roleId=%q)", fqdn, roleID)
	}
}

func isValidCSP(csp string) bool {
	switch strings.ToUpper(strings.TrimSpace(csp)) {
	case k8smodels.CSPAWS, k8smodels.CSPAzure:
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
	noTargetsCount := 0
	for cspKey, value := range result {
		cspKey = normalizeCSP(cspKey)
		if cspKey == "" {
			continue
		}

		noEligibleTargets := !isValidKubeconfig(value)
		if noEligibleTargets {
			// Write an empty kubeconfig to overwrite any stale file.
			args.PrintFailure(fmt.Sprintf("idsec generate-kubeconfig [%s]: no eligible targets — %s", cspKey, value))
			value = emptyKubeconfigContent
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

		if noEligibleTargets {
			summary[cspKey] = "no eligible targets"
			noTargetsCount++
		} else {
			summary[cspKey] = fmt.Sprintf("file created at location %s", outputPath)
		}
		successCount++
	}

	if len(result) != 1 || noTargetsCount != 1 {
		summaryJSON, err := json.MarshalIndent(summary, "", "  ")
		if err != nil {
			args.PrintWarning(fmt.Sprintf("error serializing generate-kubeconfig summary to JSON: %v", err))
			args.PrintSuccess(summary)
		} else {
			args.PrintSuccess(string(summaryJSON))
		}
	}
	if failureCount > 0 && successCount == 0 {
		os.Exit(1)
	}
	return summary, successCount, failureCount
}

// ── CLI version mismatch (HTTP 426) ──────────────────────────────────────────

type versionMismatchServerResponse struct {
	Code       string `json:"code"`
	MinVersion string `json:"minVersion"` // server sends "minVersion" (not "required")
}

// VersionMismatchHint replaces errMsg with a short version mismatch message when it carries a 426
// CLI_VERSION_UNSUPPORTED body, and returns errMsg unchanged otherwise.
func VersionMismatchHint(errMsg string) string {
	if minVersion, ok := parseVersionMismatchBody(errMsg); ok {
		return formatExactVersionMismatch(config.IdsecVersion(), minVersion)
	}
	return errMsg
}

func parseVersionMismatchBody(errMsg string) (minVersion string, ok bool) {
	const bodyMarker = "Response body: "
	idx := strings.Index(errMsg, bodyMarker)
	if idx == -1 {
		return "", false
	}
	rawBody := strings.TrimSpace(errMsg[idx+len(bodyMarker):])
	if rawBody == "" {
		return "", false
	}

	var resp versionMismatchServerResponse
	if err := json.Unmarshal([]byte(rawBody), &resp); err != nil {
		return "", false
	}
	if strings.ToLower(resp.Code) != "cli_version_unsupported" {
		return "", false
	}
	return resp.MinVersion, true
}

// versionMismatchHeader starts every formatted version mismatch message.
const versionMismatchHeader = "Error: idsec CLI version mismatch."

func formatExactVersionMismatch(currentVersion, required string) string {
	requiredLine := required
	if requiredLine == "" {
		requiredLine = "unknown (please upgrade to the latest version)"
	} else {
		requiredLine = ">= " + requiredLine
	}
	return fmt.Sprintf(versionMismatchHeader+`
  Current version : %s
  Required version: %s`,
		currentVersion, requiredLine)
}

// findVersionMismatch scans per-CSP results (as returned by the parallel path, where
// failures are stored as values rather than returned as errors) and reports the first
// CLI version mismatch (HTTP 426). The mismatch is global, so callers should report it once.
func findVersionMismatch(result map[string]string) (message string, found bool) {
	keys := make([]string, 0, len(result))
	for k := range result {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if minVersion, ok := parseVersionMismatchBody(result[k]); ok {
			return formatExactVersionMismatch(config.IdsecVersion(), minVersion), true
		}
	}
	return "", false
}
