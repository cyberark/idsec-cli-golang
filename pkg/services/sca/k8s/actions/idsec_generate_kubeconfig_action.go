package actions

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/cyberark/idsec-cli-golang/pkg/common/args"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/profiles"
	k8sservice "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s"
	k8smodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s/models"
)

// IdsecGenerateKubeconfigAction implements generate-kubeconfig for idsec exec sca k8s.
type IdsecGenerateKubeconfigAction struct {
	profilesLoader *profiles.ProfileLoader
}

func NewIdsecGenerateKubeconfigAction(profilesLoader *profiles.ProfileLoader) *IdsecGenerateKubeconfigAction {
	return &IdsecGenerateKubeconfigAction{profilesLoader: profilesLoader}
}

// DefineAction replaces Run on generate-kubeconfig; call after NewIdsecServiceExecAction.DefineAction.
func (a *IdsecGenerateKubeconfigAction) DefineAction(cmd *cobra.Command) {
	if genCmd := findNestedCommand(cmd, "exec", "sca", "k8s", "generate-kubeconfig"); genCmd != nil {
		genCmd.SilenceUsage = true
		genCmd.Run = a.runGenerateKubeconfigAction
		if f := genCmd.Flags().Lookup("all"); f != nil {
			f.NoOptDefVal = "true"
		}
	}
}

func (a *IdsecGenerateKubeconfigAction) runGenerateKubeconfigAction(cmd *cobra.Command, _ []string) {
	kubeconfigLocation, _ := cmd.Flags().GetString("kubeconfig-location")

	csp, allValue, errMsg := resolveGenerateKubeconfigFlags(cmd)
	if errMsg != "" {
		genKubeconfigExitErr(errMsg)
	}
	printVerbose(cmd, "resolved flags — csp=%q, all=%q, kubeconfig-location=%q", csp, allValue, kubeconfigLocation)

	svc := a.initK8sService(cmd)

	req := &k8smodels.IdsecSCAK8sGenerateKubeconfigRequest{
		CSP:                csp,
		All:                allValue,
		KubeconfigLocation: kubeconfigLocation,
	}
	printVerbose(cmd, "calling SDK GenerateKubeconfig — req.CSP=%q, req.All=%q", req.CSP, req.All)

	result, err := svc.GenerateKubeconfig(req)
	if err != nil {
		genKubeconfigExitErr(fmt.Sprintf("generate-kubeconfig API call failed: %v", err))
	}
	result = normalizeGenerateKubeconfigResult(csp, result)
	if len(result) == 0 {
		genKubeconfigExitErr("generate-kubeconfig API returned no valid CSP entries")
	}
	logDecodedResult(cmd, result)

	writeKubeconfigs(result, kubeconfigLocation)
}

// initK8sService loads the ISP profile/auth and returns a ready-to-use SCA K8s service.
func (a *IdsecGenerateKubeconfigAction) initK8sService(cmd *cobra.Command) *k8sservice.IdsecSCAK8sService {
	profileName, _ := cmd.Flags().GetString("profile-name")

	profile, err := (*a.profilesLoader).LoadProfile(profiles.DeduceProfileName(profileName))
	if err != nil || profile == nil {
		genKubeconfigExitErr("no idsec profile found — run 'idsec login' first to authenticate")
	}

	ispAuthenticator, ok := auth.SupportedAuthenticators["isp"]
	if !ok {
		genKubeconfigExitErr("ISP authenticator is not available in this build")
	}
	if _, hasISP := profile.AuthProfiles["isp"]; !hasISP {
		genKubeconfigExitErr(fmt.Sprintf("profile '%s' has no ISP auth configured — run 'idsec login' first", profile.ProfileName))
	}

	loadedToken, err := ispAuthenticator.LoadAuthentication(profile, false)
	if err != nil || loadedToken == nil {
		genKubeconfigExitErr("idsec session expired or not found — run 'idsec login' to re-authenticate")
	}

	svc, err := k8sservice.NewIdsecSCAK8sService(ispAuthenticator)
	if err != nil {
		genKubeconfigExitErr(fmt.Sprintf("failed to initialize SCA K8s service: %v", err))
	}
	return svc
}

// resolveGenerateKubeconfigFlags applies --csp / --all precedence for generate-kubeconfig.
func resolveGenerateKubeconfigFlags(cmd *cobra.Command) (csp string, allValue string, errMsg string) {
	rawCSP, _ := cmd.Flags().GetString("csp")
	csp = normalizeCSP(rawCSP)

	allValue, errMsg = resolveAllFlag()
	if errMsg != "" {
		return "", "", errMsg
	}

	if csp != "" && !isValidCSP(csp) {
		return "", "", fmt.Sprintf("invalid csp %q; use aws, azure, or gcp", strings.TrimSpace(rawCSP))
	}
	if csp == "" && allValue == "false" {
		return "", "", "with no --csp, --all=false or --all false is invalid; use --csp <aws|azure|gcp> or omit --all to generate for all CSPs"
	}
	return csp, allValue, ""
}

func resolveAllFlag() (string, string) {
	raw, ok := parseAllFlagFromArgv(argvAfterSubcommand(os.Args, "generate-kubeconfig"))
	if !ok {
		return "true", ""
	}
	if !isBoolString(raw) {
		return "", fmt.Sprintf(`invalid --all %q; use "true" or "false"`, raw)
	}
	return strings.ToLower(strings.TrimSpace(raw)), ""
}

// logDecodedResult prints verbose-only diagnostics about the decoded response.
// It helps debug backend/SDK response shape issues without affecting behavior.
func logDecodedResult(cmd *cobra.Command, result map[string]string) {
	keys := make([]string, 0, len(result))
	for k := range result {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%dB", k, len(result[k])))
	}
	printVerbose(cmd, "SDK decoded HTTP body — %d entries: %s", len(result), strings.Join(parts, ", "))
}

func printVerbose(cmd *cobra.Command, format string, v ...any) {
	verbose, err := cmd.Root().PersistentFlags().GetBool("verbose")
	if err != nil || !verbose {
		return
	}
	args.PrintNormal(fmt.Sprintf("[generate-kubeconfig] "+format, v...))
}

func genKubeconfigExitErr(msg string) {
	args.PrintFailure(fmt.Sprintf("idsec generate-kubeconfig: %s", msg))
	os.Exit(1)
}
