package actions

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth/identity"
	"github.com/cyberark/idsec-sdk-golang/pkg/models"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/profiles"
	k8sservice "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s"
	k8smodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s/models"
)

// kubectlLoginISPRefreshGrace aligns with the SDK’s default token refresh grace (see idsec-sdk auth).
const kubectlLoginISPRefreshGrace = 60 * time.Second

// IdsecKubectlLoginAction hooks kubectl exec-credential behaviour: hides `exec sca k8s elevate` from help,
// blocks its direct use with an error, and adds hidden `kubectl-login` as the sole exec credential plugin entry point.
type IdsecKubectlLoginAction struct {
	profilesLoader *profiles.ProfileLoader
}

func NewIdsecKubectlLoginAction(profilesLoader *profiles.ProfileLoader) *IdsecKubectlLoginAction {
	return &IdsecKubectlLoginAction{
		profilesLoader: profilesLoader,
	}
}

// DefineAction runs after exec SCA K8s actions are registered so findNestedCommand sees `elevate`.
func (a *IdsecKubectlLoginAction) DefineAction(cmd *cobra.Command) {
	if elevateCmd := findNestedCommand(cmd, "exec", "sca", "k8s", "elevate"); elevateCmd != nil {
		elevateCmd.Hidden = true
		elevateCmd.SilenceUsage = true
		elevateCmd.Run = func(cmd *cobra.Command, _ []string) {
			fmt.Fprintln(os.Stderr, "Error: 'exec sca k8s elevate' is not supported.")
			os.Exit(1)
		}
	}

	aliasCmd := &cobra.Command{
		Use:          "kubectl-login",
		Short:        "Alias for 'sca k8s elevate' — kubectl Exec Credential Plugin",
		Hidden:       true,
		SilenceUsage: true,
		Run:          a.runKubectlLoginAction,
	}
	addElevateFlags(aliasCmd)
	cmd.AddCommand(aliasCmd)
}

// addElevateFlags mirrors IdsecSCAK8sElevateKubectlRequest for the hidden `kubectl-login` alias only.
func addElevateFlags(c *cobra.Command) {
	c.Flags().String("csp", "", "Cloud provider: AWS or AZURE (required, case-insensitive)")
	c.Flags().String("role-id", "", "Cloud role ID to elevate (AWS IAM role ARN or Azure role definition resource ID)")
	c.Flags().String("fqdn", "", "Cluster API endpoint FQDN (e.g. xxxx.gr7.us-east-1.eks.amazonaws.com for EKS, <name>.hcp.<region>.azmk8s.io for AKS)")
	c.Flags().String("organization-id", "", "Azure Entra Directory ID (tenant) — required for Azure, ignored otherwise")
	c.Flags().String("namespace-id", "", "Optional Kubernetes namespace identifier (Azure)")
	c.Flags().Bool("verbose", false, "Print step-by-step diagnostics to stderr (also: IDSEC_VERBOSE=true or idsec --verbose kubectl-login …)")
}

// loadISPAuthTokenForKubectlLogin loads ISP token without interactive login where the identity cache allows it.
func loadISPAuthTokenForKubectlLogin(cmd *cobra.Command, ispAuthenticator auth.IdsecAuth, profile *models.IdsecProfile) (*authmodels.IdsecToken, error) {
	ispProf := profile.AuthProfiles["isp"]
	if ispProf == nil {
		return nil, fmt.Errorf("profile has no ISP auth profile")
	}
	if ispProf.AuthMethod != authmodels.Identity && ispProf.AuthMethod != authmodels.Default {
		kubectlLoginVerbose(cmd, "ISP auth method %q — loading session with refresh (no identity cache gate)", ispProf.AuthMethod)
		return ispAuthenticator.LoadAuthentication(profile, true)
	}

	kubectlLoginVerbose(cmd, "loading ISP session (phase: cache without refresh)")
	t, err := ispAuthenticator.LoadAuthentication(profile, false)
	if err != nil {
		return nil, err
	}
	if t != nil && time.Time(t.ExpiresIn).Add(-kubectlLoginISPRefreshGrace).After(time.Now()) {
		kubectlLoginVerbose(cmd, "ISP token still valid past refresh grace window")
		return t, nil
	}
	username := strings.TrimSpace(ispProf.Username)
	if username == "" {
		return nil, fmt.Errorf("ISP auth profile has no username")
	}
	kubectlLoginVerbose(cmd, "checking Identity keyring for silent refresh eligibility")
	if hasRec, herr := identity.HasCacheRecord(profile, username, true); herr != nil {
		return nil, fmt.Errorf("failed to read identity cache: %w", herr)
	} else if !hasRec {
		return nil, fmt.Errorf("idsec session missing or cache was cleared — run 'idsec login' to re-authenticate")
	}

	kubectlLoginVerbose(cmd, "loading ISP session with silent refresh")
	t, err = ispAuthenticator.LoadAuthentication(profile, true)
	switch {
	case err != nil:
		return nil, err
	case t == nil:
		return nil, fmt.Errorf("idsec session expired or not found — run 'idsec login' to re-authenticate")
	default:
		return t, nil
	}
}

func findNestedCommand(root *cobra.Command, names ...string) *cobra.Command {
	cur := root
	for _, name := range names {
		var next *cobra.Command
		for _, sub := range cur.Commands() {
			if sub.Name() == name {
				next = sub
				break
			}
		}
		if next == nil {
			return nil
		}
		cur = next
	}
	return cur
}

// runKubectlLoginAction: parse → profile → ISP → Evaluate → direct|proxy → ExecCredential JSON on stdout only.
func (a *IdsecKubectlLoginAction) runKubectlLoginAction(cmd *cobra.Command, _ []string) {
	startedAt := time.Now()
	defer func() {
		elapsed := time.Since(startedAt).Round(time.Millisecond)
		fmt.Fprintf(os.Stderr, "[kubectl-login] completed in %s\n", elapsed)
		kubectlLoginVerbose(cmd, "total elapsed %s", elapsed)
	}()

	kubectlLoginVerbose(cmd, "starting kubectl-login flow (verbose=%v)", kubectlLoginVerboseEnabled(cmd))

	csp, _ := cmd.Flags().GetString("csp")
	roleID, _ := cmd.Flags().GetString("role-id")
	fqdn, _ := cmd.Flags().GetString("fqdn")
	organizationID, _ := cmd.Flags().GetString("organization-id")
	namespaceID, _ := cmd.Flags().GetString("namespace-id")

	cspUpper := strings.ToUpper(strings.TrimSpace(csp))
	if cspUpper == "" {
		exitErr(cmd, "--csp is required (e.g. AWS or AZURE)")
	}
	if strings.TrimSpace(roleID) == "" {
		exitErr(cmd, "--role-id is required")
	}
	clusterFQDN := strings.TrimSpace(fqdn)
	if clusterFQDN == "" {
		exitErr(cmd, "--fqdn is required")
	}

	kubectlLoginVerbose(cmd, "flags: csp=%q roleId=%q fqdn=%q organizationId=%q namespaceId=%q",
		cspUpper, roleID, clusterFQDN, organizationID, namespaceID)

	profileName := profiles.DeduceProfileName("")
	kubectlLoginVerbose(cmd, "loading idsec profile %q", profileName)
	profile, err := (*a.profilesLoader).LoadProfile(profileName)
	if err != nil || profile == nil {
		exitErr(cmd, fmt.Sprintf("no idsec profile found — run 'idsec login' first to authenticate (profile=%q, err=%v)", profileName, err))
	}
	kubectlLoginVerbose(cmd, "loaded profile %q", profile.ProfileName)

	ispAuthenticator, ok := auth.SupportedAuthenticators["isp"]
	if !ok {
		exitErr(cmd, "ISP authenticator is not available in this build")
	}
	if _, hasISP := profile.AuthProfiles["isp"]; !hasISP {
		exitErr(cmd, fmt.Sprintf("profile '%s' has no ISP auth configured — run 'idsec login' first", profile.ProfileName))
	}

	kubectlLoginVerbose(cmd, "loading ISP session (no interactive prompt)")
	loadedToken, err := loadISPAuthTokenForKubectlLogin(cmd, ispAuthenticator, profile)
	if err != nil || loadedToken == nil {
		exitErr(cmd, "idsec session expired or not found — run 'idsec login' to re-authenticate")
	}
	kubectlLoginVerbose(cmd, "ISP session loaded for user %q", loadedToken.Username)

	svc, err := k8sservice.NewIdsecSCAK8sService(ispAuthenticator)
	if err != nil {
		exitErr(cmd, fmt.Sprintf("failed to initialize SCA K8s service: %v", err))
	}

	kubectlLoginVerbose(cmd, "calling EvaluateEligibility — csp=%q fqdn=%q", cspUpper, clusterFQDN)
	evalResp, err := svc.EvaluateEligibility(&k8smodels.IdsecSCAK8sEvaluateRequest{
		Targets: []k8smodels.IdsecSCAK8sEvaluateTarget{{FQDN: clusterFQDN}},
	}, cspUpper)
	if err != nil {
		exitErr(cmd, fmt.Sprintf("eligibility evaluation failed: %v", err))
	}
	logEvalVerbose := func(results []k8smodels.IdsecSCAK8sEvaluateResult) {
		if !kubectlLoginVerboseEnabled(cmd) {
			return
		}
		if len(results) == 0 {
			fmt.Fprintf(os.Stderr, "[kubectl-login] evaluate returned 0 targets\n")
			return
		}
		fmt.Fprintf(os.Stderr, "[kubectl-login] evaluate returned %d target(s):\n", len(results))
		for i := range results {
			r := &results[i]
			fqdn := ""
			if r.Target.FQDN != nil {
				fqdn = *r.Target.FQDN
			}
			fmt.Fprintf(os.Stderr, "[kubectl-login]   [%d] fqdn=%q roleId=%q connectionMethod=%q\n",
				i, fqdn, r.Role.ID, r.ConnectionMethod)
		}
	}
	if len(evalResp.Response) == 0 {
		logEvalVerbose(evalResp.Response)
		exitErr(cmd, "Cluster not found in eligibility evaluation.")
	}

	logEvalVerbose(evalResp.Response)

	evalResult := findMatchingEvalResult(evalResp.Response, clusterFQDN, roleID)
	if evalResult == nil {
		exitErr(cmd, fmt.Sprintf("user is not eligible for target (no evaluate result matched fqdn=%q roleId=%q)", clusterFQDN, roleID))
	}

	connectionMethod := strings.ToLower(strings.TrimSpace(evalResult.ConnectionMethod))
	kubectlLoginVerbose(cmd, "eligibility match: connectionMethod=%q", connectionMethod)

	clusterCtx := &k8sservice.IdsecSCAK8sClusterContext{
		CSP:            cspUpper,
		RoleID:         roleID,
		FQDN:           clusterFQDN,
		OrganizationID: organizationID,
		NamespaceID:    namespaceID,
		ElevateToken:   loadedToken.Token,
	}

	var execCred *k8smodels.IdsecSCAK8sExecCredential

	switch connectionMethod {
	case "direct":
		kubectlLoginVerbose(cmd, "entering direct flow")
		execCred = a.runDirectFlow(cmd, svc, cspUpper, roleID, clusterFQDN,
			organizationID, namespaceID, loadedToken.Username, clusterCtx)

	case "proxy":
		kubectlLoginVerbose(cmd, "entering proxy flow")
		execCred = a.runProxyFlow(cmd, svc, cspUpper, roleID, clusterFQDN,
			organizationID, namespaceID, loadedToken.Username, clusterCtx)

	default:
		exitErr(cmd, fmt.Sprintf("Unsupported or undefined connection method: %q", evalResult.ConnectionMethod))
	}

	kubectlLoginVerbose(cmd, "writing ExecCredential JSON to stdout")
	if err := json.NewEncoder(os.Stdout).Encode(execCred); err != nil {
		exitErr(cmd, fmt.Sprintf("failed to encode ExecCredential: %v", err))
	}
}

func findMatchingEvalResult(results []k8smodels.IdsecSCAK8sEvaluateResult, fqdn, roleID string) *k8smodels.IdsecSCAK8sEvaluateResult {
	if fqdn == "" || roleID == "" {
		return nil
	}
	for i := range results {
		r := &results[i]
		if r.Target.FQDN != nil && *r.Target.FQDN == fqdn && r.Role.ID == roleID {
			return r
		}
	}
	return nil
}

// resolveElevateResult returns cached Elevate data or calls the API; second value is true on cache hit.
func (a *IdsecKubectlLoginAction) resolveElevateResult(
	cmd *cobra.Command,
	svc *k8sservice.IdsecSCAK8sService,
	cspUpper, roleID, clusterFQDN, organizationID, namespaceID, ispUsername string,
	fallbackTTL time.Duration,
) (*k8smodels.IdsecSCAK8sElevateResult, bool) {
	kubectlLoginVerbose(cmd, "checking Elevate cache (fallbackTTL=%s)", fallbackTTL)

	cached, hitReason, missReason, err := LoadCachedElevateKeyringWithReason(cspUpper, roleID, clusterFQDN, ispUsername, fallbackTTL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to read cached Elevate credentials: %v\n", err)
	}

	if cached != nil {
		fmt.Fprintf(os.Stderr,
			"[kubectl-login] reusing cached Elevate result (sessionId=%q sessionExpTime=%q; %s)\n",
			cached.SessionID, cached.SessionExpTime, hitReason,
		)
		kubectlLoginVerbose(cmd, "Elevate cache hit — %s", hitReason)
		return cached, true
	}

	if missReason == "" {
		missReason = "no cached entry"
	}
	fmt.Fprintf(os.Stderr, "[kubectl-login] Elevate cache miss (%s) — calling Elevate API\n", missReason)

	elevateResp, err := svc.Elevate(&k8smodels.IdsecSCAK8sElevateKubectlRequest{
		CSP:            cspUpper,
		RoleID:         roleID,
		FQDN:           clusterFQDN,
		OrganizationID: organizationID,
		NamespaceID:    namespaceID,
	})
	if err != nil {
		exitErr(cmd, fmt.Sprintf("elevate API call failed: %v", err))
	}
	if len(elevateResp.Response.Results) == 0 {
		exitErr(cmd, "elevate API returned no results for the requested cluster/role")
	}

	elevateResult := &elevateResp.Response.Results[0]
	fmt.Fprintf(os.Stderr,
		"[kubectl-login] Elevate API response: organizationId=%q csp=%q sessionId=%q sessionExpTime=%q roleId=%q targetId=%q workspaceId=%q\n",
		elevateResp.Response.OrganizationID,
		elevateResp.Response.CSP,
		elevateResult.SessionID,
		elevateResult.SessionExpTime,
		elevateResult.RoleID,
		elevateResult.TargetID,
		elevateResult.WorkspaceID,
	)
	fmt.Fprintf(os.Stderr, "[kubectl-login] Elevate session expiry: %s\n", describeElevateSessionExpiry(elevateResult.SessionExpTime))
	kubectlLoginVerbose(cmd, "elevate succeeded — sessionId=%q sessionExpTime=%q targetId=%q",
		elevateResult.SessionID, elevateResult.SessionExpTime, elevateResult.TargetID)

	if saveErr := SaveCreds(cspUpper, roleID, clusterFQDN, ispUsername, elevateResult); saveErr != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to cache Elevate result (next run will call Elevate API again): %v\n", saveErr)
	} else {
		kubectlLoginVerbose(cmd, "cached Elevate result")
	}

	return elevateResult, false
}

func (a *IdsecKubectlLoginAction) runDirectFlow(
	cmd *cobra.Command,
	svc *k8sservice.IdsecSCAK8sService,
	cspUpper, roleID, clusterFQDN, organizationID, namespaceID, ispUsername string,
	clusterCtx *k8sservice.IdsecSCAK8sClusterContext,
) *k8smodels.IdsecSCAK8sExecCredential {
	provider, err := k8sservice.GetTokenProvider(cspUpper)
	if err != nil {
		exitErr(cmd, fmt.Sprintf("unsupported CSP %q: %v", cspUpper, err))
	}

	switch cspUpper {
	case "AWS":
		return a.runAWSDirectFlow(cmd, svc, provider, roleID, clusterFQDN,
			organizationID, namespaceID, ispUsername, clusterCtx)
	case "AZURE":
		return a.runAzureDirectFlow(cmd, svc, provider, roleID, clusterFQDN,
			organizationID, namespaceID, ispUsername, clusterCtx)
	default:
		exitErr(cmd, fmt.Sprintf("unsupported CSP %q for direct flow", cspUpper))
		return nil
	}
}

// runAWSDirectFlow implements the AWS EKS direct path:
//  1. Cached Elevate (SavedAt + ElevateTTL) or Elevate API
//  2. Parse EKS ARN from targetId → region + cluster name for STS presign
//  3. GenerateToken (STS presign) → ExecCredential bearer token
func (a *IdsecKubectlLoginAction) runAWSDirectFlow(
	cmd *cobra.Command,
	svc *k8sservice.IdsecSCAK8sService,
	provider k8sservice.IdsecSCAK8sTokenProvider,
	roleID, clusterFQDN, organizationID, namespaceID, ispUsername string,
	clusterCtx *k8sservice.IdsecSCAK8sClusterContext,
) *k8smodels.IdsecSCAK8sExecCredential {
	elevateResult, _ := a.resolveElevateResult(cmd, svc, "AWS", roleID, clusterFQDN,
		organizationID, namespaceID, ispUsername, provider.ElevateTTL())

	if elevateResult.TargetID != "" {
		region, clusterName, parseErr := k8sservice.ParseEKSARN(elevateResult.TargetID)
		if parseErr != nil {
			exitErr(cmd, fmt.Sprintf("failed to parse EKS ARN from elevate response targetId %q: %v", elevateResult.TargetID, parseErr))
		}
		clusterCtx.Region = region
		clusterCtx.ClusterID = clusterName
		kubectlLoginVerbose(cmd, "parsed EKS ARN — region=%q cluster=%q", region, clusterName)
	}

	kubectlLoginVerbose(cmd, "generating AWS token via direct provider")
	execCred, err := provider.GenerateToken(elevateResult, clusterCtx)
	if err != nil {
		exitErr(cmd, fmt.Sprintf("failed to generate AWS token: %v", err))
	}
	return execCred
}

// runAzureDirectFlow: (1) AKS keyring hit + unchanged az profile → BuildAzureExecCredential, no `az`.
// (2) AKS hit but profile moved → VerifyAzureCLISession, re-save fingerprint, BuildAzureExecCredential.
// (3–4) One EnsureAzureCLISession; on fresh Elevate, WaitForAzureRolePropagation(oid from that token); cache + BuildAzureExecCredential.
func (a *IdsecKubectlLoginAction) runAzureDirectFlow(
	cmd *cobra.Command,
	svc *k8sservice.IdsecSCAK8sService,
	provider k8sservice.IdsecSCAK8sTokenProvider,
	roleID, clusterFQDN, organizationID, namespaceID, ispUsername string,
	clusterCtx *k8sservice.IdsecSCAK8sClusterContext,
) *k8smodels.IdsecSCAK8sExecCredential {
	cached, hitReason, missReason, err := LoadCachedAKSToken("AZURE", roleID, clusterFQDN, ispUsername, organizationID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to read cached AKS token: %v\n", err)
	}
	if cached != nil {
		currentFP := AzureCLIFingerprint()
		if currentFP != "" && currentFP == cached.AzureCLIFingerprint {
			fmt.Fprintf(os.Stderr,
				"[kubectl-login] reusing cached AKS token (%s; local az state unchanged)\n",
				hitReason,
			)
			kubectlLoginVerbose(cmd, "AKS token fast-verify hit — %s", hitReason)
			return k8sservice.BuildAzureExecCredential(cached.Token)
		}

		liveToken, verifyErr := k8sservice.VerifyAzureCLISession(organizationID, clusterCtx.ElevateToken)
		if verifyErr != nil {
			fmt.Fprintf(os.Stderr,
				"[kubectl-login] cached AKS token not used (%s; az check: %v)\n",
				hitReason, verifyErr,
			)
			_ = DeleteCachedAKSToken("AZURE", roleID, clusterFQDN, ispUsername, organizationID)
			kubectlLoginVerbose(cmd, "AKS token cache invalidated — %v", verifyErr)
		} else {
			_ = SaveAKSToken("AZURE", roleID, clusterFQDN, ispUsername, organizationID, liveToken, AzureCLIFingerprint())
			fmt.Fprintf(os.Stderr,
				"[kubectl-login] reusing AKS token (%s; live az verification)\n",
				hitReason,
			)
			kubectlLoginVerbose(cmd, "AKS token cache hit with live az verification — %s", hitReason)
			return k8sservice.BuildAzureExecCredential(liveToken)
		}
	} else {
		kubectlLoginVerbose(cmd, "AKS token cache miss — %s", missReason)
	}

	elevateResult, elevateFromCache := a.resolveElevateResult(cmd, svc, "AZURE", roleID, clusterFQDN,
		organizationID, namespaceID, ispUsername, provider.ElevateTTL())

	subscriptionID := k8sservice.AzureSubscriptionFromTargetID(elevateResult.TargetID)
	kubectlLoginVerbose(cmd, "acquiring AKS token via az (fresh elevate=%v)", !elevateFromCache)
	accessToken, err := k8sservice.EnsureAzureCLISession(organizationID, clusterCtx.ElevateToken, subscriptionID)
	if err != nil {
		exitErr(cmd, fmt.Sprintf("azure CLI session required: %v", err))
	}

	if !elevateFromCache {
		principalOID, oidErr := k8sservice.ExtractAzurePrincipalOID(accessToken)
		if oidErr != nil {
			exitErr(cmd, fmt.Sprintf("failed to read principal OID from az access token: %v", oidErr))
		}
		if err := k8sservice.WaitForAzureRolePropagation(organizationID, elevateResult, principalOID); err != nil {
			exitErr(cmd, err.Error())
		}
	} else {
		kubectlLoginVerbose(cmd, "skipping role propagation (cached Elevate session still valid)")
	}

	if saveErr := SaveAKSToken("AZURE", roleID, clusterFQDN, ispUsername, organizationID, accessToken, AzureCLIFingerprint()); saveErr != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to cache AKS token: %v\n", saveErr)
	} else {
		kubectlLoginVerbose(cmd, "cached AKS token")
	}

	return k8sservice.BuildAzureExecCredential(accessToken)
}

func (a *IdsecKubectlLoginAction) runProxyFlow(
	cmd *cobra.Command,
	svc *k8sservice.IdsecSCAK8sService,
	cspUpper, roleID, clusterFQDN, organizationID, namespaceID, ispUsername string,
	clusterCtx *k8sservice.IdsecSCAK8sClusterContext,
) *k8smodels.IdsecSCAK8sExecCredential {
	switch cspUpper {
	case "AWS":
		return a.runAWSProxyFlow(cmd, svc, clusterCtx)
	case "AZURE":
		return a.runAzureProxyFlow(cmd, svc, roleID, clusterFQDN,
			organizationID, namespaceID, ispUsername, clusterCtx)
	default:
		exitErr(cmd, fmt.Sprintf("unsupported CSP %q for proxy flow", cspUpper))
		return nil
	}
}

func (a *IdsecKubectlLoginAction) runAWSProxyFlow(
	cmd *cobra.Command,
	svc *k8sservice.IdsecSCAK8sService,
	clusterCtx *k8sservice.IdsecSCAK8sClusterContext,
) *k8smodels.IdsecSCAK8sExecCredential {
	kubectlLoginVerbose(cmd, "generating AWS proxy ExecCredential")
	execCred, err := svc.GenerateProxyExecCredential("AWS", clusterCtx)
	if err != nil {
		exitErr(cmd, fmt.Sprintf("proxy credential generation failed: %v", err))
	}
	return execCred
}

func (a *IdsecKubectlLoginAction) runAzureProxyFlow(
	cmd *cobra.Command,
	svc *k8sservice.IdsecSCAK8sService,
	roleID, clusterFQDN, organizationID, namespaceID, ispUsername string,
	clusterCtx *k8sservice.IdsecSCAK8sClusterContext,
) *k8smodels.IdsecSCAK8sExecCredential {
	provider, err := k8sservice.GetTokenProvider("AZURE")
	if err != nil {
		exitErr(cmd, fmt.Sprintf("unsupported CSP %q: %v", "AZURE", err))
	}

	elevateResult, elevateFromCache := a.resolveElevateResult(cmd, svc, "AZURE", roleID, clusterFQDN,
		organizationID, namespaceID, ispUsername, provider.ElevateTTL())
	if !elevateFromCache {
		subscriptionID := k8sservice.AzureSubscriptionFromTargetID(elevateResult.TargetID)
		kubectlLoginVerbose(cmd, "ensuring az login before role propagation (proxy)")
		accessToken, err := k8sservice.EnsureAzureCLISession(organizationID, clusterCtx.ElevateToken, subscriptionID)
		if err != nil {
			exitErr(cmd, fmt.Sprintf("azure CLI session required: %v", err))
		}
		principalOID, err := k8sservice.ExtractAzurePrincipalOID(accessToken)
		if err != nil {
			exitErr(cmd, fmt.Sprintf("failed to extract principal OID from az token: %v", err))
		}
		kubectlLoginVerbose(cmd, "resolved az principal oid for role propagation (proxy)")
		if err := k8sservice.WaitForAzureRolePropagation(organizationID, elevateResult, principalOID); err != nil {
			exitErr(cmd, err.Error())
		}
	} else {
		kubectlLoginVerbose(cmd, "skipping role propagation (cached Elevate session still valid, proxy)")
	}

	kubectlLoginVerbose(cmd, "generating AZURE proxy ExecCredential")
	execCred, err := svc.GenerateProxyExecCredential("AZURE", clusterCtx)
	if err != nil {
		exitErr(cmd, fmt.Sprintf("proxy credential generation failed: %v", err))
	}
	return execCred
}

// kubectlLoginVerboseEnabled: IDSEC_VERBOSE and/or --verbose on this command or an ancestor.
func kubectlLoginVerboseEnabled(cmd *cobra.Command) bool {
	switch strings.TrimSpace(strings.ToLower(os.Getenv("IDSEC_VERBOSE"))) {
	case "1", "true", "yes", "on":
		return true
	}
	for c := cmd; c != nil; c = c.Parent() {
		for _, fs := range []*pflag.FlagSet{c.Flags(), c.PersistentFlags()} {
			if fs == nil {
				continue
			}
			f := fs.Lookup("verbose")
			if f == nil || !f.Changed {
				continue
			}
			if val, err := fs.GetBool("verbose"); err == nil && val {
				return true
			}
		}
	}
	return false
}

// kubectlLoginVerbose logs to stderr only (never stdout — kubectl parses ExecCredential there).
func kubectlLoginVerbose(cmd *cobra.Command, format string, args ...any) {
	if !kubectlLoginVerboseEnabled(cmd) {
		return
	}
	fmt.Fprintf(os.Stderr, "[kubectl-login] "+format+"\n", args...)
}

// exitErr writes the failure to stderr and exits; stdout stays unused on failure.
func exitErr(cmd *cobra.Command, msg string) {
	fmt.Fprintf(os.Stderr, "idsec kubectl-login: %s\n", msg)
	if cmd != nil && !kubectlLoginVerboseEnabled(cmd) {
		fmt.Fprintf(os.Stderr, "idsec kubectl-login: hint: re-run with --verbose or set IDSEC_VERBOSE=true for step-by-step diagnostics (stderr only)\n")
	}
	os.Exit(1)
}
