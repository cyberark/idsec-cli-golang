package actions

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/models"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/profiles"
	k8sservice "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s"
	k8smodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s/models"
)

// kubectlLoginISPRefreshGrace aligns with the SDK’s default token refresh grace (see idsec-sdk auth).
const kubectlLoginISPRefreshGrace = 60 * time.Second

// kubectlLoginSession carries ISP identity context threaded through cold-path flows.
type kubectlLoginSession struct {
	ispUsername      string
	sessionID        string
	idTokenExpiresAt time.Time
}

// kubectlLoginRequest bundles flag-derived cluster identity (SDK cluster context)
// with ISP session state for the kubectl-login cold path. cluster.Region,
// cluster.ClusterID, and cluster.JWEExtensionValue are populated during flow
// execution; callers must not assume they are set at construction time.
type kubectlLoginRequest struct {
	cluster *k8sservice.IdsecSCAK8sClusterContext
	session kubectlLoginSession
}

// buildKubectlLoginRequest assembles the per-invocation kubectl-login context
// from CLI flags and the loaded ISP session. cluster.Region, cluster.ClusterID,
// and cluster.JWEExtensionValue are filled in later by the active flow.
func buildKubectlLoginRequest(
	csp, roleID, fqdn, organizationID, namespaceID, elevateToken string,
	session kubectlLoginSession,
) *kubectlLoginRequest {
	return &kubectlLoginRequest{
		cluster: &k8sservice.IdsecSCAK8sClusterContext{
			CSP:            csp,
			RoleID:         roleID,
			FQDN:           fqdn,
			OrganizationID: organizationID,
			NamespaceID:    namespaceID,
			ElevateToken:   elevateToken,
		},
		session: session,
	}
}

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
			kubectlLoginError("'exec sca k8s elevate' is not supported.")
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
}

// loadISPAuthTokenForKubectlLogin loads ISP token without interactive login, refreshing silently when expired.
func loadISPAuthTokenForKubectlLogin(ispAuthenticator auth.IdsecAuth, profile *models.IdsecProfile) (*authmodels.IdsecToken, error) {
	ispProf := profile.AuthProfiles["isp"]
	if ispProf == nil {
		return nil, fmt.Errorf("profile has no ISP auth profile")
	}

	kubectlLoginVerbose("loading ISP session (phase: cache without refresh)")
	t, err := ispAuthenticator.LoadAuthentication(profile, false)
	if err != nil {
		return nil, err
	}
	if t != nil && time.Time(t.ExpiresIn).Add(-kubectlLoginISPRefreshGrace).After(time.Now()) {
		kubectlLoginVerbose("ISP token still valid past refresh grace window")
		return t, nil
	}

	kubectlLoginVerbose("loading ISP session with silent refresh")
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
	restoreLogEnv := setupKubectlLoginLogging()
	defer restoreLogEnv()

	startedAt := time.Now()
	defer func() {
		kubectlLoginInfo("total elapsed %s", time.Since(startedAt).Round(time.Millisecond))
	}()

	kubectlLoginInfo("starting kubectl-login flow (verbose=%v)", kubectlLoginDiagnosticsEnabled())

	csp, _ := cmd.Flags().GetString("csp")
	roleID, _ := cmd.Flags().GetString("role-id")
	fqdn, _ := cmd.Flags().GetString("fqdn")
	organizationID, _ := cmd.Flags().GetString("organization-id")
	namespaceID, _ := cmd.Flags().GetString("namespace-id")

	cspUpper := strings.ToUpper(strings.TrimSpace(csp))
	if cspUpper == "" {
		exitErr(fmt.Sprintf("--csp is required (e.g. %s or %s)", k8smodels.CSPAWS, k8smodels.CSPAzure))
	}
	if strings.TrimSpace(roleID) == "" {
		exitErr("--role-id is required")
	}
	clusterFQDN := strings.TrimSpace(fqdn)
	if clusterFQDN == "" {
		exitErr("--fqdn is required")
	}

	kubectlLoginVerbose("flags: csp=%q roleId=%q fqdn=%q organizationId=%q namespaceId=%q",
		cspUpper, roleID, clusterFQDN, organizationID, namespaceID)

	profileName := profiles.DeduceProfileName("")
	kubectlLoginVerbose("loading idsec profile %q", profileName)
	profileLoadStartedAt := time.Now()
	profile, err := (*a.profilesLoader).LoadProfile(profileName)
	if err != nil || profile == nil {
		exitErr(fmt.Sprintf("no idsec profile found — run 'idsec login' first to authenticate (profile=%q, err=%v)", profileName, err))
	}
	kubectlLoginVerboseDuration("profile load", profileLoadStartedAt)
	kubectlLoginVerbose("loaded profile %q", profile.ProfileName)

	authenticatorResolveStartedAt := time.Now()
	ispAuthenticator, ok := auth.SupportedAuthenticators["isp"]
	if !ok {
		exitErr("ISP authenticator is not available in this build")
	}
	if _, hasISP := profile.AuthProfiles["isp"]; !hasISP {
		exitErr(fmt.Sprintf("profile '%s' has no ISP auth configured — run 'idsec login' first", profile.ProfileName))
	}
	kubectlLoginVerboseDuration("ISP authenticator resolution", authenticatorResolveStartedAt)

	kubectlLoginVerbose("loading ISP session (no interactive prompt)")
	ispLoadStartedAt := time.Now()
	loadedToken, err := loadISPAuthTokenForKubectlLogin(ispAuthenticator, profile)
	if err != nil || loadedToken == nil {
		exitErr("idsec session expired or not found — run 'idsec login' to re-authenticate")
	}
	kubectlLoginVerboseDuration("ISP session load", ispLoadStartedAt)
	kubectlLoginInfo("ISP session loaded for user %q", loadedToken.Username)
	idTokenExpiresAt := time.Time(loadedToken.ExpiresIn)

	// Extract internal_session_id (sid) from the ISP token. This binds the unified
	// ExecCredential cache and the Elevate cache to the current Identity session,
	// so a full re-auth rotates both cache namespaces (no explicit clear required).
	// On any error we proceed with empty sid, which disables both caches for this
	// invocation (safe fall-through to the cold path).
	sidExtractStartedAt := time.Now()
	sessionID, sidErr := k8sservice.ExtractInternalSessionID(loadedToken.Token)
	if sidErr != nil {
		kubectlLoginVerbose("internal_session_id unavailable (%v) — unified and Elevate caches disabled this run", sidErr)
		sessionID = ""
	} else {
		kubectlLoginVerbose("extracted internal_session_id sid8=%q…", sessionID[:min(len(sessionID), 8)])
	}
	kubectlLoginVerboseDuration("internal_session_id extraction", sidExtractStartedAt)

	req := buildKubectlLoginRequest(cspUpper, roleID, clusterFQDN, organizationID, namespaceID, loadedToken.Token, kubectlLoginSession{
		ispUsername:      loadedToken.Username,
		sessionID:        sessionID,
		idTokenExpiresAt: idTokenExpiresAt,
	})
	req.cluster.Diagnostics = kubectlLoginDiagnosticsEnabled()

	if a.serveFromUnifiedCache(cmd, req) {
		return
	}

	serviceInitStartedAt := time.Now()
	svc, err := k8sservice.NewIdsecSCAK8sService(ispAuthenticator)
	if err != nil {
		exitErr(fmt.Sprintf("failed to initialize SCA K8s service: %v", err))
	}
	kubectlLoginVerboseDuration("SCA K8S service initialization", serviceInitStartedAt)

	kubectlLoginInfo("calling EvaluateEligibility — csp=%q fqdn=%q", cspUpper, clusterFQDN)
	evaluateStartedAt := time.Now()
	evalResp, err := svc.EvaluateEligibility(&k8smodels.IdsecSCAK8sEvaluateRequest{
		Targets: []k8smodels.IdsecSCAK8sEvaluateTarget{{FQDN: clusterFQDN}},
	}, cspUpper)
	if err != nil {
		exitErr(fmt.Sprintf("eligibility evaluation failed: %v", err))
	}
	kubectlLoginVerboseDuration("EvaluateEligibility API call", evaluateStartedAt)
	logEvalVerbose := func(results []k8smodels.IdsecSCAK8sEvaluateResult) {
		if !kubectlLoginDiagnosticsEnabled() {
			return
		}
		if len(results) == 0 {
			kubectlLoginVerbose("evaluate returned 0 targets")
			return
		}
		kubectlLoginVerbose("evaluate returned %d target(s):", len(results))
		for i := range results {
			r := &results[i]
			fqdn := ""
			if r.Target.FQDN != nil {
				fqdn = *r.Target.FQDN
			}
			kubectlLoginVerbose("  [%d] fqdn=%q roleId=%q connectionMethod=%q",
				i, fqdn, r.Role.ID, r.ConnectionMethod)
		}
	}
	if len(evalResp.Response) == 0 {
		logEvalVerbose(evalResp.Response)
		exitErr("Cluster not found in eligibility evaluation.")
	}

	logEvalVerbose(evalResp.Response)

	evalMatchStartedAt := time.Now()
	evalResult := findMatchingEvalResult(evalResp.Response, clusterFQDN, roleID)
	if evalResult == nil {
		exitErr(fmt.Sprintf("user is not eligible for target (no evaluate result matched fqdn=%q roleId=%q)", clusterFQDN, roleID))
	}
	kubectlLoginVerboseDuration("Evaluate result match", evalMatchStartedAt)

	connectionMethod := strings.ToLower(strings.TrimSpace(evalResult.ConnectionMethod))
	kubectlLoginInfo("eligibility match: connectionMethod=%q", connectionMethod)

	var execCred *k8smodels.IdsecSCAK8sExecCredential

	switch connectionMethod {
	case "direct":
		kubectlLoginInfo("entering direct flow")
		flowStartedAt := time.Now()
		execCred = a.runDirectFlow(cmd, svc, req)
		kubectlLoginVerboseDuration("direct flow", flowStartedAt)

	case "proxy":
		kubectlLoginInfo("entering proxy flow")
		flowStartedAt := time.Now()
		execCred = a.runProxyFlow(cmd, svc, req)
		kubectlLoginVerboseDuration("proxy flow", flowStartedAt)

	default:
		exitErr(fmt.Sprintf("Unsupported or undefined connection method: %q", evalResult.ConnectionMethod))
	}

	a.saveUnifiedExecCredential(cmd, req, connectionMethod, execCred)

	kubectlLoginInfo("writing ExecCredential JSON to stdout")
	if err := json.NewEncoder(os.Stdout).Encode(execCred); err != nil {
		exitErr(fmt.Sprintf("failed to encode ExecCredential: %v", err))
	}
}

// emitCachedExecCredential writes the cached ExecCredential JSON verbatim to
// stdout (kubectl parses stdout). The caller has already validated that the
// payload is non-empty and within its expirationTimestamp window.
func emitCachedExecCredential(cmd *cobra.Command, execCredJSON string) {
	kubectlLoginInfo("writing cached ExecCredential JSON to stdout (%d bytes)", len(execCredJSON))
	payload := strings.TrimRight(execCredJSON, "\n")
	if _, err := fmt.Fprintln(os.Stdout, payload); err != nil {
		exitErr(fmt.Sprintf("failed to write cached ExecCredential: %v", err))
	}
}

// serveFromUnifiedCache performs the pre-Evaluate unified cache lookup and,
// on a valid hit, emits the cached ExecCredential JSON to stdout. Returns true
// when the caller should return immediately; false means cold path should run.
//
// LoadUnifiedExecCredential performs integrity checks and cache invalidation
// (including Azure CLI fingerprint and probable 401 refresh detection) before
// any cached entry reaches this helper.
func (a *IdsecKubectlLoginAction) serveFromUnifiedCache(
	cmd *cobra.Command,
	req *kubectlLoginRequest,
) bool {
	if req.session.sessionID == "" {
		return false
	}
	cacheLookupStartedAt := time.Now()
	entry, hitReason, missReason, lookupErr := LoadUnifiedExecCredential(
		req.cluster.CSP, req.cluster.RoleID, req.cluster.FQDN, req.session.ispUsername, req.session.sessionID, "",
	)
	kubectlLoginVerboseDuration("unified cache lookup", cacheLookupStartedAt)
	if lookupErr != nil {
		kubectlLoginVerbose("unified cache read failed: %v", lookupErr)
	}
	if entry == nil {
		if missReason != "" {
			kubectlLoginInfo("unified cache miss (%s)", missReason)
		}
		return false
	}
	kubectlLoginInfo("unified cache HIT (%s/%s): %s",
		strings.ToLower(req.cluster.CSP), entry.Method, hitReason)
	emitCachedExecCredential(cmd, entry.ExecCredentialJSON)
	return true
}

// saveUnifiedExecCredential persists a freshly generated ExecCredential to
// the unified cache so the next kubectl invocation hits the pre-Evaluate
// fast path. It is a no-op when sessionID is empty or the credential lacks a
// status.expirationTimestamp. Save errors are logged but never fail the
// command — the freshly-built ExecCredential is still emitted to stdout by
// the caller.
//
// AzureCLIFingerprint is stamped on every Azure entry (direct AND proxy) so
// `az login --tenant=...` rotations invalidate cached creds for both
// connection methods uniformly.
func (a *IdsecKubectlLoginAction) saveUnifiedExecCredential(
	cmd *cobra.Command,
	req *kubectlLoginRequest,
	connectionMethod string,
	execCred *k8smodels.IdsecSCAK8sExecCredential,
) {
	if req.session.sessionID == "" {
		return
	}
	method := ExecCredMethodDirect
	if connectionMethod == "proxy" {
		method = ExecCredMethodProxy
	}
	fingerprint := ""
	if req.cluster.CSP == k8smodels.CSPAzure {
		fingerprint = AzureCLIFingerprint()
	}
	expiresAt, expErr := k8sservice.ProxyExecCredentialExpiresAt(execCred)
	if expErr != nil {
		kubectlLoginVerbose("skipping unified cache save: ExecCredential has no expirationTimestamp (%v)", expErr)
		return
	}
	execCredJSON, mErr := json.Marshal(execCred)
	if mErr != nil {
		kubectlLoginVerbose("skipping unified cache save: marshal failed (%v)", mErr)
		return
	}
	saveStartedAt := time.Now()
	if saveErr := SaveUnifiedExecCredential(
		req.cluster.CSP, req.cluster.RoleID, req.cluster.FQDN, req.session.ispUsername, req.session.sessionID,
		method, string(execCredJSON), expiresAt, fingerprint,
	); saveErr != nil {
		kubectlLoginVerbose("unified cache save failed (%v)", saveErr)
	} else {
		kubectlLoginVerbose("unified cache saved (method=%s expiresAt=%s)",
			method, expiresAt.Format(time.RFC3339))
	}
	kubectlLoginVerboseDuration("unified cache save", saveStartedAt)
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

// resolveElevateResult returns cached Elevate data or calls the API, plus a concrete Elevate expiry bound.
func (a *IdsecKubectlLoginAction) resolveElevateResult(
	cmd *cobra.Command,
	svc *k8sservice.IdsecSCAK8sService,
	req *kubectlLoginRequest,
	fallbackTTL time.Duration,
) (*k8smodels.IdsecSCAK8sElevateResult, bool, time.Time) {
	kubectlLoginVerbose("checking Elevate cache (fallbackTTL=%s)", fallbackTTL)

	cacheStartedAt := time.Now()
	cached, cachedSavedAt, hitReason, missReason, err := LoadCachedElevateKeyringWithReason(
		req.cluster.CSP, req.cluster.OrganizationID, req.cluster.RoleID, req.cluster.FQDN,
		req.session.ispUsername, req.session.sessionID, fallbackTTL,
	)
	if err != nil {
		kubectlLoginVerbose("failed to read cached Elevate credentials: %v", err)
	}
	kubectlLoginVerboseDuration("Elevate cache lookup", cacheStartedAt)

	if cached != nil {
		kubectlLoginVerbose(
			"reusing cached Elevate result (sessionId=%q sessionExpTime=%q; %s)",
			cached.SessionID, cached.SessionExpTime, hitReason,
		)
		elevateExp, source := deriveElevateExpiry(cached, cachedSavedAt, fallbackTTL, kubectlLoginDiagnosticsEnabled())
		if elevateExp.IsZero() {
			kubectlLoginVerbose("Elevate expiry bound from cache unavailable")
		} else {
			kubectlLoginVerbose("Elevate expiry bound from cache: %s source=%s",
				elevateExp.UTC().Format(time.RFC3339), source)
		}
		return cached, true, elevateExp
	}

	if missReason == "" {
		missReason = "no cached entry"
	}
	kubectlLoginInfo("Elevate cache miss (%s) — calling Elevate API", missReason)

	// elevateStartedAt anchors fallbackTTL when sessionExpTime is absent; keeping
	// the timestamp from before the API call makes the bound conservative.
	elevateStartedAt := time.Now()
	elevateResp, err := svc.Elevate(&k8smodels.IdsecSCAK8sElevateKubectlRequest{
		CSP:            req.cluster.CSP,
		RoleID:         req.cluster.RoleID,
		FQDN:           req.cluster.FQDN,
		OrganizationID: req.cluster.OrganizationID,
		NamespaceID:    req.cluster.NamespaceID,
	})
	if err != nil {
		exitErr(fmt.Sprintf("elevate API call failed: %v", err))
	}
	if len(elevateResp.Response.Results) == 0 {
		exitErr("elevate API returned no results for the requested cluster/role")
	}
	kubectlLoginVerboseDuration("Elevate API call", elevateStartedAt)

	elevateResult := &elevateResp.Response.Results[0]
	kubectlLoginVerbose(
		"Elevate API response: organizationId=%q csp=%q sessionId=%q sessionExpTime=%q roleId=%q targetId=%q workspaceId=%q",
		elevateResp.Response.OrganizationID,
		elevateResp.Response.CSP,
		elevateResult.SessionID,
		elevateResult.SessionExpTime,
		elevateResult.RoleID,
		elevateResult.TargetID,
		elevateResult.WorkspaceID,
	)
	kubectlLoginVerbose("Elevate session expiry: %s", describeElevateSessionExpiry(elevateResult.SessionExpTime))
	kubectlLoginVerbose("elevate succeeded — sessionId=%q sessionExpTime=%q targetId=%q",
		elevateResult.SessionID, elevateResult.SessionExpTime, elevateResult.TargetID)

	if saveErr := SaveCreds(req.cluster.CSP, req.cluster.OrganizationID, req.cluster.RoleID, req.cluster.FQDN, req.session.ispUsername, req.session.sessionID, elevateResult); saveErr != nil {
		kubectlLoginWarning("failed to cache Elevate result (next run will call Elevate API again): %v", saveErr)
	} else {
		kubectlLoginVerbose("cached Elevate result")
	}

	elevateExp, source := deriveElevateExpiry(elevateResult, elevateStartedAt, fallbackTTL, kubectlLoginDiagnosticsEnabled())
	if elevateExp.IsZero() {
		kubectlLoginVerbose("Elevate expiry bound from API unavailable")
	} else {
		kubectlLoginVerbose("Elevate expiry bound from API: %s source=%s",
			elevateExp.UTC().Format(time.RFC3339), source)
	}
	return elevateResult, false, elevateExp
}

// applyFlowExecCredentialTTL stamps status.expirationTimestamp on a freshly
// built ExecCredential using the flow-specific min() across every TTL candidate
// (SDK-stamped credential expiry, Elevate session, ISP id_token exp, and for
// Azure proxy the raw AKS JWT exp). Fails the command when any required
// candidate is missing so we never cache with an unbounded dimension.
func (a *IdsecKubectlLoginAction) applyFlowExecCredentialTTL(
	cmd *cobra.Command,
	flow execCredFlow,
	execCred *k8smodels.IdsecSCAK8sExecCredential,
	elevateExpiresAt time.Time,
	req *kubectlLoginRequest,
	aksAccessToken string,
) {
	if execCred == nil {
		return
	}
	candidates := execCredTTLCandidates(flow, execCred, elevateExpiresAt, req.session.idTokenExpiresAt, aksAccessToken)
	effective, picked, err := computeEffectiveExecCredentialExpiry(candidates...)
	kubectlLoginVerboseExecCredentialTTL(string(flow), candidates, effective, picked, err)
	if err != nil {
		exitErr(fmt.Sprintf("%s: %v", flow, err))
		return
	}
	execCred.Status.ExpirationTimestamp = effective.UTC().Format(time.RFC3339)
}

func (a *IdsecKubectlLoginAction) runDirectFlow(
	cmd *cobra.Command,
	svc *k8sservice.IdsecSCAK8sService,
	req *kubectlLoginRequest,
) *k8smodels.IdsecSCAK8sExecCredential {
	provider, err := k8sservice.GetTokenProvider(req.cluster.CSP)
	if err != nil {
		exitErr(fmt.Sprintf("unsupported CSP %q: %v", req.cluster.CSP, err))
	}

	switch req.cluster.CSP {
	case k8smodels.CSPAWS:
		return a.runAWSDirectFlow(cmd, svc, provider, req)
	case k8smodels.CSPAzure:
		return a.runAzureDirectFlow(cmd, svc, provider, req)
	default:
		exitErr(fmt.Sprintf("unsupported CSP %q for direct flow", req.cluster.CSP))
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
	req *kubectlLoginRequest,
) *k8smodels.IdsecSCAK8sExecCredential {
	elevateResult, _, elevateExpiresAt := a.resolveElevateResult(cmd, svc, req, provider.ElevateTTL())

	if elevateResult.TargetID != "" {
		region, clusterName, parseErr := k8sservice.ParseEKSARN(elevateResult.TargetID)
		if parseErr != nil {
			exitErr(fmt.Sprintf("failed to parse EKS ARN from elevate response targetId %q: %v", elevateResult.TargetID, parseErr))
		}
		req.cluster.Region = region
		req.cluster.ClusterID = clusterName
		kubectlLoginVerbose("parsed EKS ARN — region=%q cluster=%q", region, clusterName)
	}

	kubectlLoginInfo("generating AWS token via direct provider")
	generateStartedAt := time.Now()
	execCred, err := provider.GenerateToken(elevateResult, req.cluster)
	if err != nil {
		exitErr(fmt.Sprintf("failed to generate AWS token: %v", err))
	}
	a.applyFlowExecCredentialTTL(cmd, execCredFlowAWSDirect, execCred, elevateExpiresAt, req, "")
	kubectlLoginVerboseDuration("AWS direct token generation", generateStartedAt)
	return execCred
}

// acquireAzureAKSToken is the shared helper for both Azure direct and Azure proxy.
// It runs: Elevate (cache or API) → EnsureAzureCLISession → optional role propagation.
//
// Returns:
//   - accessToken:      the raw AKS access token from the Azure CLI.
//   - elevateFromCache: true when the Elevate result came from the keyring.
//   - elevateExpiresAt: concrete Elevate expiry bound for direct/proxy TTL min.
func (a *IdsecKubectlLoginAction) acquireAzureAKSToken(
	cmd *cobra.Command,
	svc *k8sservice.IdsecSCAK8sService,
	provider k8sservice.IdsecSCAK8sTokenProvider,
	req *kubectlLoginRequest,
) (accessToken string, elevateFromCache bool, elevateExpiresAt time.Time) {
	elevateResult, elevateFromCache, elevateExpiresAt := a.resolveElevateResult(cmd, svc, req, provider.ElevateTTL())

	subscriptionID := k8sservice.AzureSubscriptionFromTargetID(elevateResult.TargetID)
	kubectlLoginInfo("acquiring AKS token via az (fresh elevate=%v)", !elevateFromCache)
	var err error
	accessToken, err = k8sservice.EnsureAzureCLISession(req.cluster.OrganizationID, req.cluster.ElevateToken, subscriptionID, req.cluster.Diagnostics)
	if err != nil {
		exitErr(fmt.Sprintf("azure CLI session required: %v", err))
	}

	if !elevateFromCache {
		principalOID, oidErr := k8sservice.ExtractAzurePrincipalOID(accessToken)
		if oidErr != nil {
			exitErr(fmt.Sprintf("failed to read principal OID from az access token: %v", oidErr))
		}
		if err := k8sservice.WaitForAzureRolePropagation(req.cluster.OrganizationID, elevateResult, principalOID, kubectlLoginDiagnosticsEnabled()); err != nil {
			exitErr(err.Error())
		}
	} else {
		kubectlLoginInfo("skipping role propagation (cached Elevate session still valid)")
	}

	return accessToken, elevateFromCache, elevateExpiresAt
}

// runAzureDirectFlow runs the Azure direct cold path: acquireAzureAKSToken
// (Elevate + az + optional propagation) → BuildAzureExecCredential. The
// AzureCLIFingerprint-aware fast path now lives in the pre-Evaluate unified
// cache lookup at the top of runKubectlLoginAction; on a fingerprint mismatch
// the unified entry is purged and we land here.
func (a *IdsecKubectlLoginAction) runAzureDirectFlow(
	cmd *cobra.Command,
	svc *k8sservice.IdsecSCAK8sService,
	provider k8sservice.IdsecSCAK8sTokenProvider,
	req *kubectlLoginRequest,
) *k8smodels.IdsecSCAK8sExecCredential {
	accessToken, _, elevateExpiresAt := a.acquireAzureAKSToken(cmd, svc, provider, req)
	execCred := k8sservice.BuildAzureExecCredential(accessToken)
	a.applyFlowExecCredentialTTL(cmd, execCredFlowAzureDirect, execCred, elevateExpiresAt, req, "")
	return execCred
}

func (a *IdsecKubectlLoginAction) runProxyFlow(
	cmd *cobra.Command,
	svc *k8sservice.IdsecSCAK8sService,
	req *kubectlLoginRequest,
) *k8smodels.IdsecSCAK8sExecCredential {
	switch req.cluster.CSP {
	case k8smodels.CSPAWS:
		return a.runAWSProxyFlow(cmd, svc, req)
	case k8smodels.CSPAzure:
		return a.runAzureProxyFlow(cmd, svc, req)
	default:
		exitErr(fmt.Sprintf("unsupported CSP %q for proxy flow", req.cluster.CSP))
		return nil
	}
}

func (a *IdsecKubectlLoginAction) runAWSProxyFlow(
	cmd *cobra.Command,
	svc *k8sservice.IdsecSCAK8sService,
	req *kubectlLoginRequest,
) *k8smodels.IdsecSCAK8sExecCredential {
	kubectlLoginInfo("generating AWS proxy ExecCredential")
	proxyStartedAt := time.Now()
	execCred, err := svc.GenerateProxyExecCredential(k8smodels.CSPAWS, req.cluster)
	if err != nil {
		exitErr(fmt.Sprintf("proxy credential generation failed: %v", err))
	}
	a.applyFlowExecCredentialTTL(cmd, execCredFlowAWSProxy, execCred, time.Time{}, req, "")
	kubectlLoginVerboseDuration("AWS proxy ExecCredential generation", proxyStartedAt)
	return execCred
}

// runAzureProxyFlow implements the Azure AKS proxy cold path:
// acquireAzureAKSToken → set JWEExtensionValue → GenerateProxyExecCredential
// (DPA SSO acquire) → return cert/key ExecCredential. Caching of the resulting
// ExecCredential is handled by the unified cache layer in runKubectlLoginAction;
// nothing is persisted at this level. The AKS JWT itself is never cached.
func (a *IdsecKubectlLoginAction) runAzureProxyFlow(
	cmd *cobra.Command,
	svc *k8sservice.IdsecSCAK8sService,
	req *kubectlLoginRequest,
) *k8smodels.IdsecSCAK8sExecCredential {
	kubectlLoginVerbose("azure proxy flow: fqdn=%q role=%q user=%q",
		req.cluster.FQDN, req.cluster.RoleID, req.session.ispUsername)

	kubectlLoginInfo("azure proxy flow [1/2]: acquiring AKS token (Elevate → az CLI)")
	provider, err := k8sservice.GetTokenProvider(k8smodels.CSPAzure)
	if err != nil {
		exitErr(fmt.Sprintf("unsupported CSP %q: %v", k8smodels.CSPAzure, err))
	}
	accessToken, _, elevateExpiresAt := a.acquireAzureAKSToken(cmd, svc, provider, req)
	kubectlLoginInfo("azure proxy flow [1/2]: AKS token acquired (%d bytes)", len(accessToken))
	kubectlLoginVerbose("AKS token acquired (len=%d) — setting as jwe_extension_value", len(accessToken))

	req.cluster.JWEExtensionValue = accessToken
	kubectlLoginInfo("azure proxy flow [2/2]: calling DPA SSO acquire (DPA-K8S) with jwe_extension_value")
	kubectlLoginVerbose("generating AZURE proxy ExecCredential via DPA SSO acquire (jwe_extension_value set, len=%d)", len(accessToken))
	execCred, err := svc.GenerateProxyExecCredential(k8smodels.CSPAzure, req.cluster)
	if err != nil {
		exitErr(fmt.Sprintf("proxy credential generation failed: %v", err))
	}
	kubectlLoginInfo(
		"azure proxy flow [2/2]: DPA SSO acquire returned cert (%d bytes) and key (%d bytes)",
		len(execCred.Status.ClientCertificateData), len(execCred.Status.ClientKeyData),
	)

	a.applyFlowExecCredentialTTL(cmd, execCredFlowAzureProxy, execCred, elevateExpiresAt, req, accessToken)

	logProxyExecCredential(execCred, "from DPA SSO acquire")
	return execCred
}

// logProxyExecCredential logs a safe ExecCredential summary to stderr.
func logProxyExecCredential(cred *k8smodels.IdsecSCAK8sExecCredential, source string) {
	if cred == nil {
		return
	}
	kubectlLoginInfo(
		"proxy ExecCredential (%s): apiVersion=%s kind=%s cert=%d bytes key=%d bytes token_set=%v",
		source,
		cred.APIVersion,
		cred.Kind,
		len(cred.Status.ClientCertificateData),
		len(cred.Status.ClientKeyData),
		cred.Status.Token != "",
	)
}
