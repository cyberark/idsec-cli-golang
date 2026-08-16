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
	profileName string // idsec profile name (colon-sanitized before cache use)
	userUUID    string // user_uuid JWT claim — stable per-user identity
	sessionID   string // internal_session_id JWT claim — rotates cache namespace on re-auth
}

// kubectlLoginRequest bundles flag-derived cluster identity (SDK cluster context)
// with ISP session state for the kubectl-login cold path. cluster.Region,
// cluster.ClusterID, and cluster.K8sToken are populated during flow
// execution; callers must not assume they are set at construction time.
type kubectlLoginRequest struct {
	cluster *k8sservice.IdsecSCAK8sClusterContext
	session kubectlLoginSession
}

// buildKubectlLoginRequest assembles the per-invocation kubectl-login context
// from CLI flags and the loaded ISP session. cluster.Region, cluster.ClusterID,
// and cluster.K8sToken are filled in later by the active flow.
func buildKubectlLoginRequest(
	csp, roleID, fqdn, organizationID, namespace, elevateToken, clusterToken string,
	session kubectlLoginSession,
) *kubectlLoginRequest {
	return &kubectlLoginRequest{
		cluster: &k8sservice.IdsecSCAK8sClusterContext{
			CSP:            csp,
			RoleID:         roleID,
			FQDN:           fqdn,
			OrganizationID: organizationID,
			Namespace:      namespace,
			ElevateToken:   elevateToken,
			ClusterToken:   clusterToken,
		},
		session: session,
	}
}

// resolvedNamespace returns the parsed namespace name from the raw cluster namespace flag.
// The raw value is kept on cluster.Namespace for the Elevate API; this method is used for cache keying.
func (r *kubectlLoginRequest) resolvedNamespace() string {
	return k8sservice.ParseNamespaceName(r.cluster.Namespace)
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
	c.Flags().String("namespace", "", "Optional Kubernetes namespace (Azure)")
	c.Flags().String("cluster-token", "", "Base64-encoded cluster token injected by SIA (optional, backward-compatible)")
}

// loadISPAuthTokenForKubectlLogin loads ISP auth without interactive login.
// oldSessionID is the pre-refresh SID when a silent refresh ran (else empty).
func loadISPAuthTokenForKubectlLogin(ispAuthenticator auth.IdsecAuth, profile *models.IdsecProfile, profileName string) (token *authmodels.IdsecToken, oldSessionID string, err error) {
	ispProf := profile.AuthProfiles["isp"]
	if ispProf == nil {
		return nil, "", fmt.Errorf("profile has no ISP auth profile")
	}

	kubectlLoginVerbose("loading ISP session (phase: cache without refresh)")
	t, err := ispAuthenticator.LoadAuthentication(profile, false)
	if err != nil {
		return nil, "", err
	}
	if t != nil && time.Time(t.ExpiresIn).Add(-kubectlLoginISPRefreshGrace).After(time.Now()) {
		kubectlLoginVerbose("ISP token still valid past refresh grace window")
		kubectlLoginVerbose("ISP token still valid — no SID remap")
		return t, "", nil
	}

	hasCache, preClaims, cacheErr := loadCachedISPSession(profile, ispProf.Username)
	if cacheErr != nil {
		return nil, "", cacheErr
	}
	if !hasCache {
		return nil, "", fmt.Errorf("idsec session expired or not found — run 'idsec login' to re-authenticate")
	}
	oldSessionID = preClaims.SessionID
	if oldSessionID == "" || preClaims.UserUUID == "" {
		kubectlLoginVerbose("cached ISP token missing sid/uuid claims — refresh may still succeed")
	}

	kubectlLoginVerbose("loading ISP session with silent refresh")
	t, err = ispAuthenticator.LoadAuthentication(profile, true)
	switch {
	case err != nil:
		purgeUserCacheEntries(profileName, preClaims.UserUUID)
		return nil, "", err
	case t == nil:
		purgeUserCacheEntries(profileName, preClaims.UserUUID)
		return nil, "", fmt.Errorf("idsec session expired or not found — run 'idsec login' to re-authenticate")
	default:
		return t, oldSessionID, nil
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
	namespace, _ := cmd.Flags().GetString("namespace")
	clusterToken, _ := cmd.Flags().GetString("cluster-token")

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

	kubectlLoginVerbose("flags: csp=%q roleId=%q fqdn=%q organizationId=%q namespace=%q clusterTokenLen=%d",
		cspUpper, roleID, clusterFQDN, organizationID, namespace, len(clusterToken))

	profileName := profiles.DeduceProfileName("")
	if strings.TrimSpace(profileName) == "" {
		exitErr("could not determine idsec profile name — run 'idsec login' first")
	}
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
	loadedToken, oldSessionID, err := loadISPAuthTokenForKubectlLogin(ispAuthenticator, profile, profileName)
	if err != nil || loadedToken == nil {
		exitErr("idsec session expired or not found — run 'idsec login' to re-authenticate")
	}
	kubectlLoginVerboseDuration("ISP session load", ispLoadStartedAt)
	kubectlLoginInfo("ISP session loaded for user %q", loadedToken.Username)

	// Extract internal_session_id and user_uuid from the ISP token in a single parse.
	// Both are mandatory for cache keying; missing either is a token integrity problem
	// — the user must re-authenticate to get a valid token.
	claimsExtractStartedAt := time.Now()
	ispClaims, claimsErr := k8sservice.ExtractISPSessionClaims(loadedToken.Token)
	kubectlLoginVerboseDuration("ISP JWT claims extraction", claimsExtractStartedAt)
	if claimsErr != nil {
		exitErr(fmt.Sprintf("ISP token could not be parsed — run 'idsec login' to re-authenticate: %v", claimsErr))
	}
	if ispClaims.SessionID == "" {
		exitErr("ISP token is missing required claim 'internal_session_id' — run 'idsec login' to re-authenticate")
	}
	if ispClaims.UserUUID == "" {
		exitErr("ISP token is missing required claim 'user_uuid' — run 'idsec login' to re-authenticate")
	}
	kubectlLoginVerbose("extracted internal_session_id sid8=%q…", ispClaims.SessionID[:min(len(ispClaims.SessionID), 8)])
	kubectlLoginVerbose("extracted user_uuid=%q", ispClaims.UserUUID)

	// Silent refresh may rotate internal_session_id for the same user (e.g. Entra AD).
	// Remap session-scoped caches (elevate, execcred, AWS IDC OIDC) so other
	// terminals/clusters stay warm under the new SID.
	sessionIDRotated := oldSessionID != "" && oldSessionID != ispClaims.SessionID
	if sessionIDRotated {
		kubectlLoginInfo("silent refresh rotated SID sid8=%q… → %q… — remapping cache keys",
			sid8(oldSessionID), sid8(ispClaims.SessionID))
		remapUserCacheSessionKeys(profileName, ispClaims.UserUUID, oldSessionID, ispClaims.SessionID)
	} else if oldSessionID != "" {
		kubectlLoginVerbose("silent refresh SID unchanged sid8=%q…", sid8(ispClaims.SessionID))
	}

	req := buildKubectlLoginRequest(cspUpper, roleID, clusterFQDN, organizationID, namespace, loadedToken.Token, clusterToken, kubectlLoginSession{
		profileName: profileName,
		userUUID:    ispClaims.UserUUID,
		sessionID:   ispClaims.SessionID,
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
	evalResult := findMatchingEvalResult(evalResp.Response, clusterFQDN, roleID, namespace)
	if evalResult == nil {
		if strings.TrimSpace(namespace) != "" {
			exitErr(fmt.Sprintf(
				"user is not eligible for target (no evaluate result matched fqdn=%q roleId=%q namespace=%q)",
				clusterFQDN, roleID, namespace,
			))
		}
		exitErr(fmt.Sprintf("user is not eligible for target (no evaluate result matched fqdn=%q roleId=%q)", clusterFQDN, roleID))
	}
	kubectlLoginVerboseDuration("Evaluate result match", evalMatchStartedAt)

	// Always capture cluster CA from evaluate (direct and proxy). Azure / AWS IDC
	// proxy flows encrypt it into the DPA JWE as root_ca for proxy→cluster mTLS.
	req.cluster.RootCA = strings.TrimSpace(evalResult.CertificateData)

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
	if req.session.sessionID == "" || req.session.userUUID == "" {
		return false
	}
	namespace := req.resolvedNamespace()
	cacheLookupStartedAt := time.Now()
	entry, hitReason, missReason, lookupErr := LoadUnifiedExecCredential(
		req.session.profileName, req.cluster.CSP, req.cluster.RoleID, req.cluster.FQDN,
		req.session.userUUID, namespace, req.session.sessionID, "",
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
	if req.session.sessionID == "" || req.session.userUUID == "" {
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
	namespace := req.resolvedNamespace()
	saveStartedAt := time.Now()
	if saveErr := SaveUnifiedExecCredential(
		req.session.profileName, req.cluster.CSP, req.cluster.RoleID, req.cluster.FQDN,
		req.session.userUUID, namespace, req.session.sessionID,
		method, string(execCredJSON), expiresAt, fingerprint,
	); saveErr != nil {
		kubectlLoginVerbose("unified cache save failed (%v)", saveErr)
	} else {
		kubectlLoginVerbose("unified cache saved (method=%s expiresAt=%s)",
			method, expiresAt.Format(time.RFC3339))
	}
	kubectlLoginVerboseDuration("unified cache save", saveStartedAt)
}

// evalResultNamespaceName returns the namespace name from an evaluate target, normalizing
// Azure resource IDs via ParseNamespaceName. Empty when the target is cluster-scoped.
func evalResultNamespaceName(target k8smodels.IdsecSCAk8sListClustersTarget) string {
	if target.NamespaceID == nil {
		return ""
	}
	return k8sservice.ParseNamespaceName(*target.NamespaceID)
}

// findMatchingEvalResult selects the evaluate entry for the requested cluster role.
// When namespace is set on the kubeconfig user exec args, results must also match that
// namespace (after normalization). When namespace is omitted, matching is fqdn+roleId
// only and the first matching entry wins (existing behaviour).
func findMatchingEvalResult(results []k8smodels.IdsecSCAK8sEvaluateResult, fqdn, roleID, namespace string) *k8smodels.IdsecSCAK8sEvaluateResult {
	if fqdn == "" || roleID == "" {
		return nil
	}
	requestedNamespace := k8sservice.ParseNamespaceName(namespace)
	for i := range results {
		r := &results[i]
		if r.Target.FQDN == nil || *r.Target.FQDN != fqdn || r.Role.ID != roleID {
			continue
		}
		if requestedNamespace != "" && evalResultNamespaceName(r.Target) != requestedNamespace {
			continue
		}
		return r
	}
	return nil
}

// resolveElevateResult returns cached Elevate data or calls the API, plus a
// concrete Elevate expiry bound derived from sessionExpTime. Fails the process
// if the Elevate API response is missing sessionExpTime.
func (a *IdsecKubectlLoginAction) resolveElevateResult(
	cmd *cobra.Command,
	svc *k8sservice.IdsecSCAK8sService,
	req *kubectlLoginRequest,
) (*k8smodels.IdsecSCAK8sElevateResult, bool, time.Time) {
	kubectlLoginVerbose("checking Elevate cache")

	cacheStartedAt := time.Now()
	namespace := req.resolvedNamespace()
	cached, hitReason, missReason, err := LoadCachedElevateKeyringWithReason(
		req.session.profileName, req.cluster.CSP, req.cluster.RoleID, req.cluster.FQDN,
		req.session.userUUID, namespace, req.session.sessionID,
	)
	if err != nil {
		kubectlLoginVerbose("failed to read cached Elevate credentials: %v", err)
	}
	kubectlLoginVerboseDuration("Elevate cache lookup", cacheStartedAt)

	if cached != nil {
		if k8sservice.IsAWSIDCPermissionSetRole(cached.RoleID) {
			if vErr := k8sservice.ValidateAWSIDCDeviceRegistration(cached); vErr != nil {
				kubectlLoginWarning(
					"cached Elevate result missing required AWS IDC fields (%v) — calling Elevate API for fresh data",
					vErr,
				)
				cached = nil
				missReason = "cached entry missing required AWS IDC fields"
			}
		}
	}

	if cached != nil {
		kubectlLoginVerbose(
			"reusing cached Elevate result (sessionId=%q sessionExpTime=%q; %s)",
			cached.SessionID, cached.SessionExpTime, hitReason,
		)
		elevateExp, expErr := deriveElevateExpiry(cached)
		if expErr != nil {
			exitErr(fmt.Sprintf("cached Elevate result has invalid session expiry: %v", expErr))
		}
		kubectlLoginVerbose("Elevate expiry from cache: %s", elevateExp.UTC().Format(time.RFC3339))
		return cached, true, elevateExp
	}

	if missReason == "" {
		missReason = "no cached entry"
	}

	elevateStartedAt := time.Now()
	kubectlLoginInfo("Elevate cache miss (%s) — calling Elevate API", missReason)

	elevateResp, err := svc.Elevate(&k8smodels.IdsecSCAK8sElevateKubectlRequest{
		CSP:            req.cluster.CSP,
		RoleID:         req.cluster.RoleID,
		FQDN:           req.cluster.FQDN,
		OrganizationID: req.cluster.OrganizationID,
		Namespace:      req.cluster.Namespace,
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

	elevateExp, expErr := deriveElevateExpiry(elevateResult)
	if expErr != nil {
		exitErr(expErr.Error())
	}

	kubectlLoginVerbose("elevate succeeded — sessionId=%q sessionExpTime=%s targetId=%q",
		elevateResult.SessionID, elevateExp.UTC().Format(time.RFC3339), elevateResult.TargetID)

	if saveErr := SaveElevateCreds(req.session.profileName, req.cluster.CSP, req.cluster.RoleID, req.cluster.FQDN, req.session.userUUID, namespace, req.session.sessionID, elevateResult); saveErr != nil {
		kubectlLoginWarning("failed to cache Elevate result (next run will call Elevate API again): %v", saveErr)
	} else {
		kubectlLoginVerbose("cached Elevate result")
	}

	return elevateResult, false, elevateExp
}

// applyFlowExecCredentialTTL stamps status.expirationTimestamp on a freshly
// built ExecCredential using the flow-specific min() across every TTL candidate
// (SDK-stamped credential expiry, Elevate session, and for Azure proxy the raw
// AKS JWT exp). Fails the command when any required candidate is missing so we
// never cache with an unbounded dimension.
func (a *IdsecKubectlLoginAction) applyFlowExecCredentialTTL(
	cmd *cobra.Command,
	flow execCredFlow,
	execCred *k8smodels.IdsecSCAK8sExecCredential,
	elevateExpiresAt time.Time,
	aksAccessToken string,
) {
	if execCred == nil {
		return
	}
	candidates := execCredTTLCandidates(flow, execCred, elevateExpiresAt, aksAccessToken)
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

// runAWSDirectFlow dispatches the AWS EKS direct path to the appropriate sub-flow
// based on whether the role is an IAM Identity Center permission-set or a plain IAM role.
func (a *IdsecKubectlLoginAction) runAWSDirectFlow(
	cmd *cobra.Command,
	svc *k8sservice.IdsecSCAK8sService,
	provider k8sservice.IdsecSCAK8sTokenProvider,
	req *kubectlLoginRequest,
) *k8smodels.IdsecSCAK8sExecCredential {
	if k8sservice.IsAWSIDCPermissionSetRole(req.cluster.RoleID) {
		return a.runAWSIDCDirectFlow(cmd, svc, provider, req)
	}
	return a.runAWSIAMDirectFlow(cmd, svc, provider, req)
}

// runAWSIDCDirectFlow implements the AWS IDC permission-set direct path:
//  1. Cached Elevate (sessionExpTime-based) or Elevate API
//  2. Parse EKS ARN from targetId → region + cluster name
//  3. HydrateAWSAccessCredentialsFromElevate (device registration → GetRoleCredentials)
//  4. GenerateToken (client-side STS presign) → ExecCredential bearer token
func (a *IdsecKubectlLoginAction) runAWSIDCDirectFlow(
	cmd *cobra.Command,
	svc *k8sservice.IdsecSCAK8sService,
	provider k8sservice.IdsecSCAK8sTokenProvider,
	req *kubectlLoginRequest,
) *k8smodels.IdsecSCAK8sExecCredential {
	kubectlLoginInfo("AWS flow selected: IDC permission-set (device registration → STS → EKS token)")

	elevateResult, _, elevateExpiresAt := a.resolveElevateResult(cmd, svc, req)

	if elevateResult.TargetID != "" {
		region, clusterName, parseErr := k8sservice.ParseEKSARN(elevateResult.TargetID)
		if parseErr != nil {
			exitErr(fmt.Sprintf("failed to parse EKS ARN from elevate response targetId %q: %v", elevateResult.TargetID, parseErr))
		}
		req.cluster.Region = region
		req.cluster.ClusterID = clusterName
		kubectlLoginVerbose("parsed EKS ARN — region=%q cluster=%q", region, clusterName)
	}

	kubectlLoginInfo("hydrating AWS IDC credentials via device registration")
	oidcCache := NewAWSIDCOIDCCache(
		req.session.profileName,
		req.cluster.CSP,
		req.cluster.RoleID,
		req.cluster.FQDN,
		req.session.userUUID,
		req.resolvedNamespace(),
		req.session.sessionID,
	)
	if err := k8sservice.HydrateAWSAccessCredentialsFromElevate(
		elevateResult,
		req.cluster.Diagnostics,
		oidcCache,
	); err != nil {
		exitErr(fmt.Sprintf("failed to obtain AWS IDC credentials: %v", err))
	}

	kubectlLoginInfo("generating AWS token via direct provider")
	generateStartedAt := time.Now()
	execCred, err := provider.GenerateToken(elevateResult, req.cluster)
	if err != nil {
		exitErr(fmt.Sprintf("failed to generate AWS token: %v", err))
	}
	a.applyFlowExecCredentialTTL(cmd, execCredFlowAWSIDCDirect, execCred, elevateExpiresAt, "")
	kubectlLoginVerboseDuration("AWS IDC direct token generation", generateStartedAt)
	return execCred
}

// runAWSIAMDirectFlow implements the AWS IAM role direct path with two sub-paths
// determined by which Elevate API format is cached:
//
//  1. Check the Elevate cache via LoadCachedElevateKeyringWithReason.
//  2. Old format (accessCredentials present, eksToken absent): cache hit → skip Elevate API
//     entirely and generate the EKS token client-side from the cached STS credentials.
//     STS credentials are valid for ~1 hour, so this is safe until sessionExpTime.
//  3. New format (eksToken present): eksToken has a 15-min hard ceiling, so always call the
//     Elevate API for a fresh token. Pass the cached sessionId (if any) to continue the
//     existing SCA session without starting a new one.
//  4. Cache miss → call Elevate API without a sessionId (cold start).
//  5. Parse EKS ARN from targetId → region + cluster name.
//  6. Persist the fresh Elevate result for reuse on the next invocation.
//  7. GenerateToken → ExecCredential bearer token.
func (a *IdsecKubectlLoginAction) runAWSIAMDirectFlow(
	cmd *cobra.Command,
	svc *k8sservice.IdsecSCAK8sService,
	provider k8sservice.IdsecSCAK8sTokenProvider,
	req *kubectlLoginRequest,
) *k8smodels.IdsecSCAK8sExecCredential {
	kubectlLoginInfo("AWS flow selected: IAM role (server-side EKS token)")
	namespace := req.resolvedNamespace()

	cached, hitReason, missReason, cacheErr := LoadCachedElevateKeyringWithReason(
		req.session.profileName, req.cluster.CSP, req.cluster.RoleID, req.cluster.FQDN,
		req.session.userUUID, namespace, req.session.sessionID,
	)
	if cacheErr != nil {
		kubectlLoginVerbose("failed to read Elevate cache: %v", cacheErr)
	}

	// Old Elevate API (accessCredentials, no eksToken): cached STS credentials are valid for ~1 hour.
	// Skip the Elevate API and generate the EKS token client-side — restores pre-eksToken behaviour.
	if cached != nil && strings.TrimSpace(cached.EKSToken) == "" {
		kubectlLoginInfo("Elevate cache HIT (accessCredentials format — skipping Elevate API): %s", hitReason)
		elevateExpiresAt, expErr := deriveElevateExpiry(cached)
		if expErr != nil {
			exitErr(expErr.Error())
		}
		if cached.TargetID != "" {
			region, clusterName, parseErr := k8sservice.ParseEKSARN(cached.TargetID)
			if parseErr != nil {
				exitErr(fmt.Sprintf("failed to parse EKS ARN from cached Elevate targetId %q: %v", cached.TargetID, parseErr))
			}
			req.cluster.Region = region
			req.cluster.ClusterID = clusterName
			kubectlLoginVerbose("parsed EKS ARN — region=%q cluster=%q", region, clusterName)
		}
		generateStartedAt := time.Now()
		execCred, err := provider.GenerateToken(cached, req.cluster)
		if err != nil {
			exitErr(fmt.Sprintf("failed to generate AWS token: %v", err))
		}
		a.applyFlowExecCredentialTTL(cmd, execCredFlowAWSDirect, execCred, elevateExpiresAt, "")
		kubectlLoginVerboseDuration("AWS IAM direct token generation", generateStartedAt)
		return execCred
	}

	// New Elevate API (eksToken): 15-min hard ceiling means the cached token is unusable by the time
	// the ExecCredential cache expires. Always call the API for a fresh token; pass the cached
	// sessionId (if available) so the server continues the existing SCA session.
	cachedSessionID := ""
	elevateCacheKey := buildSCAK8sCacheKey(req.session.profileName, req.cluster.CSP, req.cluster.RoleID,
		req.cluster.FQDN, req.session.userUUID, namespace, req.session.sessionID)
	if cached != nil {
		cachedSessionID = strings.TrimSpace(cached.SessionID)
		if cachedSessionID != "" {
			kubectlLoginVerbose("elevate: reusing cached sessionId=%q for EKS token refresh", sid8(cachedSessionID))
		}
	} else {
		if missReason == "" {
			missReason = "no cached entry"
		}
		kubectlLoginVerbose("elevate: no valid cached sessionId — starting new session (%s)", missReason)
	}

	elevateStartedAt := time.Now()
	kubectlLoginInfo("calling Elevate API (hasCachedSession=%v)", cachedSessionID != "")
	elevateResp, err := svc.Elevate(&k8smodels.IdsecSCAK8sElevateKubectlRequest{
		CSP:            req.cluster.CSP,
		RoleID:         req.cluster.RoleID,
		FQDN:           req.cluster.FQDN,
		OrganizationID: req.cluster.OrganizationID,
		SessionID:      cachedSessionID,
	})
	if err != nil {
		if cachedSessionID != "" {
			// The forwarded sessionId may have been revoked server-side. Delete the
			// cache entry so the next invocation starts a fresh session.
			if impl, kErr := krElevateCreds.get(); kErr == nil {
				_ = impl.DeletePassword(elevateCredsServiceName, elevateCacheKey)
				kubectlLoginVerbose("cleared elevate cache after Elevate API error (sessionId may have been revoked)")
			}
		}
		exitErr(fmt.Sprintf("elevate API call failed: %v", err))
	}
	if len(elevateResp.Response.Results) == 0 {
		exitErr("elevate API returned no results for the requested cluster/role")
	}
	kubectlLoginVerboseDuration("Elevate API call", elevateStartedAt)

	elevateResult := &elevateResp.Response.Results[0]
	kubectlLoginVerbose(
		"Elevate response: sessionId=%q sessionExpTime=%q eksToken_len=%d targetId=%q",
		elevateResult.SessionID, elevateResult.SessionExpTime, len(elevateResult.EKSToken), elevateResult.TargetID,
	)

	if elevateResult.TargetID != "" {
		region, clusterName, parseErr := k8sservice.ParseEKSARN(elevateResult.TargetID)
		if parseErr != nil {
			exitErr(fmt.Sprintf("failed to parse EKS ARN from elevate response targetId %q: %v", elevateResult.TargetID, parseErr))
		}
		req.cluster.Region = region
		req.cluster.ClusterID = clusterName
		kubectlLoginVerbose("parsed EKS ARN — region=%q cluster=%q", region, clusterName)
	}

	elevateExpiresAt, expErr := deriveElevateExpiry(elevateResult)
	if expErr != nil {
		exitErr(expErr.Error())
	}

	if saveErr := SaveElevateCreds(
		req.session.profileName, req.cluster.CSP, req.cluster.RoleID, req.cluster.FQDN,
		req.session.userUUID, namespace, req.session.sessionID, elevateResult,
	); saveErr != nil {
		kubectlLoginWarning("failed to cache Elevate result (next run will call Elevate API without sessionId): %v", saveErr)
	} else {
		kubectlLoginVerbose("cached Elevate result (sessionId=%q sessionExpTime=%q)", elevateResult.SessionID, elevateResult.SessionExpTime)
	}

	kubectlLoginInfo("generating AWS token via direct provider")
	generateStartedAt := time.Now()
	execCred, err := provider.GenerateToken(elevateResult, req.cluster)
	if err != nil {
		exitErr(fmt.Sprintf("failed to generate AWS token: %v", err))
	}
	a.applyFlowExecCredentialTTL(cmd, execCredFlowAWSDirect, execCred, elevateExpiresAt, "")
	kubectlLoginVerboseDuration("AWS IAM direct token generation", generateStartedAt)
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
	elevateResult, elevateFromCache, elevateExpiresAt := a.resolveElevateResult(cmd, svc, req)

	subscriptionID := k8sservice.AzureSubscriptionFromTargetID(elevateResult.TargetID)
	kubectlLoginInfo("acquiring AKS token via az (fresh elevate=%v)", !elevateFromCache)
	var err error
	accessToken, err = k8sservice.EnsureAzureCLISession(req.cluster.OrganizationID, req.cluster.ElevateToken, subscriptionID, req.cluster.Diagnostics)
	if err != nil {
		exitErr(fmt.Sprintf("azure CLI session required: %v", err))
	}

	switch {
	case elevateFromCache:
		kubectlLoginVerbose("skipping role propagation (cached Elevate session still valid)")
	case strings.TrimSpace(req.cluster.Namespace) != "":
		// Namespace-scoped elevations grant a data-plane role that does not include
		// the management-plane Microsoft.Authorization/roleAssignments/read action,
		// and the assignment lands at the namespace sub-scope (not the cluster scope
		// the ARM check queries). The ARM propagation check therefore 403s and adds
		// no value here; skip it (SSAR-based readiness is planned as a follow-up).
		kubectlLoginVerbose("skipping role propagation (namespace-scoped elevation)")
	default:
		principalOID, oidErr := k8sservice.ExtractAzurePrincipalOID(accessToken)
		if oidErr != nil {
			exitErr(fmt.Sprintf("failed to read principal OID from az access token: %v", oidErr))
		}
		if err := k8sservice.WaitForAzureRolePropagation(req.cluster.OrganizationID, elevateResult, principalOID, kubectlLoginDiagnosticsEnabled()); err != nil {
			exitErr(err.Error())
		}
	}

	return accessToken, elevateFromCache, elevateExpiresAt
}

// acquireAWSIDCSTSCredentials is the shared helper for AWS IDC permission-set
// direct and proxy flows. It mirrors acquireAzureAKSToken: Elevate (cache or API)
// → device registration → GetRoleCredentials, leaving AccessCredentials on the
// elevate result for subsequent EKS token generation.
func (a *IdsecKubectlLoginAction) acquireAWSIDCSTSCredentials(
	cmd *cobra.Command,
	svc *k8sservice.IdsecSCAK8sService,
	provider k8sservice.IdsecSCAK8sTokenProvider,
	req *kubectlLoginRequest,
) (elevateResult *k8smodels.IdsecSCAK8sElevateResult, elevateFromCache bool, elevateExpiresAt time.Time) {
	elevateResult, elevateFromCache, elevateExpiresAt = a.resolveElevateResult(cmd, svc, req)

	if elevateResult.TargetID != "" {
		region, clusterName, parseErr := k8sservice.ParseEKSARN(elevateResult.TargetID)
		if parseErr != nil {
			exitErr(fmt.Sprintf("failed to parse EKS ARN from elevate response targetId %q: %v", elevateResult.TargetID, parseErr))
		}
		req.cluster.Region = region
		req.cluster.ClusterID = clusterName
	}

	kubectlLoginInfo("acquiring AWS IDC STS credentials (fresh elevate=%v)", !elevateFromCache)
	oidcCache := NewAWSIDCOIDCCache(
		req.session.profileName,
		req.cluster.CSP,
		req.cluster.RoleID,
		req.cluster.FQDN,
		req.session.userUUID,
		req.resolvedNamespace(),
		req.session.sessionID,
	)
	if err := k8sservice.HydrateAWSAccessCredentialsFromElevate(
		elevateResult,
		req.cluster.Diagnostics,
		oidcCache,
	); err != nil {
		exitErr(fmt.Sprintf("failed to obtain AWS IDC credentials: %v", err))
	}
	return elevateResult, elevateFromCache, elevateExpiresAt
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
	a.applyFlowExecCredentialTTL(cmd, execCredFlowAzureDirect, execCred, elevateExpiresAt, "")
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

// requireProxyRootCA ensures evaluate certificateData is present for Azure / AWS IDC
// proxy JWE paths (SIA proxy needs the cluster CA for mTLS to the API server).
// proxyJWEFields returns a "+"-joined list of the JWE fields that will be sent
// to the DPA acquire call based on what is currently set on the cluster context.
func proxyJWEFields(cluster *k8sservice.IdsecSCAK8sClusterContext) string {
	var fields []string
	if cluster != nil {
		if strings.TrimSpace(cluster.K8sToken) != "" {
			fields = append(fields, "k8s_token")
		}
		if strings.TrimSpace(cluster.RootCA) != "" {
			fields = append(fields, "root_ca")
		}
		if strings.TrimSpace(cluster.ClusterToken) != "" {
			fields = append(fields, "cluster_token")
		}
	}
	if len(fields) == 0 {
		return "none"
	}
	return strings.Join(fields, "+")
}

func requireProxyRootCA(req *kubectlLoginRequest) {
	if req == nil || strings.TrimSpace(req.cluster.RootCA) == "" {
		exitErr("evaluate response missing certificateData required for proxy JWE (k8s_token+root_ca)")
	}
}

func (a *IdsecKubectlLoginAction) runAWSProxyFlow(
	cmd *cobra.Command,
	svc *k8sservice.IdsecSCAK8sService,
	req *kubectlLoginRequest,
) *k8smodels.IdsecSCAK8sExecCredential {
	if !k8sservice.IsAWSIDCPermissionSetRole(req.cluster.RoleID) {
		kubectlLoginInfo("AWS flow selected: IAM role (proxy DPA SSO acquire jwe_fields=%s)", proxyJWEFields(req.cluster))
		kubectlLoginInfo("generating AWS proxy ExecCredential")
		proxyStartedAt := time.Now()
		execCred, err := svc.GenerateProxyExecCredential(k8smodels.CSPAWS, req.cluster)
		if err != nil {
			exitErr(fmt.Sprintf("proxy credential generation failed: %v", err))
		}
		a.applyFlowExecCredentialTTL(cmd, execCredFlowAWSProxy, execCred, time.Time{}, "")
		kubectlLoginVerboseDuration("AWS proxy ExecCredential generation", proxyStartedAt)
		return execCred
	}

	requireProxyRootCA(req)
	kubectlLoginInfo("AWS flow selected: IDC permission-set (Elevate → device auth → EKS token → DPA JWE)")
	kubectlLoginVerbose("aws idc proxy flow: fqdn=%q role=%q userUUID=%q",
		req.cluster.FQDN, req.cluster.RoleID, req.session.userUUID)

	kubectlLoginInfo("aws idc proxy flow [1/3]: acquiring AWS IDC STS credentials (Elevate → device auth)")
	provider, err := k8sservice.GetTokenProvider(k8smodels.CSPAWS)
	if err != nil {
		exitErr(fmt.Sprintf("unsupported CSP %q: %v", k8smodels.CSPAWS, err))
	}
	elevateResult, _, elevateExpiresAt := a.acquireAWSIDCSTSCredentials(cmd, svc, provider, req)
	kubectlLoginInfo("aws idc proxy flow [1/3]: AWS IDC STS credentials acquired")

	kubectlLoginInfo("aws idc proxy flow [2/3]: generating EKS bearer token (K8sToken)")
	eksExecCred, err := provider.GenerateToken(elevateResult, req.cluster)
	if err != nil {
		exitErr(fmt.Sprintf("failed to generate EKS token for AWS IDC proxy: %v", err))
	}
	eksToken := strings.TrimSpace(eksExecCred.Status.Token)
	if eksToken == "" {
		exitErr("EKS token generation returned an empty token")
	}
	req.cluster.K8sToken = eksToken
	kubectlLoginInfo("aws idc proxy flow [2/3]: EKS token generated (%d bytes)", len(eksToken))
	kubectlLoginVerbose("EKS token acquired (len=%d) root_ca_len=%d — encrypting as JWE for DPA",
		len(eksToken), len(req.cluster.RootCA))

	kubectlLoginInfo("aws idc proxy flow [3/3]: calling DPA SSO acquire (DPA-K8S) with proxy JWE (jwe_fields=%s)", proxyJWEFields(req.cluster))
	proxyStartedAt := time.Now()
	execCred, err := svc.GenerateProxyExecCredential(k8smodels.CSPAWS, req.cluster)
	if err != nil {
		exitErr(fmt.Sprintf("proxy credential generation failed: %v", err))
	}
	a.applyFlowExecCredentialTTL(cmd, execCredFlowAWSIDCProxy, execCred, elevateExpiresAt, eksExecCred.Status.ExpirationTimestamp)
	kubectlLoginVerboseDuration("AWS IDC proxy ExecCredential generation", proxyStartedAt)
	return execCred
}

// runAzureProxyFlow implements the Azure AKS proxy cold path:
// acquireAzureAKSToken → set K8sToken → GenerateProxyExecCredential
// (DPA SSO acquire with proxy JWE) → return cert/key ExecCredential.
// Caching of the resulting ExecCredential is handled by the unified cache layer
// in runKubectlLoginAction; nothing is persisted at this level. The AKS JWT
// itself is never cached.
func (a *IdsecKubectlLoginAction) runAzureProxyFlow(
	cmd *cobra.Command,
	svc *k8sservice.IdsecSCAK8sService,
	req *kubectlLoginRequest,
) *k8smodels.IdsecSCAK8sExecCredential {
	requireProxyRootCA(req)
	kubectlLoginVerbose("azure proxy flow: fqdn=%q role=%q userUUID=%q",
		req.cluster.FQDN, req.cluster.RoleID, req.session.userUUID)

	kubectlLoginInfo("azure proxy flow [1/2]: acquiring AKS token (Elevate → az CLI)")
	provider, err := k8sservice.GetTokenProvider(k8smodels.CSPAzure)
	if err != nil {
		exitErr(fmt.Sprintf("unsupported CSP %q: %v", k8smodels.CSPAzure, err))
	}
	accessToken, _, elevateExpiresAt := a.acquireAzureAKSToken(cmd, svc, provider, req)
	kubectlLoginInfo("azure proxy flow [1/2]: AKS token acquired (%d bytes)", len(accessToken))
	kubectlLoginVerbose("AKS token acquired (len=%d) root_ca_len=%d — encrypting as JWE for DPA",
		len(accessToken), len(req.cluster.RootCA))

	req.cluster.K8sToken = accessToken
	kubectlLoginInfo("azure proxy flow [2/2]: calling DPA SSO acquire (DPA-K8S) with proxy JWE (jwe_fields=%s)", proxyJWEFields(req.cluster))
	proxyStartedAt := time.Now()
	execCred, err := svc.GenerateProxyExecCredential(k8smodels.CSPAzure, req.cluster)
	if err != nil {
		exitErr(fmt.Sprintf("proxy credential generation failed: %v", err))
	}
	kubectlLoginInfo(
		"azure proxy flow [2/2]: DPA SSO acquire returned cert (%d bytes) and key (%d bytes)",
		len(execCred.Status.ClientCertificateData), len(execCred.Status.ClientKeyData),
	)
	kubectlLoginVerboseDuration("Azure proxy ExecCredential generation", proxyStartedAt)

	a.applyFlowExecCredentialTTL(cmd, execCredFlowAzureProxy, execCred, elevateExpiresAt, accessToken)

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
