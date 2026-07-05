package actions

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	idseckeyring "github.com/cyberark/idsec-sdk-golang/pkg/common/keyring"
	k8sservice "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s"
	k8smodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s/models"
)

const (
	elevateCredsServiceName  = "idsec-sca-k8s-elevate"
	execCredCredsServiceName = "idsec-sca-k8s-execcred"
	// execCredSkew is a tiny clock-skew tolerance applied on read so we don't
	// serve a credential right at the edge of its already-buffered expiry. The
	// SDK has baked the 60s early-refresh window into status.expirationTimestamp
	// so this is intentionally small (no double-buffering).
	execCredSkew = 5 * time.Second
	// rawTokenEarlyRefreshBuffer is subtracted from raw (non-SDK-stamped) expiry
	// times — Elevate sessionExpTime, ISP id_token exp, Azure-proxy AKS JWT exp —
	// when computing the effective ExecCredential TTL min. SDK-stamped
	// status.expirationTimestamp values already include this 60s early-refresh
	// window and must not be buffered again.
	rawTokenEarlyRefreshBuffer = 60 * time.Second
	// Re-call Elevate this long before sessionExpTime when the session is long-lived.
	elevateSessionRefreshBuffer = 5 * time.Minute
	// Short API sessions need a smaller margin or the cache would never hit.
	elevateSessionRefreshBufferMin = 10 * time.Second
)

// CachedExecCredentialMethod identifies the connection-method shape of a cached
// ExecCredential. It is both an integrity gate on read (mismatch = clean miss
// + purge) and a storage-policy signal on write (proxy entries are never
// written to the basic-file fallback because they carry a private key).
type CachedExecCredentialMethod string

const (
	ExecCredMethodDirect CachedExecCredentialMethod = "direct"
	ExecCredMethodProxy  CachedExecCredentialMethod = "proxy"
)

type cachedElevateCreds struct {
	ElevateResult *k8smodels.IdsecSCAK8sElevateResult `json:"elevateResult"`
	SavedAt       time.Time                           `json:"savedAt"`
}

// cachedExecCredential is the value persisted in the OS keyring by the unified
// cache. The kubectl-ready ExecCredential JSON is stored verbatim in
// ExecCredentialJSON and emitted to stdout on cache hit without any further
// reconstruction. ExpiresAt is the parsed status.expirationTimestamp value
// (the SDK has already applied the early-refresh buffer). CSP and Method are
// integrity gates on read; AzureCLIFingerprint is set for both azure-direct
// and azure-proxy entries (a local `az` identity rotation invalidates the
// AKS access token used by direct AND the DPA-issued cert whose subject is
// derived from that token via jwe_extension_value). LastServedParentPID records
// the kubectl process that received this credential. If the same kubectl process
// asks again before expiry, client-go likely retried after a 401.
type cachedExecCredential struct {
	ExecCredentialJSON  string                     `json:"execCredential"`
	ExpiresAt           time.Time                  `json:"expiresAt"`
	SavedAt             time.Time                  `json:"savedAt"`
	CSP                 string                     `json:"csp"`
	Method              CachedExecCredentialMethod `json:"method"`
	AzureCLIFingerprint string                     `json:"azureCliFingerprint,omitempty"`
	LastServedParentPID int                        `json:"lastServedParentPid,omitempty"`
}

// AzureCLIFingerprint returns mtime:size for azureProfile.json (or AZURE_CONFIG_DIR); empty means unknown.
func AzureCLIFingerprint() string {
	dir := strings.TrimSpace(os.Getenv("AZURE_CONFIG_DIR"))
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		dir = filepath.Join(home, ".azure")
	}
	info, err := os.Stat(filepath.Join(dir, "azureProfile.json"))
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%d:%d", info.ModTime().UnixNano(), info.Size())
}

// ---------------------------------------------------------------------------
// ExecCredential effective TTL helpers.
// ---------------------------------------------------------------------------

type execCredFlow string

const (
	execCredFlowAWSDirect   execCredFlow = "aws direct"
	execCredFlowAWSProxy    execCredFlow = "aws proxy"
	execCredFlowAzureDirect execCredFlow = "azure direct"
	execCredFlowAzureProxy  execCredFlow = "azure proxy"
)

// ttlCandidate is one expiry dimension considered when computing the effective
// ExecCredential TTL. SDK-stamped timestamps set alreadyBuffered=true and
// skew=0; raw token/session expiries use rawTokenEarlyRefreshBuffer.
type ttlCandidate struct {
	name            string
	when            time.Time
	skew            time.Duration
	alreadyBuffered bool
	skipReason      string
}

// effective returns the candidate instant used in the min() comparison after
// applying any early-refresh buffer (skew).
func (c ttlCandidate) effective() time.Time {
	if c.when.IsZero() {
		return time.Time{}
	}
	return c.when.Add(-c.skew)
}

// computeEffectiveExecCredentialExpiry returns the minimum effective expiry
// across the supplied candidates. Already-buffered ExecCredential/cert
// timestamps should pass skew=0; raw token and session expiries should pass
// rawTokenEarlyRefreshBuffer so all dimensions refresh early.
//
// If any candidate is missing its expiration (zero when / non-empty skipReason)
// an error is returned naming every missing candidate. We refuse to compute a
// min TTL on a partial view because an unbounded dimension would silently
// extend the cached ExecCredential past one of its underlying credentials.
func computeEffectiveExecCredentialExpiry(cands ...ttlCandidate) (time.Time, string, error) {
	var missing []string
	for _, c := range cands {
		if c.when.IsZero() {
			reason := strings.TrimSpace(c.skipReason)
			if reason == "" {
				reason = "missing expiration"
			}
			missing = append(missing, fmt.Sprintf("%s (%s)", c.name, reason))
		}
	}
	if len(missing) > 0 {
		return time.Time{}, "", fmt.Errorf(
			"cannot compute effective ExecCredential TTL: %d candidate(s) missing expiration: %s",
			len(missing), strings.Join(missing, "; "),
		)
	}

	var minCand ttlCandidate
	for _, c := range cands {
		if minCand.when.IsZero() || c.effective().Before(minCand.effective()) {
			minCand = c
		}
	}
	if minCand.when.IsZero() {
		return time.Time{}, "", fmt.Errorf("cannot compute effective ExecCredential TTL: no candidates supplied")
	}
	return minCand.effective(), minCand.name, nil
}

// execCredentialExpiresAtCandidate reads status.expirationTimestamp from an
// ExecCredential (direct EKS/AKS bearer or proxy cert). The SDK helper name
// references proxy creds but applies to any ExecCredential shape.
func execCredentialExpiresAtCandidate(name string, execCred *k8smodels.IdsecSCAK8sExecCredential) ttlCandidate {
	exp, err := k8sservice.ProxyExecCredentialExpiresAt(execCred)
	if err != nil {
		return ttlCandidate{name: name, skipReason: fmt.Sprintf("missing/unparseable expirationTimestamp: %v", err)}
	}
	return ttlCandidate{name: name, when: exp, alreadyBuffered: true}
}

// execCredTTLCandidates returns the per-flow expiry dimensions that feed the
// effective ExecCredential TTL min. Each flow includes idtokenlifetime; direct
// and proxy Azure paths also include Elevate where applicable.
func execCredTTLCandidates(
	flow execCredFlow,
	execCred *k8smodels.IdsecSCAK8sExecCredential,
	elevateExpiresAt, idTokenExpiresAt time.Time,
	aksAccessToken string,
) []ttlCandidate {
	switch flow {
	case execCredFlowAWSDirect:
		return []ttlCandidate{
			execCredentialExpiresAtCandidate("eks", execCred),
			rawTokenTTLCandidate("elevate", elevateExpiresAt),
			rawTokenTTLCandidate("idtokenlifetime", idTokenExpiresAt),
		}
	case execCredFlowAWSProxy:
		return []ttlCandidate{
			execCredentialExpiresAtCandidate("cert", execCred),
			rawTokenTTLCandidate("idtokenlifetime", idTokenExpiresAt),
		}
	case execCredFlowAzureDirect:
		return []ttlCandidate{
			execCredentialExpiresAtCandidate("aks", execCred),
			rawTokenTTLCandidate("elevate", elevateExpiresAt),
			rawTokenTTLCandidate("idtokenlifetime", idTokenExpiresAt),
		}
	case execCredFlowAzureProxy:
		return []ttlCandidate{
			execCredentialExpiresAtCandidate("cert", execCred),
			parseAKSTTLCandidate(aksAccessToken),
			rawTokenTTLCandidate("elevate", elevateExpiresAt),
			rawTokenTTLCandidate("idtokenlifetime", idTokenExpiresAt),
		}
	default:
		return nil
	}
}

// rawTokenTTLCandidate wraps a raw expiry (Elevate session or ISP id_token)
// with the standard early-refresh buffer applied at min-time.
func rawTokenTTLCandidate(name string, exp time.Time) ttlCandidate {
	if exp.IsZero() {
		return ttlCandidate{name: name, skipReason: "empty expiration"}
	}
	return ttlCandidate{name: name, when: exp, skew: rawTokenEarlyRefreshBuffer}
}

// parseAKSTTLCandidate extracts the JWT exp from the Azure-proxy AKS access
// token forwarded as jwe_extension_value and applies the early-refresh buffer.
func parseAKSTTLCandidate(accessToken string) ttlCandidate {
	exp, err := k8sservice.ParseAccessTokenExpiry(accessToken)
	if err != nil {
		return ttlCandidate{name: "aks", skipReason: fmt.Sprintf("access-token exp unparseable: %v", err)}
	}
	return ttlCandidate{name: "aks", when: exp, skew: rawTokenEarlyRefreshBuffer}
}

// deriveElevateExpiry returns the concrete Elevate session expiry used as a
// TTL candidate. Prefers sessionExpTime from the API; falls back to
// base+provider ElevateTTL (from cache SavedAt on hits, or pre-API timestamp
// on misses) when the API omits sessionExpTime.
func deriveElevateExpiry(elevateResult *k8smodels.IdsecSCAK8sElevateResult, base time.Time, fallbackTTL time.Duration, verbose bool) (time.Time, string) {
	if elevateResult != nil {
		if trimmed := strings.TrimSpace(elevateResult.SessionExpTime); trimmed != "" {
			if exp, err := parseSessionExpTime(trimmed); err == nil {
				return exp, "sessionExpTime"
			} else if verbose {
				kubectlLoginVerbose("Elevate sessionExpTime %q unparseable, using fallbackTTL: %v", trimmed, err)
			}
		}
	}
	// base is intentionally captured before the Elevate API round-trip so
	// fallbackTTL stays conservative when sessionExpTime is absent.
	if fallbackTTL > 0 && !base.IsZero() {
		return base.Add(fallbackTTL), "fallbackTTL"
	}
	return time.Time{}, ""
}

// lazyKeyring opens the OS keyring once per (service name, basic-store) pair; sync.Once is thread-safe lazy init.
type lazyKeyring struct {
	once    sync.Once
	impl    idseckeyring.IdsecKeyringImpl
	err     error
	service string
	basic   bool
}

func (k *lazyKeyring) get() (idseckeyring.IdsecKeyringImpl, error) {
	k.once.Do(func() {
		k.impl, k.err = idseckeyring.NewIdsecKeyring(k.service).GetKeyring(k.basic)
	})
	return k.impl, k.err
}

var (
	krElevateCreds  = &lazyKeyring{service: elevateCredsServiceName}
	krExecCred      = &lazyKeyring{service: execCredCredsServiceName}
	krExecCredBasic = &lazyKeyring{service: execCredCredsServiceName, basic: true}
	krBasicFallback = &lazyKeyring{service: elevateCredsServiceName, basic: true}

	currentParentPID        = os.Getppid
	currentAzureFingerprint = AzureCLIFingerprint
)

// kubectl-login cache key shapes (both bind to internal_session_id when present):
//
//	Elevate keyring:  CSP:shortRole:fqdn:user[:organizationID][:sessionID]
//	Unified execcred: CSP:shortRole:fqdn:user:sessionID  (no organizationID)
//
// An empty sessionID disables both caches at the API boundary (callers fall
// through to the cold path). When sessionID is set it is the final key segment
// for Elevate and the required final segment for unified execcred.
//
// buildCacheKey forms the Elevate keyring cache key.
func buildCacheKey(csp, organizationID, roleID, fqdn, username, sessionID string) string {
	key := fmt.Sprintf(
		"%s:%s:%s:%s",
		strings.ToUpper(strings.TrimSpace(csp)),
		shortRoleKey(roleID),
		fqdn,
		normalizeUsername(username),
	)
	if org := strings.TrimSpace(organizationID); org != "" {
		key += ":" + org
	}
	if sid := strings.TrimSpace(sessionID); sid != "" {
		key += ":" + sid
	}
	return key
}

func normalizeUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

func shortRoleKey(roleID string) string {
	const azureRoleMarker = "roleDefinitions/"
	if idx := strings.LastIndex(roleID, azureRoleMarker); idx >= 0 {
		return roleID[idx+len(azureRoleMarker):]
	}
	return roleID
}

// azureElevateRefreshBuffer returns how long before sessionExpTime we should re-elevate.
// Long sessions use elevateSessionRefreshBuffer (5m). Short API sessions use a smaller
// buffer so back-to-back kubectl invocations can reuse the cached Elevate result.
func azureElevateRefreshBuffer(exp, now time.Time) time.Duration {
	remaining := exp.Sub(now)
	if remaining <= 0 {
		return 0
	}
	if remaining > elevateSessionRefreshBuffer+time.Minute {
		return elevateSessionRefreshBuffer
	}
	if remaining > elevateSessionRefreshBufferMin {
		return elevateSessionRefreshBufferMin
	}
	return 0
}

func isCachedElevateStillValid(
	csp string,
	result *k8smodels.IdsecSCAK8sElevateResult,
	savedAt time.Time,
	fallbackTTL time.Duration,
	now time.Time,
) (valid bool, reason string) {
	if result == nil {
		return false, "empty result"
	}
	if strings.ToUpper(strings.TrimSpace(csp)) == k8smodels.CSPAzure && strings.TrimSpace(result.SessionExpTime) != "" {
		exp, err := parseSessionExpTime(result.SessionExpTime)
		if err != nil {
			return false, fmt.Sprintf("invalid sessionExpTime: %v", err)
		}
		remaining := exp.Sub(now)
		if remaining <= 0 {
			return false, fmt.Sprintf("sessionExpTime %s expired", exp.Format(time.RFC3339))
		}
		buffer := azureElevateRefreshBuffer(exp, now)
		// Very short API sessions (<10s): reuse cache for the whole lifetime (no 5m margin).
		if buffer == 0 {
			return true, fmt.Sprintf(
				"sessionExpTime %s (%s until expiry, short-session cache)",
				exp.Format(time.RFC3339),
				remaining.Round(time.Second),
			)
		}
		refreshDeadline := now.Add(buffer)
		if refreshDeadline.Before(exp) {
			return true, fmt.Sprintf(
				"sessionExpTime %s (%s until expiry, refresh buffer %s)",
				exp.Format(time.RFC3339),
				remaining.Round(time.Second),
				buffer,
			)
		}
		return false, fmt.Sprintf(
			"sessionExpTime %s within %s refresh window (%s until expiry)",
			exp.Format(time.RFC3339),
			buffer,
			remaining.Round(time.Second),
		)
	}
	if fallbackTTL > 0 && now.Sub(savedAt) < fallbackTTL {
		return true, fmt.Sprintf("SavedAt+fallbackTTL (%s)", fallbackTTL)
	}
	return false, "cache entry expired"
}

func parseSessionExpTime(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, fmt.Errorf("empty sessionExpTime")
	}

	// API formats seen in production:
	//   2026-05-21T10:21:07.240104+00:00  (RFC3339Nano with numeric offset)
	//   2026-05-21T10:21:07.240104Z
	//   2026-05-21T09:37:33.392778         (fractional seconds, UTC implied)
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, raw); err == nil {
			return t.UTC(), nil
		}
	}

	// UTC implied when the API omits a zone suffix.
	for _, layout := range []string{
		"2006-01-02T15:04:05.999999999",
		"2006-01-02T15:04:05.999999",
		"2006-01-02T15:04:05",
	} {
		if t, err := time.ParseInLocation(layout, raw, time.UTC); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognized time format %q", raw)
}

// LoadCachedElevateKeyringWithReason loads cached Elevate JSON from the keyring
// with SavedAt metadata so callers can derive fallbackTTL-based expiry bounds.
func LoadCachedElevateKeyringWithReason(csp, organizationID, roleID, fqdn, username, sessionID string, fallbackTTL time.Duration) (result *k8smodels.IdsecSCAK8sElevateResult, savedAt time.Time, hitReason, missReason string, err error) {
	if strings.TrimSpace(sessionID) == "" {
		return nil, time.Time{}, "", "missing session id (cache disabled)", nil
	}
	if fallbackTTL == 0 && strings.ToUpper(strings.TrimSpace(csp)) != k8smodels.CSPAzure {
		return nil, time.Time{}, "", "", nil
	}

	impl, err := krElevateCreds.get()
	if err != nil {
		return nil, time.Time{}, "", "", fmt.Errorf("failed to open credential cache: %w", err)
	}

	key := buildCacheKey(csp, organizationID, roleID, fqdn, username, sessionID)
	data, err := impl.GetPassword(elevateCredsServiceName, key)
	if err != nil || data == "" {
		return nil, time.Time{}, "", "no cached entry", nil
	}

	var cached cachedElevateCreds
	if err := json.Unmarshal([]byte(data), &cached); err != nil {
		_ = impl.DeletePassword(elevateCredsServiceName, key)
		return nil, time.Time{}, "", "corrupt cached entry (removed)", nil
	}

	now := time.Now()
	valid, reason := isCachedElevateStillValid(csp, cached.ElevateResult, cached.SavedAt, fallbackTTL, now)
	if !valid {
		_ = impl.DeletePassword(elevateCredsServiceName, key)
		return nil, time.Time{}, "", reason, nil
	}

	return cached.ElevateResult, cached.SavedAt, reason, "", nil
}

// describeElevateSessionExpiry returns a log line about sessionExpTime parsing and remaining lifetime.
func describeElevateSessionExpiry(sessionExpTime string) string {
	sessionExpTime = strings.TrimSpace(sessionExpTime)
	if sessionExpTime == "" {
		return "no sessionExpTime in response (cache falls back to provider ElevateTTL)"
	}
	exp, err := parseSessionExpTime(sessionExpTime)
	if err != nil {
		return fmt.Sprintf("sessionExpTime %q is not parseable: %v", sessionExpTime, err)
	}
	now := time.Now()
	remaining := exp.Sub(now)
	buffer := azureElevateRefreshBuffer(exp, now)
	return fmt.Sprintf(
		"sessionExpTime=%s (expires in %s; cache refresh buffer %s)",
		exp.Format(time.RFC3339),
		remaining.Round(time.Second),
		buffer,
	)
}

// buildUnifiedExecCredKey forms the unified ExecCredential cache key used by
// the pre-Evaluate fast path. Shape: <CSP>:<shortRole>:<fqdn>:<normalizedUser>:<sessionID>.
//
// organizationID is intentionally NOT in the key. Cluster FQDN is unique per
// cluster, so two clusters in different organizations cannot collide. Binding
// the key to internal_session_id (sessionID) rotates the entire cache namespace
// on full re-auth without any explicit clear.
func buildUnifiedExecCredKey(csp, roleID, fqdn, username, sessionID string) string {
	return fmt.Sprintf(
		"%s:%s:%s:%s:%s",
		strings.ToUpper(strings.TrimSpace(csp)),
		shortRoleKey(roleID),
		fqdn,
		normalizeUsername(username),
		strings.TrimSpace(sessionID),
	)
}

func saveUnifiedExecCredentialEntry(impl idseckeyring.IdsecKeyringImpl, key string, cached cachedExecCredential) error {
	payload, err := json.Marshal(cached)
	if err != nil {
		return fmt.Errorf("failed to marshal unified execcred cache: %w", err)
	}
	return impl.SetPassword(execCredCredsServiceName, key, string(payload))
}

func deleteUnifiedExecCredentialByKey(key string) {
	if impl, err := krExecCred.get(); err == nil {
		_ = impl.DeletePassword(execCredCredsServiceName, key)
	}
	if basicImpl, err := krExecCredBasic.get(); err == nil {
		_ = basicImpl.DeletePassword(execCredCredsServiceName, key)
	}
}

// LoadUnifiedExecCredential returns a valid cached ExecCredential entry for the
// supplied identity, or (nil, _, missReason, _) when absent / expired / corrupt
// / mismatched. expectedMethod, when non-empty, is enforced as an integrity gate
// (mismatch → purge + miss). Callers running the pre-Evaluate fast path pass
// expectedMethod="" because the connection method is not yet known; in that
// mode the cached entry's own Method tag describes what we are returning.
//
// An empty sessionID disables the cache entirely (returns "" hitReason and a
// missReason explaining why) so callers fall through to the cold path safely
// when the ISP token is missing internal_session_id.
func LoadUnifiedExecCredential(
	csp, roleID, fqdn, username, sessionID string,
	expectedMethod CachedExecCredentialMethod,
) (entry *cachedExecCredential, hitReason, missReason string, err error) {
	if strings.TrimSpace(sessionID) == "" {
		return nil, "", "missing session id (cache disabled)", nil
	}

	primaryKeyring, err := krExecCred.get()
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to open unified execcred cache: %w", err)
	}

	key := buildUnifiedExecCredKey(csp, roleID, fqdn, username, sessionID)
	keyringHoldingEntry := primaryKeyring
	data, err := primaryKeyring.GetPassword(execCredCredsServiceName, key)
	if err != nil || data == "" {
		// Direct entries may have landed in the basic-file fallback on hosts
		// without an OS keyring. Look there too. Proxy entries are never written
		// to the basic backend, so a hit there is by construction a direct entry.
		if basicKeyring, bErr := krExecCredBasic.get(); bErr == nil && basicKeyring != primaryKeyring {
			if d2, e2 := basicKeyring.GetPassword(execCredCredsServiceName, key); e2 == nil && d2 != "" {
				data = d2
				keyringHoldingEntry = basicKeyring
			}
		}
		if data == "" {
			return nil, "", "no cached entry", nil
		}
	}

	var cached cachedExecCredential
	if jErr := json.Unmarshal([]byte(data), &cached); jErr != nil || strings.TrimSpace(cached.ExecCredentialJSON) == "" {
		deleteUnifiedExecCredentialByKey(key)
		return nil, "", "corrupt cached entry (removed)", nil
	}

	if !strings.EqualFold(strings.TrimSpace(cached.CSP), strings.TrimSpace(csp)) {
		deleteUnifiedExecCredentialByKey(key)
		return nil, "", fmt.Sprintf("csp mismatch (cached=%s, expected=%s)", cached.CSP, csp), nil
	}
	if expectedMethod != "" && cached.Method != expectedMethod {
		deleteUnifiedExecCredentialByKey(key)
		return nil, "", fmt.Sprintf("method mismatch (cached=%s, expected=%s)", cached.Method, expectedMethod), nil
	}

	now := time.Now()
	if cached.ExpiresAt.IsZero() || now.Add(execCredSkew).After(cached.ExpiresAt) {
		remaining := cached.ExpiresAt.Sub(now).Round(time.Second)
		deleteUnifiedExecCredentialByKey(key)
		return nil, "", fmt.Sprintf("entry expired (%s remaining)", remaining), nil
	}

	if strings.EqualFold(strings.TrimSpace(csp), k8smodels.CSPAzure) {
		currentFP := currentAzureFingerprint()
		// Azure credentials depend on the local az identity. If it changed, the
		// cached AKS token or proxy cert may no longer match the active user.
		if currentFP == "" || currentFP != cached.AzureCLIFingerprint {
			deleteUnifiedExecCredentialByKey(key)
			return nil, "", "azure cli fingerprint changed", nil
		}
	}

	kubectlParentPID := currentParentPID()
	var markerReason string
	if kubectlParentPID > 0 {
		// Kubernetes does not tell exec plugins that the previous request got 401.
		// A repeated request from the same kubectl process for an unexpired entry is
		// the strongest signal we have, so purge and let the cold path regenerate.
		if cached.LastServedParentPID == kubectlParentPID {
			deleteUnifiedExecCredentialByKey(key)
			return nil, "", fmt.Sprintf(
				"probable 401 refresh: same kubectl parent process requested unexpired cached credential again (parentPID=%d); forcing cold path",
				kubectlParentPID,
			), nil
		}
		cached.LastServedParentPID = kubectlParentPID
		if err := saveUnifiedExecCredentialEntry(keyringHoldingEntry, key, cached); err != nil {
			deleteUnifiedExecCredentialByKey(key)
			return nil, "", fmt.Sprintf("serve marker update failed for kubectl parentPID=%d (removed cached entry; forcing cold path)", kubectlParentPID), nil
		}
		markerReason = fmt.Sprintf("serve marker updated for kubectl parentPID=%d", kubectlParentPID)
	} else {
		markerReason = "serve marker skipped (kubectl parentPID unavailable)"
	}

	reason := fmt.Sprintf("method=%s expiresAt=%s (%s remaining)",
		cached.Method,
		cached.ExpiresAt.Format(time.RFC3339),
		cached.ExpiresAt.Sub(now).Round(time.Second),
	)
	reason = fmt.Sprintf("%s; %s", reason, markerReason)
	return &cached, reason, "", nil
}

// SaveUnifiedExecCredential persists the kubectl-ready ExecCredential JSON.
//
// For ExecCredMethodProxy entries the basic-file fallback is REFUSED because
// proxy entries carry a private key. On secure-storage failure the proxy entry
// is simply not cached; the next call regenerates from DPA SSO acquire. This
// honors the proxy team directive to avoid storing the token on the user's
// machine in plaintext.
//
// expiresAt must be the ExecCredential status.expirationTimestamp the SDK
// already wrote (early-refresh buffer baked in); the cache treats it as final.
func SaveUnifiedExecCredential(
	csp, roleID, fqdn, username, sessionID string,
	method CachedExecCredentialMethod,
	execCredJSON string,
	expiresAt time.Time,
	azureCLIFingerprint string,
) error {
	if strings.TrimSpace(sessionID) == "" {
		return fmt.Errorf("cannot cache execcred: sessionID is empty")
	}
	if strings.TrimSpace(execCredJSON) == "" {
		return fmt.Errorf("cannot cache execcred: empty JSON payload")
	}
	if expiresAt.IsZero() {
		return fmt.Errorf("cannot cache execcred: expiresAt is zero")
	}
	if method != ExecCredMethodDirect && method != ExecCredMethodProxy {
		return fmt.Errorf("unknown execcred method %q", method)
	}

	impl, err := krExecCred.get()
	if err != nil {
		return fmt.Errorf("failed to open unified execcred cache: %w", err)
	}

	payload, err := json.Marshal(cachedExecCredential{
		ExecCredentialJSON:  execCredJSON,
		ExpiresAt:           expiresAt.UTC(),
		SavedAt:             time.Now().UTC(),
		CSP:                 strings.TrimSpace(csp),
		Method:              method,
		AzureCLIFingerprint: azureCLIFingerprint,
		LastServedParentPID: currentParentPID(),
	})
	if err != nil {
		return fmt.Errorf("failed to marshal unified execcred cache: %w", err)
	}

	key := buildUnifiedExecCredKey(csp, roleID, fqdn, username, sessionID)
	if setErr := impl.SetPassword(execCredCredsServiceName, key, string(payload)); setErr == nil {
		return nil
	} else if method == ExecCredMethodProxy {
		// Architectural rule: proxy entries (private key) MUST NEVER live in
		// the basic-file fallback. Skip caching; cold path will run next time.
		return fmt.Errorf("proxy execcred not cached: secure keyring unavailable, plaintext fallback refused: %w", setErr)
	} else {
		basicImpl, bErr := krExecCredBasic.get()
		if bErr != nil {
			return fmt.Errorf("failed to save execcred to cache: %w", setErr)
		}
		if bErr := basicImpl.SetPassword(execCredCredsServiceName, key, string(payload)); bErr != nil {
			return fmt.Errorf("failed to save execcred to cache (basic fallback): %w", bErr)
		}
	}
	return nil
}

// DeleteUnifiedExecCredential removes a unified cache entry, used by the
// Azure-direct fingerprint-mismatch / live-verify-failed path.
func DeleteUnifiedExecCredential(csp, roleID, fqdn, username, sessionID string) error {
	if strings.TrimSpace(sessionID) == "" {
		return nil
	}
	key := buildUnifiedExecCredKey(csp, roleID, fqdn, username, sessionID)
	deleteUnifiedExecCredentialByKey(key)
	return nil
}

// SaveCreds writes Elevate result JSON to the keyring.
func SaveCreds(csp, organizationID, roleID, fqdn, username, sessionID string, result *k8smodels.IdsecSCAK8sElevateResult) error {
	if strings.TrimSpace(sessionID) == "" {
		return nil
	}
	impl, err := krElevateCreds.get()
	if err != nil {
		return fmt.Errorf("failed to open credential cache: %w", err)
	}

	data, err := json.Marshal(cachedElevateCreds{
		ElevateResult: result,
		SavedAt:       time.Now(),
	})
	if err != nil {
		return fmt.Errorf("failed to marshal cached creds: %w", err)
	}

	key := buildCacheKey(csp, organizationID, roleID, fqdn, username, sessionID)
	if err := impl.SetPassword(elevateCredsServiceName, key, string(data)); err != nil {
		basicImpl, bErr := krBasicFallback.get()
		if bErr != nil {
			return fmt.Errorf("failed to save credentials to cache: %w", err)
		}
		if bErr := basicImpl.SetPassword(elevateCredsServiceName, key, string(data)); bErr != nil {
			return fmt.Errorf("failed to save credentials to cache (basic fallback): %w", bErr)
		}
	}
	return nil
}
