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
	aksTokenCredsServiceName = "idsec-sca-k8s-aks-token"
	aksTokenRefreshBuffer    = 60 * time.Second
	// Re-call Elevate this long before sessionExpTime when the session is long-lived.
	elevateSessionRefreshBuffer = 5 * time.Minute
	// Short API sessions need a smaller margin or the cache would never hit.
	elevateSessionRefreshBufferMin = 10 * time.Second
)

type cachedElevateCreds struct {
	ElevateResult *k8smodels.IdsecSCAK8sElevateResult `json:"elevateResult"`
	SavedAt       time.Time                           `json:"savedAt"`
}

type cachedAKSToken struct {
	Token               string    `json:"token"`
	ExpiresAt           time.Time `json:"expiresAt"`
	SavedAt             time.Time `json:"savedAt"`
	AzureCLIFingerprint string    `json:"azureCliFingerprint,omitempty"`
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
	krAKSToken      = &lazyKeyring{service: aksTokenCredsServiceName}
	krBasicFallback = &lazyKeyring{service: elevateCredsServiceName, basic: true}
)

func buildAKSTokenCacheKey(csp, roleID, fqdn, username, organizationID string) string {
	key := buildCacheKey(csp, roleID, fqdn, username)
	if org := strings.TrimSpace(organizationID); org != "" {
		key += ":" + strings.ToLower(org)
	}
	return key
}

func buildCacheKey(csp, roleID, fqdn, username string) string {
	return fmt.Sprintf(
		"%s:%s:%s:%s",
		strings.ToUpper(strings.TrimSpace(csp)),
		shortRoleKey(roleID),
		fqdn,
		normalizeUsername(username),
	)
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
	if strings.ToUpper(strings.TrimSpace(csp)) == "AZURE" && strings.TrimSpace(result.SessionExpTime) != "" {
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

// LoadCachedElevateKeyringWithReason loads cached Elevate JSON from the keyring (hitReason/missReason for logs).
func LoadCachedElevateKeyringWithReason(csp, roleID, fqdn, username string, fallbackTTL time.Duration) (result *k8smodels.IdsecSCAK8sElevateResult, hitReason, missReason string, err error) {
	if fallbackTTL == 0 && strings.ToUpper(strings.TrimSpace(csp)) != "AZURE" {
		return nil, "", "", nil
	}

	impl, err := krElevateCreds.get()
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to open credential cache: %w", err)
	}

	key := buildCacheKey(csp, roleID, fqdn, username)
	data, err := impl.GetPassword(elevateCredsServiceName, key)
	if err != nil || data == "" {
		return nil, "", "no cached entry", nil
	}

	var cached cachedElevateCreds
	if err := json.Unmarshal([]byte(data), &cached); err != nil {
		_ = impl.DeletePassword(elevateCredsServiceName, key)
		return nil, "", "corrupt cached entry (removed)", nil
	}

	now := time.Now()
	valid, reason := isCachedElevateStillValid(csp, cached.ElevateResult, cached.SavedAt, fallbackTTL, now)
	if !valid {
		_ = impl.DeletePassword(elevateCredsServiceName, key)
		return nil, "", reason, nil
	}

	return cached.ElevateResult, reason, "", nil
}

// describeElevateSessionExpiry returns a log line about sessionExpTime parsing and remaining lifetime.
func describeElevateSessionExpiry(sessionExpTime string) string {
	sessionExpTime = strings.TrimSpace(sessionExpTime)
	if sessionExpTime == "" {
		return "no sessionExpTime in response (Azure cache falls back to SavedAt+1h TTL)"
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

func isCachedAKSTokenStillValid(expiresAt, now time.Time) (bool, string) {
	if expiresAt.IsZero() {
		return false, "no expiry"
	}
	remaining := expiresAt.Sub(now)
	if remaining <= 0 {
		return false, fmt.Sprintf("AKS token expired at %s", expiresAt.Format(time.RFC3339))
	}
	if now.Add(aksTokenRefreshBuffer).Before(expiresAt) {
		return true, fmt.Sprintf("JWT exp %s (%s remaining, buffer %s)",
			expiresAt.Format(time.RFC3339), remaining.Round(time.Second), aksTokenRefreshBuffer)
	}
	return false, fmt.Sprintf("AKS token within %s of JWT exp (%s remaining)",
		aksTokenRefreshBuffer, remaining.Round(time.Second))
}

// LoadCachedAKSToken returns a cached AKS JWT or missReason.
func LoadCachedAKSToken(csp, roleID, fqdn, username, organizationID string) (*cachedAKSToken, string, string, error) {
	if strings.ToUpper(strings.TrimSpace(csp)) != "AZURE" {
		return nil, "", "", nil
	}

	impl, err := krAKSToken.get()
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to open AKS token cache: %w", err)
	}

	key := buildAKSTokenCacheKey(csp, roleID, fqdn, username, organizationID)
	data, err := impl.GetPassword(aksTokenCredsServiceName, key)
	if err != nil || data == "" {
		return nil, "", "no cached AKS token", nil
	}

	var cached cachedAKSToken
	if err := json.Unmarshal([]byte(data), &cached); err != nil || cached.Token == "" {
		_ = impl.DeletePassword(aksTokenCredsServiceName, key)
		return nil, "", "corrupt AKS token entry (removed)", nil
	}

	valid, reason := isCachedAKSTokenStillValid(cached.ExpiresAt, time.Now())
	if !valid {
		_ = impl.DeletePassword(aksTokenCredsServiceName, key)
		return nil, "", reason, nil
	}

	return &cached, reason, "", nil
}

func DeleteCachedAKSToken(csp, roleID, fqdn, username, organizationID string) error {
	impl, err := krAKSToken.get()
	if err != nil {
		return err
	}
	return impl.DeletePassword(aksTokenCredsServiceName, buildAKSTokenCacheKey(csp, roleID, fqdn, username, organizationID))
}

// SaveAKSToken caches the AKS JWT (with optional azureCLIFingerprint for fast reuse).
func SaveAKSToken(csp, roleID, fqdn, username, organizationID, token, azureCLIFingerprint string) error {
	expiresAt, err := k8sservice.ParseAccessTokenExpiry(token)
	if err != nil {
		return fmt.Errorf("cannot cache AKS token without JWT exp: %w", err)
	}

	impl, err := krAKSToken.get()
	if err != nil {
		return fmt.Errorf("failed to open AKS token cache: %w", err)
	}

	data, err := json.Marshal(cachedAKSToken{
		Token:               token,
		ExpiresAt:           expiresAt,
		SavedAt:             time.Now(),
		AzureCLIFingerprint: azureCLIFingerprint,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal AKS token cache: %w", err)
	}

	key := buildAKSTokenCacheKey(csp, roleID, fqdn, username, organizationID)
	if err := impl.SetPassword(aksTokenCredsServiceName, key, string(data)); err != nil {
		basicImpl, bErr := krBasicFallback.get()
		if bErr != nil {
			return fmt.Errorf("failed to save AKS token to cache: %w", err)
		}
		if bErr := basicImpl.SetPassword(aksTokenCredsServiceName, key, string(data)); bErr != nil {
			return fmt.Errorf("failed to save AKS token to cache (basic fallback): %w", bErr)
		}
	}
	return nil
}

// SaveCreds writes Elevate result JSON to the keyring.
func SaveCreds(csp, roleID, fqdn, username string, result *k8smodels.IdsecSCAK8sElevateResult) error {
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

	key := buildCacheKey(csp, roleID, fqdn, username)
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
