package actions

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	idseckeyring "github.com/cyberark/idsec-sdk-golang/pkg/common/keyring"
	k8smodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s/models"
)

const (
	// elevateCredsServiceName is the keyring service namespace for cached elevate credentials.
	elevateCredsServiceName = "idsec-sca-k8s-elevate"
)

// cachedElevateCreds is the keyring-persisted envelope for a single Elevate result.
type cachedElevateCreds struct {
	ElevateResult *k8smodels.IdsecSCAK8sElevateResult `json:"elevateResult"`
	SavedAt       time.Time                           `json:"savedAt"`
}

// buildCacheKey returns the keyring username key for a given CSP/role/fqdn triple.
// Format: <CSP-UPPER>:<roleKey>:<fqdn>
//
// fqdn is the cluster API endpoint (e.g. "xxxx.gr7.us-east-1.eks.amazonaws.com").
// It is always provided via the --fqdn CLI flag and uniquely identifies the cluster.
//
// Key length: e.g. "AWS:arn:aws:iam::123456789012:role/name:xxxx.gr7.us-east-1.eks.amazonaws.com"
// is ~100 chars — well within the macOS Keychain 512-char limit for account names.
func buildCacheKey(csp, roleKey, fqdn string) string {
	return fmt.Sprintf("%s:%s:%s", strings.ToUpper(csp), roleKey, fqdn)
}

// LoadCachedCreds reads the cached Elevate result from the OS keyring and validates
// it against the provided TTL.
//
// fqdn is the cluster API endpoint (always provided via --fqdn in kubeconfig).
// It forms the third component of the cache key: <CSP>:<roleKey>:<fqdn>.
//
// Returns (result, nil) when a valid cached entry exists (SavedAt + ttl > now).
// Returns (nil, nil) when the cache is empty, expired, or unreadable — the caller
// should re-call the Elevate API.
// Returns (nil, err) only on unexpected keyring errors.
//
// If ttl == 0 the function always returns (nil, nil) — Azure stub uses 0 to
// indicate it manages no keyring caching of its own.
func LoadCachedCreds(csp, roleKey, fqdn string, ttl time.Duration) (*k8smodels.IdsecSCAK8sElevateResult, error) {
	if ttl == 0 {
		return nil, nil
	}

	kr := idseckeyring.NewIdsecKeyring(elevateCredsServiceName)
	impl, err := kr.GetKeyring(false)
	if err != nil {
		return nil, fmt.Errorf("failed to open keyring: %w", err)
	}

	key := buildCacheKey(csp, roleKey, fqdn)
	data, err := impl.GetPassword(elevateCredsServiceName, key)
	if err != nil || data == "" {
		return nil, nil
	}

	var cached cachedElevateCreds
	if err := json.Unmarshal([]byte(data), &cached); err != nil {
		// Corrupted entry — treat as cache miss, let the caller refresh.
		_ = impl.DeletePassword(elevateCredsServiceName, key)
		return nil, nil
	}

	if time.Since(cached.SavedAt) > ttl {
		_ = impl.DeletePassword(elevateCredsServiceName, key)
		return nil, nil
	}

	return cached.ElevateResult, nil
}

// SaveCreds persists an Elevate result to the OS keyring with the current timestamp.
// The TTL is NOT stored — it is evaluated only at read time by LoadCachedCreds, so
// changing ElevateTTL() automatically affects all subsequent reads without requiring
// cache invalidation.
//
// fqdn is the cluster API endpoint (always provided via --fqdn in kubeconfig).
func SaveCreds(csp, roleKey, fqdn string, result *k8smodels.IdsecSCAK8sElevateResult) error {
	kr := idseckeyring.NewIdsecKeyring(elevateCredsServiceName)
	impl, err := kr.GetKeyring(false)
	if err != nil {
		return fmt.Errorf("failed to open keyring: %w", err)
	}

	entry := cachedElevateCreds{
		ElevateResult: result,
		SavedAt:       time.Now(),
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal cached creds: %w", err)
	}

	key := buildCacheKey(csp, roleKey, fqdn)
	if err := impl.SetPassword(elevateCredsServiceName, key, string(data)); err != nil {
		// Fallback to basic keyring on secure keyring failure.
		basicImpl, bErr := kr.GetKeyring(true)
		if bErr != nil {
			return fmt.Errorf("failed to save creds to keyring: %w", err)
		}
		if bErr := basicImpl.SetPassword(elevateCredsServiceName, key, string(data)); bErr != nil {
			return fmt.Errorf("failed to save creds to keyring (basic fallback): %w", bErr)
		}
	}
	return nil
}
