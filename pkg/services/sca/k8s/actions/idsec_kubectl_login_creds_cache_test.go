package actions

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	k8sservice "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s"
	k8smodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s/models"
)

func TestBuildCacheKey(t *testing.T) {
	tests := []struct {
		name     string
		csp      string
		roleKey  string
		fqdn     string
		username string
		expected string
	}{
		{
			name:     "success_formats_correctly",
			csp:      "AWS",
			roleKey:  "arn:aws:iam::123456789012:role/k8s-role",
			fqdn:     "745445889F087548523CF96B3D365FF0.gr7.us-east-1.eks.amazonaws.com",
			username: "alice@example.com",
			expected: "AWS:arn:aws:iam::123456789012:role/k8s-role:745445889F087548523CF96B3D365FF0.gr7.us-east-1.eks.amazonaws.com:alice@example.com",
		},
		{
			name:     "success_uppercases_csp",
			csp:      "azure",
			roleKey:  "my-role",
			fqdn:     "mycluster.eastus.azmk8s.io",
			username: "bob@example.com",
			expected: "AZURE:my-role:mycluster.eastus.azmk8s.io:bob@example.com",
		},
		{
			name:     "success_mixed_case_csp_is_uppercased",
			csp:      "Aws",
			roleKey:  "role-name",
			fqdn:     "cluster.example.com",
			username: "carol@example.com",
			expected: "AWS:role-name:cluster.example.com:carol@example.com",
		},
		{
			name:     "success_username_is_lowercased_and_trimmed",
			csp:      "AWS",
			roleKey:  "arn:aws:iam::123:role/foo",
			fqdn:     "cluster.example.com",
			username: "  Alice@Example.COM  ",
			expected: "AWS:arn:aws:iam::123:role/foo:cluster.example.com:alice@example.com",
		},
		{
			name:     "success_empty_username_produces_trailing_separator",
			csp:      "AWS",
			roleKey:  "arn:aws:iam::123:role/foo",
			fqdn:     "cluster.example.com",
			username: "",
			expected: "AWS:arn:aws:iam::123:role/foo:cluster.example.com:",
		},
		{
			name:     "success_empty_fqdn_produces_consecutive_separators",
			csp:      "AWS",
			roleKey:  "arn:aws:iam::123:role/foo",
			fqdn:     "",
			username: "alice@example.com",
			expected: "AWS:arn:aws:iam::123:role/foo::alice@example.com",
		},
		{
			name:     "success_empty_role_key_produces_consecutive_separators",
			csp:      "AWS",
			roleKey:  "",
			fqdn:     "cluster.eks.amazonaws.com",
			username: "alice@example.com",
			expected: "AWS::cluster.eks.amazonaws.com:alice@example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := buildCacheKey(tt.csp, "", tt.roleKey, tt.fqdn, tt.username, "")
			if got != tt.expected {
				t.Errorf("buildCacheKey(%q, %q, %q, %q, %q) = %q, want %q",
					tt.csp, "", tt.roleKey, tt.fqdn, tt.username, got, tt.expected)
			}
		})
	}
}

func TestBuildCacheKey_AzureRoleIsShortened(t *testing.T) {
	t.Run("success_azure_role_definition_is_truncated_to_uuid", func(t *testing.T) {
		t.Parallel()

		longAzureRoleID := "/subscriptions/00000000-1111-2222-3333-444444444444/providers/Microsoft.Authorization/roleDefinitions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
		key := buildCacheKey("AZURE", "", longAzureRoleID, "mycluster.eastus.azmk8s.io", "alice@example.com", "")
		expected := "AZURE:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee:mycluster.eastus.azmk8s.io:alice@example.com"
		if key != expected {
			t.Errorf("expected key %q, got %q", expected, key)
		}
	})

	t.Run("success_aws_role_arn_is_kept_as_is", func(t *testing.T) {
		t.Parallel()

		awsRoleARN := "arn:aws:iam::123456789012:role/k8s_sca_test_role"
		key := buildCacheKey("AWS", "", awsRoleARN, "cluster.eks.amazonaws.com", "alice@example.com", "")
		expected := "AWS:arn:aws:iam::123456789012:role/k8s_sca_test_role:cluster.eks.amazonaws.com:alice@example.com"
		if key != expected {
			t.Errorf("expected key %q, got %q", expected, key)
		}
	})
}

func TestBuildCacheKey_DifferentUsernamesProduceDifferentKeys(t *testing.T) {
	t.Parallel()

	keyAlice := buildCacheKey("AWS", "", "arn:aws:iam::123:role/foo", "cluster.eks.amazonaws.com", "alice@example.com", "")
	keyBob := buildCacheKey("AWS", "", "arn:aws:iam::123:role/foo", "cluster.eks.amazonaws.com", "bob@example.com", "")
	if keyAlice == keyBob {
		t.Errorf("expected per-user cache keys to differ; both yielded %q", keyAlice)
	}
}

func TestBuildCacheKey_IncludesSessionIDWithoutSidPrefix(t *testing.T) {
	t.Parallel()

	got := buildCacheKey("AWS", "org-1", "arn:aws:iam::123:role/foo", "cluster.eks.amazonaws.com", "alice@example.com", "session-abc")
	want := "AWS:arn:aws:iam::123:role/foo:cluster.eks.amazonaws.com:alice@example.com:org-1:session-abc"
	if got != want {
		t.Errorf("buildCacheKey with sessionID = %q, want %q", got, want)
	}
	if strings.Contains(got, ":sid:") {
		t.Errorf("elevate cache key must not contain :sid: prefix; got %q", got)
	}
}

func TestShortRoleKey(t *testing.T) {
	tests := []struct {
		name   string
		roleID string
		want   string
	}{
		{
			name:   "azure_role_definition_keeps_only_uuid_after_marker",
			roleID: "/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/role-uuid",
			want:   "role-uuid",
		},
		{
			name:   "aws_role_arn_unchanged",
			roleID: "arn:aws:iam::123:role/foo",
			want:   "arn:aws:iam::123:role/foo",
		},
		{
			name:   "plain_role_name_unchanged",
			roleID: "viewer",
			want:   "viewer",
		},
		{
			name:   "empty_returns_empty",
			roleID: "",
			want:   "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := shortRoleKey(tt.roleID); got != tt.want {
				t.Errorf("shortRoleKey(%q) = %q, want %q", tt.roleID, got, tt.want)
			}
		})
	}
}

func TestNormalizeUsername(t *testing.T) {
	tests := []struct {
		name     string
		username string
		want     string
	}{
		{
			name:     "lowercases_mixed_case_email",
			username: "Alice@Example.COM",
			want:     "alice@example.com",
		},
		{
			name:     "trims_surrounding_whitespace",
			username: "   alice@example.com\n",
			want:     "alice@example.com",
		},
		{
			name:     "empty_returns_empty",
			username: "",
			want:     "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := normalizeUsername(tt.username); got != tt.want {
				t.Errorf("normalizeUsername(%q) = %q, want %q", tt.username, got, tt.want)
			}
		})
	}
}

func TestBuildCacheKey_Format(t *testing.T) {
	t.Run("success_key_contains_four_colon_separated_parts", func(t *testing.T) {
		t.Parallel()

		key := buildCacheKey("AWS", "", "arn:aws:iam::123:role/foo", "mycluster.eks.amazonaws.com", "alice@example.com", "")
		// The key must start with the uppercased CSP.
		if !strings.HasPrefix(key, "AWS:") {
			t.Errorf("expected key to start with 'AWS:', got %q", key)
		}
		// The key must end with the normalized username.
		if !strings.HasSuffix(key, ":alice@example.com") {
			t.Errorf("expected key to end with ':alice@example.com', got %q", key)
		}
		// The role ARN portion must be present.
		if !strings.Contains(key, "arn:aws:iam::123:role/foo") {
			t.Errorf("expected key to contain role ARN, got %q", key)
		}
		// FQDN must be present between role and username.
		if !strings.Contains(key, ":mycluster.eks.amazonaws.com:") {
			t.Errorf("expected key to contain ':<fqdn>:', got %q", key)
		}
	})
}

func TestParseSessionExpTime(t *testing.T) {
	t.Parallel()
	cases := []struct {
		raw    string
		wantOK bool
	}{
		{"2026-05-21T10:21:07.240104+00:00", true},
		{"2026-05-21T10:21:07.240104Z", true},
		{"2026-05-21T09:37:33.392778", true},
		{"", false},
		{"not-a-time", false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.raw, func(t *testing.T) {
			t.Parallel()
			got, err := parseSessionExpTime(tc.raw)
			if tc.wantOK && err != nil {
				t.Fatalf("parseSessionExpTime(%q): %v", tc.raw, err)
			}
			if !tc.wantOK && err == nil {
				t.Fatalf("expected error for %q, got %v", tc.raw, got)
			}
		})
	}
}

func TestIsCachedElevateStillValid_AzureSessionExpTime(t *testing.T) {
	now := time.Date(2026, 5, 21, 9, 0, 0, 0, time.UTC)
	result := &k8smodels.IdsecSCAK8sElevateResult{
		SessionID:      "sess-1",
		SessionExpTime: "2026-05-21T10:21:07.240104+00:00",
	}

	valid, _ := isCachedElevateStillValid("AZURE", result, now.Add(-time.Hour), time.Hour, now)
	if !valid {
		t.Fatal("expected valid when sessionExpTime is >5m in the future")
	}

	valid, _ = isCachedElevateStillValid("AZURE", result, now.Add(-time.Hour), time.Hour,
		time.Date(2026, 5, 21, 10, 21, 8, 0, time.UTC))
	if valid {
		t.Fatal("expected invalid after sessionExpTime")
	}
}

func TestIsCachedElevateStillValid_AzureShortSession(t *testing.T) {
	// Mirrors production: sessionExpTime ~20–40s after elevate.
	now := time.Date(2026, 5, 21, 12, 46, 0, 0, time.UTC)
	result := &k8smodels.IdsecSCAK8sElevateResult{
		SessionID:      "sess-short",
		SessionExpTime: "2026-05-21T12:46:30+00:00",
	}

	valid, reason := isCachedElevateStillValid("AZURE", result, now, time.Hour, now.Add(5*time.Second))
	if !valid {
		t.Fatalf("expected cache hit 5s into a 30s session, got invalid: %s", reason)
	}

	valid, _ = isCachedElevateStillValid("AZURE", result, now, time.Hour, now.Add(31*time.Second))
	if valid {
		t.Fatal("expected invalid after sessionExpTime passed")
	}
}

func TestIsCachedElevateStillValid_AWSFallbackTTL(t *testing.T) {
	now := time.Now()
	result := &k8smodels.IdsecSCAK8sElevateResult{SessionID: "sess-1"}
	savedAt := now.Add(-30 * time.Minute)

	valid, _ := isCachedElevateStillValid("AWS", result, savedAt, time.Hour, now)
	if !valid {
		t.Fatal("expected valid within 1h SavedAt TTL")
	}

	valid, _ = isCachedElevateStillValid("AWS", result, savedAt.Add(-2*time.Hour), time.Hour, now)
	if valid {
		t.Fatal("expected expired after 1h SavedAt TTL")
	}
}

func TestLoadCachedElevateKeyring(t *testing.T) {
	tests := []struct {
		name        string
		csp         string
		roleKey     string
		fqdn        string
		username    string
		ttl         time.Duration
		expectNil   bool
		expectError bool
	}{
		{
			name:        "success_ttl_zero_returns_nil_without_keyring_access",
			csp:         "AWS",
			roleKey:     "arn:aws:iam::123:role/k8s-role",
			fqdn:        "745445889F087548523CF96B3D365FF0.gr7.us-east-1.eks.amazonaws.com",
			username:    "alice@example.com",
			ttl:         0,
			expectNil:   true,
			expectError: false,
		},
		{
			name:        "success_ttl_zero_for_azure_returns_nil",
			csp:         "AZURE",
			roleKey:     "azure-role",
			fqdn:        "mycluster.eastus.azmk8s.io",
			username:    "alice@example.com",
			ttl:         0,
			expectNil:   true,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, _, _, _, err := LoadCachedElevateKeyringWithReason(tt.csp, "", tt.roleKey, tt.fqdn, tt.username, "", tt.ttl)

			if tt.expectError && err == nil {
				t.Error("expected error but got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if tt.expectNil && result != nil {
				t.Errorf("expected nil result but got %+v", result)
			}
			if !tt.expectNil && result == nil {
				t.Error("expected non-nil result but got nil")
			}
		})
	}
}

func TestBuildCacheKey_WithOrgSuffix(t *testing.T) {
	t.Parallel()
	const orgID = "00000000-1111-2222-3333-444444444444"
	got := buildCacheKey("AZURE", orgID, "role-guid", "cluster.azmk8s.io", "alice@contoso.com", "")
	want := "AZURE:role-guid:cluster.azmk8s.io:alice@contoso.com:" + orgID
	if got != want {
		t.Errorf("buildCacheKey with org = %q, want %q", got, want)
	}
}

func TestBuildCacheKey_DifferentOrgsProduceDifferentKeys(t *testing.T) {
	t.Parallel()
	a := buildCacheKey("AZURE", "org-a", "role", "fqdn", "user@x.com", "")
	b := buildCacheKey("AZURE", "org-b", "role", "fqdn", "user@x.com", "")
	if a == b {
		t.Errorf("expected different keys for different orgs; both %q", a)
	}
}

func TestBuildProxyExecCredential(t *testing.T) {
	t.Parallel()
	cert := "---CERT---"
	key := "---KEY---"
	expiresAt := time.Date(2030, 6, 1, 12, 0, 0, 0, time.UTC)
	cred := k8sservice.BuildProxyExecCredential(cert, key, expiresAt)
	if cred == nil {
		t.Fatal("expected non-nil ExecCredential")
	}
	if cred.APIVersion != "client.authentication.k8s.io/v1beta1" {
		t.Errorf("unexpected APIVersion: %q", cred.APIVersion)
	}
	if cred.Kind != "ExecCredential" {
		t.Errorf("unexpected Kind: %q", cred.Kind)
	}
	if cred.Status.ClientCertificateData != cert {
		t.Errorf("cert mismatch: got %q", cred.Status.ClientCertificateData)
	}
	if cred.Status.ClientKeyData != key {
		t.Errorf("key mismatch: got %q", cred.Status.ClientKeyData)
	}
	if cred.Status.Token != "" {
		t.Errorf("bearer token must be empty for proxy cert cred; got %q", cred.Status.Token)
	}
	if cred.Status.ExpirationTimestamp == "" {
		t.Error("expected expirationTimestamp from metadata.expires_at")
	}
}

// Verify BuildProxyExecCredential uses the correct k8s model shape.
func TestBuildProxyExecCredential_ModelShape(t *testing.T) {
	t.Parallel()
	expiresAt := time.Date(2030, 6, 1, 12, 0, 0, 0, time.UTC)
	cred := k8sservice.BuildProxyExecCredential("CERT_DATA", "KEY_DATA", expiresAt)
	var zero k8smodels.IdsecSCAK8sExecCredential
	_ = zero
	if cred.Status.ClientCertificateData == "" {
		t.Error("ClientCertificateData must not be empty")
	}
	if cred.Status.ClientKeyData == "" {
		t.Error("ClientKeyData must not be empty")
	}
}

// ---------------------------------------------------------------------------
// Unified ExecCredential cache tests.
// ---------------------------------------------------------------------------

type memoryKeyring struct {
	items  map[string]string
	setErr error
}

func newMemoryKeyring() *memoryKeyring {
	return &memoryKeyring{items: map[string]string{}}
}

func (m *memoryKeyring) SetPassword(serviceName string, username string, password string) error {
	if m.setErr != nil {
		return m.setErr
	}
	m.items[serviceName+"\x00"+username] = password
	return nil
}

func (m *memoryKeyring) GetPassword(serviceName string, username string) (string, error) {
	return m.items[serviceName+"\x00"+username], nil
}

func (m *memoryKeyring) DeletePassword(serviceName string, username string) error {
	delete(m.items, serviceName+"\x00"+username)
	return nil
}

func (m *memoryKeyring) ClearAllPasswords() error {
	m.items = map[string]string{}
	return nil
}

func readyTestKeyring(impl *memoryKeyring) *lazyKeyring {
	k := &lazyKeyring{service: execCredCredsServiceName}
	k.once.Do(func() {
		k.impl = impl
	})
	return k
}

func withExecCredentialKeyrings(t *testing.T, primary, basic *memoryKeyring) {
	t.Helper()
	oldPrimary := krExecCred
	oldBasic := krExecCredBasic
	krExecCred = readyTestKeyring(primary)
	krExecCredBasic = readyTestKeyring(basic)
	t.Cleanup(func() {
		krExecCred = oldPrimary
		krExecCredBasic = oldBasic
	})
}

func withParentPID(t *testing.T, pid int) {
	t.Helper()
	old := currentParentPID
	currentParentPID = func() int { return pid }
	t.Cleanup(func() {
		currentParentPID = old
	})
}

func withAzureFingerprint(t *testing.T, fingerprint string) {
	t.Helper()
	old := currentAzureFingerprint
	currentAzureFingerprint = func() string { return fingerprint }
	t.Cleanup(func() {
		currentAzureFingerprint = old
	})
}

func storeCachedExecCredentialForTest(t *testing.T, kr *memoryKeyring, key string, cached cachedExecCredential) {
	t.Helper()
	data, err := json.Marshal(cached)
	if err != nil {
		t.Fatalf("marshal cached credential: %v", err)
	}
	if err := kr.SetPassword(execCredCredsServiceName, key, string(data)); err != nil {
		t.Fatalf("store cached credential: %v", err)
	}
}

func loadCachedExecCredentialForTest(t *testing.T, kr *memoryKeyring, key string) (cachedExecCredential, bool) {
	t.Helper()
	data, err := kr.GetPassword(execCredCredsServiceName, key)
	if err != nil {
		t.Fatalf("load cached credential: %v", err)
	}
	if data == "" {
		return cachedExecCredential{}, false
	}
	var cached cachedExecCredential
	if err := json.Unmarshal([]byte(data), &cached); err != nil {
		t.Fatalf("unmarshal cached credential: %v", err)
	}
	return cached, true
}

func validCachedExecCredential(expiresAt time.Time) cachedExecCredential {
	return cachedExecCredential{
		ExecCredentialJSON: `{"apiVersion":"client.authentication.k8s.io/v1beta1","kind":"ExecCredential","status":{"token":"redacted"}}`,
		ExpiresAt:          expiresAt.UTC(),
		SavedAt:            time.Now().UTC(),
		CSP:                "AWS",
		Method:             ExecCredMethodDirect,
	}
}

// TestBuildUnifiedExecCredKey_Shape verifies the key format is exactly
// CSP:shortRole:fqdn:user:sid (in that order, colon-separated, no orgID).
func TestBuildUnifiedExecCredKey_Shape(t *testing.T) {
	t.Parallel()
	got := buildUnifiedExecCredKey(
		"aws",
		"arn:aws:iam::123456789012:role/k8s-role",
		"cluster.example.com",
		"  Alice@Example.COM  ",
		"sid-abc-123",
	)
	want := "AWS:arn:aws:iam::123456789012:role/k8s-role:cluster.example.com:alice@example.com:sid-abc-123"
	if got != want {
		t.Errorf("buildUnifiedExecCredKey = %q, want %q", got, want)
	}
}

// TestBuildUnifiedExecCredKey_AzureRoleShortened verifies the Azure long-form
// roleDefinitions/<guid> resource IDs are shortened to just the trailing GUID
// (matching the existing shortRoleKey contract).
func TestBuildUnifiedExecCredKey_AzureRoleShortened(t *testing.T) {
	t.Parallel()
	roleID := "/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	got := buildUnifiedExecCredKey(
		"AZURE",
		roleID,
		"mycluster.eastus.azmk8s.io",
		"alice@contoso.com",
		"sid-xyz",
	)
	want := "AZURE:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee:mycluster.eastus.azmk8s.io:alice@contoso.com:sid-xyz"
	if got != want {
		t.Errorf("buildUnifiedExecCredKey azure = %q, want %q", got, want)
	}
}

// TestBuildUnifiedExecCredKey_NoOrganizationID confirms the key never includes
// organizationID (the explicit design choice — FQDN already disambiguates).
func TestBuildUnifiedExecCredKey_NoOrganizationID(t *testing.T) {
	t.Parallel()
	const orgID = "00000000-1111-2222-3333-444444444444"
	got := buildUnifiedExecCredKey("AZURE", "role-guid", "cluster.azmk8s.io", "alice@contoso.com", "sid-1")
	if strings.Contains(got, orgID) {
		t.Errorf("unified key must not contain organizationID; got %q", got)
	}
}

// TestBuildUnifiedExecCredKey_DifferentSessionsRotateNamespace ensures rotation
// of internal_session_id (re-auth) automatically partitions cache namespaces.
func TestBuildUnifiedExecCredKey_DifferentSessionsRotateNamespace(t *testing.T) {
	t.Parallel()
	a := buildUnifiedExecCredKey("AWS", "role", "fqdn.example.com", "user@x.com", "sid-A")
	b := buildUnifiedExecCredKey("AWS", "role", "fqdn.example.com", "user@x.com", "sid-B")
	if a == b {
		t.Errorf("unified keys for different sessionIDs must differ; both = %q", a)
	}
}

// TestBuildUnifiedExecCredKey_DifferentCSPsDoNotCollide guards against the
// (impossible-by-policy but worth-asserting) case of an AWS and Azure entry
// for the same identity colliding on the same key.
func TestBuildUnifiedExecCredKey_DifferentCSPsDoNotCollide(t *testing.T) {
	t.Parallel()
	a := buildUnifiedExecCredKey("AWS", "role", "fqdn.example.com", "user@x.com", "sid-1")
	b := buildUnifiedExecCredKey("AZURE", "role", "fqdn.example.com", "user@x.com", "sid-1")
	if a == b {
		t.Errorf("unified keys for different CSPs must differ; both = %q", a)
	}
}

// TestLoadUnifiedExecCredential_EmptySessionDisablesCache verifies the safety
// fall-through when the ISP token did not yield internal_session_id: we must
// NEVER touch the keyring and must return a clear missReason.
func TestLoadUnifiedExecCredential_EmptySessionDisablesCache(t *testing.T) {
	t.Parallel()
	entry, hitReason, missReason, err := LoadUnifiedExecCredential(
		"AWS", "role", "fqdn.example.com", "user@x.com", "", "",
	)
	if err != nil {
		t.Fatalf("unexpected error on empty sessionID: %v", err)
	}
	if entry != nil {
		t.Errorf("expected nil entry when sessionID is empty; got %+v", entry)
	}
	if hitReason != "" {
		t.Errorf("expected empty hitReason; got %q", hitReason)
	}
	if missReason == "" {
		t.Errorf("expected non-empty missReason explaining cache disabled")
	}
}

func TestLoadUnifiedExecCredential_UpdatesParentMarkerOnCacheHit(t *testing.T) {
	primary := newMemoryKeyring()
	basic := newMemoryKeyring()
	withExecCredentialKeyrings(t, primary, basic)
	withParentPID(t, 4242)

	key := buildUnifiedExecCredKey("AWS", "role", "fqdn.example.com", "user@x.com", "sid-1")
	storeCachedExecCredentialForTest(t, primary, key, validCachedExecCredential(time.Now().Add(15*time.Minute)))

	entry, hitReason, missReason, err := LoadUnifiedExecCredential(
		"AWS", "role", "fqdn.example.com", "user@x.com", "sid-1", "",
	)
	if err != nil {
		t.Fatalf("load unified credential: %v", err)
	}
	if entry == nil {
		t.Fatalf("expected cache hit, missReason=%q", missReason)
	}
	if entry.LastServedParentPID != 4242 {
		t.Fatalf("entry LastServedParentPID = %d, want 4242", entry.LastServedParentPID)
	}
	if !strings.Contains(hitReason, "serve marker updated") {
		t.Fatalf("expected hitReason to mention marker update, got %q", hitReason)
	}
	if !strings.Contains(hitReason, "parentPID=4242") {
		t.Fatalf("expected hitReason to include parent PID, got %q", hitReason)
	}

	persisted, ok := loadCachedExecCredentialForTest(t, primary, key)
	if !ok {
		t.Fatal("expected cache entry to remain after marker update")
	}
	if persisted.LastServedParentPID != 4242 {
		t.Fatalf("persisted LastServedParentPID = %d, want 4242", persisted.LastServedParentPID)
	}
}

func TestLoadUnifiedExecCredential_SameParentUnexpiredPurgesAsProbable401(t *testing.T) {
	primary := newMemoryKeyring()
	basic := newMemoryKeyring()
	withExecCredentialKeyrings(t, primary, basic)
	withParentPID(t, 5150)

	expiresAt := time.Now().Add(15 * time.Minute)
	if err := SaveUnifiedExecCredential(
		"AWS", "role", "fqdn.example.com", "user@x.com",
		"sid-1", ExecCredMethodDirect, `{"status":{"token":"redacted"}}`, expiresAt, "",
	); err != nil {
		t.Fatalf("save unified credential: %v", err)
	}

	entry, hitReason, missReason, err := LoadUnifiedExecCredential(
		"AWS", "role", "fqdn.example.com", "user@x.com", "sid-1", "",
	)
	if err != nil {
		t.Fatalf("second load returned error: %v", err)
	}
	if entry != nil {
		t.Fatalf("expected probable 401 to force cache miss, got entry=%+v hitReason=%q", entry, hitReason)
	}
	if !strings.Contains(missReason, "probable 401 refresh") {
		t.Fatalf("missReason = %q, want probable 401 refresh", missReason)
	}
	if !strings.Contains(missReason, "parentPID=5150") || !strings.Contains(missReason, "forcing cold path") {
		t.Fatalf("expected missReason to include parent PID and cold-path decision, got %q", missReason)
	}

	key := buildUnifiedExecCredKey("AWS", "role", "fqdn.example.com", "user@x.com", "sid-1")
	if _, ok := loadCachedExecCredentialForTest(t, primary, key); ok {
		t.Fatal("expected probable 401 path to delete primary cache entry")
	}
	if _, ok := loadCachedExecCredentialForTest(t, basic, key); ok {
		t.Fatal("expected probable 401 path to delete basic fallback cache entry")
	}
}

func TestSaveUnifiedExecCredential_StoresParentMarkerForFreshCredential(t *testing.T) {
	primary := newMemoryKeyring()
	basic := newMemoryKeyring()
	withExecCredentialKeyrings(t, primary, basic)
	withParentPID(t, 6060)

	expiresAt := time.Now().Add(15 * time.Minute)
	if err := SaveUnifiedExecCredential(
		"AWS", "role", "fqdn.example.com", "user@x.com",
		"sid-1", ExecCredMethodDirect, `{"status":{"token":"redacted"}}`, expiresAt, "",
	); err != nil {
		t.Fatalf("save unified credential: %v", err)
	}

	key := buildUnifiedExecCredKey("AWS", "role", "fqdn.example.com", "user@x.com", "sid-1")
	persisted, ok := loadCachedExecCredentialForTest(t, primary, key)
	if !ok {
		t.Fatal("expected fresh credential to be cached")
	}
	if persisted.LastServedParentPID != 6060 {
		t.Fatalf("fresh save LastServedParentPID = %d, want 6060", persisted.LastServedParentPID)
	}
}

func TestLoadUnifiedExecCredential_ExpiredEntryWinsBeforeSameParentCheck(t *testing.T) {
	primary := newMemoryKeyring()
	basic := newMemoryKeyring()
	withExecCredentialKeyrings(t, primary, basic)
	withParentPID(t, 6262)

	key := buildUnifiedExecCredKey("AWS", "role", "fqdn.example.com", "user@x.com", "sid-1")
	cached := validCachedExecCredential(time.Now().Add(-time.Minute))
	cached.LastServedParentPID = 6262
	storeCachedExecCredentialForTest(t, primary, key, cached)

	entry, hitReason, missReason, err := LoadUnifiedExecCredential(
		"AWS", "role", "fqdn.example.com", "user@x.com", "sid-1", "",
	)
	if err != nil {
		t.Fatalf("load unified credential: %v", err)
	}
	if entry != nil {
		t.Fatalf("expected expired entry to miss, got entry=%+v hitReason=%q", entry, hitReason)
	}
	if !strings.Contains(missReason, "entry expired") {
		t.Fatalf("missReason = %q, want entry expired", missReason)
	}
	if strings.Contains(missReason, "probable 401") {
		t.Fatalf("expired entry must not be classified as 401 refresh: %q", missReason)
	}
}

func TestLoadUnifiedExecCredential_MismatchWinsBeforeSameParentCheck(t *testing.T) {
	primary := newMemoryKeyring()
	basic := newMemoryKeyring()
	withExecCredentialKeyrings(t, primary, basic)
	withParentPID(t, 7373)

	key := buildUnifiedExecCredKey("AWS", "role", "fqdn.example.com", "user@x.com", "sid-1")
	cached := validCachedExecCredential(time.Now().Add(15 * time.Minute))
	cached.CSP = "AZURE"
	cached.LastServedParentPID = 7373
	storeCachedExecCredentialForTest(t, primary, key, cached)

	entry, hitReason, missReason, err := LoadUnifiedExecCredential(
		"AWS", "role", "fqdn.example.com", "user@x.com", "sid-1", "",
	)
	if err != nil {
		t.Fatalf("load unified credential: %v", err)
	}
	if entry != nil {
		t.Fatalf("expected csp mismatch to miss, got entry=%+v hitReason=%q", entry, hitReason)
	}
	if !strings.Contains(missReason, "csp mismatch") {
		t.Fatalf("missReason = %q, want csp mismatch", missReason)
	}
	if strings.Contains(missReason, "probable 401") {
		t.Fatalf("mismatch must not be classified as 401 refresh: %q", missReason)
	}
}

func TestLoadUnifiedExecCredential_AzureFingerprintWinsBeforeSameParentCheck(t *testing.T) {
	primary := newMemoryKeyring()
	basic := newMemoryKeyring()
	withExecCredentialKeyrings(t, primary, basic)
	withParentPID(t, 7474)
	withAzureFingerprint(t, "current-fingerprint")

	key := buildUnifiedExecCredKey("AZURE", "role", "fqdn.example.com", "user@x.com", "sid-1")
	cached := validCachedExecCredential(time.Now().Add(15 * time.Minute))
	cached.CSP = k8smodels.CSPAzure
	cached.AzureCLIFingerprint = "old-fingerprint"
	cached.LastServedParentPID = 7474
	storeCachedExecCredentialForTest(t, primary, key, cached)

	entry, hitReason, missReason, err := LoadUnifiedExecCredential(
		"AZURE", "role", "fqdn.example.com", "user@x.com", "sid-1", "",
	)
	if err != nil {
		t.Fatalf("load unified credential: %v", err)
	}
	if entry != nil {
		t.Fatalf("expected azure fingerprint mismatch to miss, got entry=%+v hitReason=%q", entry, hitReason)
	}
	if !strings.Contains(missReason, "azure cli fingerprint changed") {
		t.Fatalf("missReason = %q, want azure cli fingerprint changed", missReason)
	}
	if strings.Contains(missReason, "probable 401") {
		t.Fatalf("fingerprint mismatch must not be classified as 401 refresh: %q", missReason)
	}
	if _, ok := loadCachedExecCredentialForTest(t, primary, key); ok {
		t.Fatal("expected azure fingerprint mismatch to delete primary cache entry")
	}
}

func TestLoadUnifiedExecCredential_BasicFallbackUpdatesParentMarker(t *testing.T) {
	primary := newMemoryKeyring()
	basic := newMemoryKeyring()
	withExecCredentialKeyrings(t, primary, basic)
	withParentPID(t, 8484)

	key := buildUnifiedExecCredKey("AWS", "role", "fqdn.example.com", "user@x.com", "sid-1")
	storeCachedExecCredentialForTest(t, basic, key, validCachedExecCredential(time.Now().Add(15*time.Minute)))

	entry, hitReason, missReason, err := LoadUnifiedExecCredential(
		"AWS", "role", "fqdn.example.com", "user@x.com", "sid-1", "",
	)
	if err != nil {
		t.Fatalf("load unified credential: %v", err)
	}
	if entry == nil {
		t.Fatalf("expected basic fallback cache hit, missReason=%q", missReason)
	}
	if !strings.Contains(hitReason, "serve marker updated") {
		t.Fatalf("expected hitReason to mention marker update, got %q", hitReason)
	}
	if !strings.Contains(hitReason, "parentPID=8484") {
		t.Fatalf("expected hitReason to include parent PID, got %q", hitReason)
	}
	if _, ok := loadCachedExecCredentialForTest(t, primary, key); ok {
		t.Fatal("primary keyring should stay empty when hit came from basic fallback")
	}
	persisted, ok := loadCachedExecCredentialForTest(t, basic, key)
	if !ok {
		t.Fatal("expected basic fallback entry to remain")
	}
	if persisted.LastServedParentPID != 8484 {
		t.Fatalf("basic fallback LastServedParentPID = %d, want 8484", persisted.LastServedParentPID)
	}
}

func TestLoadUnifiedExecCredential_ParentMarkerWriteFailureForcesColdPath(t *testing.T) {
	primary := newMemoryKeyring()
	basic := newMemoryKeyring()
	withExecCredentialKeyrings(t, primary, basic)
	withParentPID(t, 9595)

	key := buildUnifiedExecCredKey("AWS", "role", "fqdn.example.com", "user@x.com", "sid-1")
	storeCachedExecCredentialForTest(t, primary, key, validCachedExecCredential(time.Now().Add(15*time.Minute)))
	primary.setErr = errors.New("write failed")

	entry, hitReason, missReason, err := LoadUnifiedExecCredential(
		"AWS", "role", "fqdn.example.com", "user@x.com", "sid-1", "",
	)
	if err != nil {
		t.Fatalf("load unified credential: %v", err)
	}
	if entry != nil {
		t.Fatalf("marker write failure should force cache miss, got entry=%+v hitReason=%q", entry, hitReason)
	}
	if !strings.Contains(missReason, "serve marker update failed") {
		t.Fatalf("missReason = %q, want marker update failed", missReason)
	}
	if !strings.Contains(missReason, "parentPID=9595") || !strings.Contains(missReason, "forcing cold path") {
		t.Fatalf("expected missReason to include parent PID and cold-path decision, got %q", missReason)
	}
	if _, ok := loadCachedExecCredentialForTest(t, primary, key); ok {
		t.Fatal("expected marker write failure to delete primary cache entry")
	}
	if _, ok := loadCachedExecCredentialForTest(t, basic, key); ok {
		t.Fatal("expected marker write failure to delete basic fallback cache entry")
	}
}

// TestSaveUnifiedExecCredential_GuardClauses asserts the four input-validation
// guards on Save (no sid, zero expiry, empty payload, unknown method). These
// guards prevent us from polluting the keyring with malformed entries that
// would later cause confusing miss reasons or silent data-shape corruption.
func TestSaveUnifiedExecCredential_GuardClauses(t *testing.T) {
	t.Parallel()
	validExp := time.Now().Add(15 * time.Minute)
	validJSON := `{"apiVersion":"client.authentication.k8s.io/v1beta1","kind":"ExecCredential"}`

	cases := []struct {
		name      string
		sessionID string
		method    CachedExecCredentialMethod
		json      string
		expiresAt time.Time
		errSubstr string
	}{
		{name: "empty_sid", sessionID: "", method: ExecCredMethodDirect, json: validJSON, expiresAt: validExp, errSubstr: "sessionID is empty"},
		{name: "zero_expiry", sessionID: "sid-1", method: ExecCredMethodDirect, json: validJSON, expiresAt: time.Time{}, errSubstr: "expiresAt is zero"},
		{name: "empty_json", sessionID: "sid-1", method: ExecCredMethodDirect, json: "   ", expiresAt: validExp, errSubstr: "empty JSON payload"},
		{name: "unknown_method", sessionID: "sid-1", method: CachedExecCredentialMethod("bogus"), json: validJSON, expiresAt: validExp, errSubstr: "unknown execcred method"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := SaveUnifiedExecCredential(
				"AWS", "role", "fqdn.example.com", "user@x.com",
				tc.sessionID, tc.method, tc.json, tc.expiresAt, "",
			)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.errSubstr)
			}
			if !strings.Contains(err.Error(), tc.errSubstr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.errSubstr)
			}
		})
	}
}

// TestDeleteUnifiedExecCredential_EmptySessionIDIsNoop ensures Delete does not
// error on missing sessionID (matches the Save/Load fall-through contract).
func TestDeleteUnifiedExecCredential_EmptySessionIDIsNoop(t *testing.T) {
	t.Parallel()
	if err := DeleteUnifiedExecCredential("AWS", "role", "fqdn.example.com", "user@x.com", ""); err != nil {
		t.Fatalf("expected nil error for empty sessionID, got %v", err)
	}
}

// TestExecCredMethodConstants asserts the on-the-wire string values used in
// stored entries don't drift; renaming them silently would invalidate every
// entry on every user's machine.
func TestExecCredMethodConstants(t *testing.T) {
	t.Parallel()
	if got := string(ExecCredMethodDirect); got != "direct" {
		t.Errorf("ExecCredMethodDirect = %q, want %q", got, "direct")
	}
	if got := string(ExecCredMethodProxy); got != "proxy" {
		t.Errorf("ExecCredMethodProxy = %q, want %q", got, "proxy")
	}
}

// ---------------------------------------------------------------------------
// computeEffectiveExecCredentialExpiry tests: flow-specific min formulas.
// Already-buffered ExecCredential/cert timestamps pass through unchanged; raw
// token/session expiries are skewed by rawTokenEarlyRefreshBuffer before comparison.
// ---------------------------------------------------------------------------

func TestComputeEffectiveExecCredentialExpiry_FlowFormulas(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 6, 11, 10, 0, 0, 0, time.UTC)

	tests := []struct {
		name       string
		candidates []ttlCandidate
		want       time.Time
		wantPicked string
	}{
		{
			name: "aws_direct_min_eks_elevate_idtoken",
			candidates: []ttlCandidate{
				{name: "eks", when: now.Add(14 * time.Minute), alreadyBuffered: true},
				{name: "elevate", when: now.Add(60 * time.Minute), skew: rawTokenEarlyRefreshBuffer},
				{name: "idtokenlifetime", when: now.Add(12 * time.Hour), skew: rawTokenEarlyRefreshBuffer},
			},
			want:       now.Add(14 * time.Minute),
			wantPicked: "eks",
		},
		{
			name: "aws_proxy_min_cert_idtoken",
			candidates: []ttlCandidate{
				{name: "cert", when: now.Add(30 * time.Minute), alreadyBuffered: true},
				{name: "idtokenlifetime", when: now.Add(10 * time.Minute), skew: rawTokenEarlyRefreshBuffer},
			},
			want:       now.Add(9 * time.Minute),
			wantPicked: "idtokenlifetime",
		},
		{
			name: "azure_direct_min_aks_elevate_idtoken",
			candidates: []ttlCandidate{
				{name: "aks", when: now.Add(45 * time.Minute), alreadyBuffered: true},
				{name: "elevate", when: now.Add(12 * time.Minute), skew: rawTokenEarlyRefreshBuffer},
				{name: "idtokenlifetime", when: now.Add(12 * time.Hour), skew: rawTokenEarlyRefreshBuffer},
			},
			want:       now.Add(11 * time.Minute),
			wantPicked: "elevate",
		},
		{
			name: "azure_proxy_min_cert_aks_elevate_idtoken",
			candidates: []ttlCandidate{
				{name: "cert", when: now.Add(30 * time.Minute), alreadyBuffered: true},
				{name: "aks", when: now.Add(20 * time.Minute), skew: rawTokenEarlyRefreshBuffer},
				{name: "elevate", when: now.Add(60 * time.Minute), skew: rawTokenEarlyRefreshBuffer},
				{name: "idtokenlifetime", when: now.Add(12 * time.Hour), skew: rawTokenEarlyRefreshBuffer},
			},
			want:       now.Add(19 * time.Minute),
			wantPicked: "aks",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, picked, err := computeEffectiveExecCredentialExpiry(tt.candidates...)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !got.Equal(tt.want) {
				t.Errorf("expected %s, got %s", tt.want.UTC().Format(time.RFC3339), got.UTC().Format(time.RFC3339))
			}
			if picked != tt.wantPicked {
				t.Errorf("expected picked=%q, got %q", tt.wantPicked, picked)
			}
		})
	}
}

func TestComputeEffectiveExecCredentialExpiry_AnyMissingFailsWithCandidateDetails(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 6, 11, 10, 0, 0, 0, time.UTC)

	t.Run("all_missing_returns_error_listing_each_candidate", func(t *testing.T) {
		t.Parallel()
		got, picked, err := computeEffectiveExecCredentialExpiry(
			ttlCandidate{name: "cert", skipReason: "missing"},
			ttlCandidate{name: "idtokenlifetime", skipReason: "empty"},
		)
		if err == nil {
			t.Fatal("expected error when all candidates are missing expiration")
		}
		if !strings.Contains(err.Error(), "cert (missing)") || !strings.Contains(err.Error(), "idtokenlifetime (empty)") {
			t.Errorf("expected error to name each missing candidate with its reason; got %q", err.Error())
		}
		if !got.IsZero() || picked != "" {
			t.Errorf("expected zero/empty return on error; got got=%s picked=%q", got, picked)
		}
	})

	t.Run("one_missing_among_valid_still_fails", func(t *testing.T) {
		t.Parallel()
		_, _, err := computeEffectiveExecCredentialExpiry(
			ttlCandidate{name: "cert", when: now.Add(30 * time.Minute), alreadyBuffered: true},
			ttlCandidate{name: "elevate", skipReason: "unparseable"},
			ttlCandidate{name: "idtokenlifetime", when: now.Add(12 * time.Hour), skew: rawTokenEarlyRefreshBuffer},
		)
		if err == nil {
			t.Fatal("expected error when any candidate is missing expiration")
		}
		if !strings.Contains(err.Error(), "elevate (unparseable)") {
			t.Errorf("expected error to mention the missing candidate elevate; got %q", err.Error())
		}
		if !strings.Contains(err.Error(), "1 candidate(s) missing expiration") {
			t.Errorf("expected error to count missing candidates; got %q", err.Error())
		}
	})

	t.Run("zero_when_without_skip_reason_defaults_to_missing_expiration", func(t *testing.T) {
		t.Parallel()
		_, _, err := computeEffectiveExecCredentialExpiry(
			ttlCandidate{name: "aks"},
		)
		if err == nil {
			t.Fatal("expected error for bare zero-when candidate")
		}
		if !strings.Contains(err.Error(), "aks (missing expiration)") {
			t.Errorf("expected fallback reason in error; got %q", err.Error())
		}
	})
}

func TestComputeEffectiveExecCredentialExpiry_AlreadyBufferedNeverDoubleBuffered(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 6, 11, 10, 0, 0, 0, time.UTC)
	certExp := now.Add(5 * time.Minute)
	aksExp := certExp.Add(rawTokenEarlyRefreshBuffer + time.Second)

	got, picked, err := computeEffectiveExecCredentialExpiry(
		ttlCandidate{name: "cert", when: certExp, alreadyBuffered: true},
		ttlCandidate{name: "aks", when: aksExp, skew: rawTokenEarlyRefreshBuffer},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got.Equal(certExp) {
		t.Errorf("already-buffered cert must pass through verbatim; got %s want %s",
			got.UTC().Format(time.RFC3339), certExp.UTC().Format(time.RFC3339))
	}
	if picked != "cert" {
		t.Errorf("expected picked=cert, got %q", picked)
	}
}

func TestComputeEffectiveExecCredentialExpiry_TiesPickInsertionOrder(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 6, 11, 10, 0, 0, 0, time.UTC)
	certExp := now.Add(10 * time.Minute)
	aksExp := certExp.Add(rawTokenEarlyRefreshBuffer)

	got, picked, err := computeEffectiveExecCredentialExpiry(
		ttlCandidate{name: "cert", when: certExp, alreadyBuffered: true},
		ttlCandidate{name: "aks", when: aksExp, skew: rawTokenEarlyRefreshBuffer},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got.Equal(certExp) {
		t.Errorf("expected tie to resolve to first candidate; got %s", got.UTC().Format(time.RFC3339))
	}
	if picked != "cert" {
		t.Errorf("expected picked=cert on tie, got %q", picked)
	}
}

func TestLoadCachedElevateKeyringWithReason_EmptySessionDisablesCache(t *testing.T) {
	t.Parallel()
	result, savedAt, hitReason, missReason, err := LoadCachedElevateKeyringWithReason(
		"AWS", "", "arn:aws:iam::123:role/foo", "cluster.eks.amazonaws.com", "alice@example.com", "", time.Hour,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil || !savedAt.IsZero() || hitReason != "" {
		t.Fatalf("expected empty result on disabled cache; got result=%v savedAt=%v hitReason=%q", result, savedAt, hitReason)
	}
	if missReason != "missing session id (cache disabled)" {
		t.Errorf("missReason = %q, want %q", missReason, "missing session id (cache disabled)")
	}
}

func TestSaveCreds_EmptySessionIDIsNoop(t *testing.T) {
	t.Parallel()
	err := SaveCreds("AWS", "", "role", "fqdn", "user@x.com", "", &k8smodels.IdsecSCAK8sElevateResult{SessionID: "s"})
	if err != nil {
		t.Fatalf("expected nil error for empty sessionID, got %v", err)
	}
}

func TestDeriveElevateExpiry_UnparseableSessionExpTimeFallsBack(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 6, 11, 10, 0, 0, 0, time.UTC)
	result := &k8smodels.IdsecSCAK8sElevateResult{SessionExpTime: "not-a-time"}
	exp, source := deriveElevateExpiry(result, base, time.Hour, false)
	if !exp.Equal(base.Add(time.Hour)) {
		t.Errorf("expected fallbackTTL expiry, got %s", exp.UTC().Format(time.RFC3339))
	}
	if source != "fallbackTTL" {
		t.Errorf("source = %q, want fallbackTTL", source)
	}
}

func TestApplyFlowExecCredentialTTL_LogsCandidatesAndFinalTimestamp(t *testing.T) {
	t.Setenv("IDSEC_VERBOSE", "true")
	cmd := &cobra.Command{Use: "kubectl-login"}
	now := time.Date(2026, 6, 11, 10, 0, 0, 0, time.UTC)
	cred := k8sservice.BuildProxyExecCredential("CERT", "KEY", now.Add(30*time.Minute))
	loginSess := kubectlLoginSession{idTokenExpiresAt: now.Add(12 * time.Hour)}
	req := buildKubectlLoginRequest("AZURE", "role", "fqdn", "org", "", "", loginSess)
	aksToken := testJWTWithExp(now.Add(20 * time.Minute))

	stderr := captureKubectlLoginStderr(t, func() {
		(&IdsecKubectlLoginAction{}).applyFlowExecCredentialTTL(
			cmd, execCredFlowAzureProxy, cred, now.Add(60*time.Minute), req, aksToken,
		)
	})

	logs := string(stderr)
	for _, want := range []string{
		"azure proxy effective TTL candidates",
		"cert: raw=2026-06-11T10:30:00Z effective=2026-06-11T10:30:00Z source=already-buffered",
		"aks: raw=2026-06-11T10:20:00Z effective=2026-06-11T10:19:00Z source=raw skew=1m0s",
		"elevate: raw=2026-06-11T11:00:00Z effective=2026-06-11T10:59:00Z source=raw skew=1m0s",
		"idtokenlifetime: raw=2026-06-11T22:00:00Z effective=2026-06-11T21:59:00Z source=raw skew=1m0s",
		"azure proxy effective TTL: selected=aks expirationTimestamp=2026-06-11T10:19:00Z",
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("expected logs to contain %q; got %s", want, logs)
		}
	}
	if got := cred.Status.ExpirationTimestamp; got != "2026-06-11T10:19:00Z" {
		t.Errorf("expected final expirationTimestamp to be rewritten, got %q", got)
	}
}

func TestApplyFlowExecCredentialTTL_LogsCandidatesWithIDSECVerbose(t *testing.T) {
	t.Setenv("IDSEC_VERBOSE", "true")
	cmd := &cobra.Command{Use: "kubectl-login"}

	now := time.Date(2026, 6, 11, 10, 0, 0, 0, time.UTC)
	cred := k8sservice.BuildProxyExecCredential("CERT", "KEY", now.Add(30*time.Minute))
	loginSess := kubectlLoginSession{idTokenExpiresAt: now.Add(10 * time.Minute)}
	req := buildKubectlLoginRequest("AWS", "role", "fqdn", "", "", "", loginSess)

	stderr := captureKubectlLoginStderr(t, func() {
		(&IdsecKubectlLoginAction{}).applyFlowExecCredentialTTL(
			cmd, execCredFlowAWSProxy, cred, time.Time{}, req, "",
		)
	})

	if !strings.Contains(string(stderr), "effective TTL candidates") {
		t.Errorf("expected TTL candidate logs with IDSEC_VERBOSE=true, got %s", stderr)
	}
	if got := cred.Status.ExpirationTimestamp; got != "2026-06-11T10:09:00Z" {
		t.Errorf("expected final expirationTimestamp to still be rewritten, got %q", got)
	}
}

func testJWTWithExp(exp time.Time) string {
	payload := fmt.Sprintf(`{"exp":%d}`, exp.Unix())
	encoded := base64.RawURLEncoding.EncodeToString([]byte(payload))
	return "eyJhbGciOiJIUzI1NiJ9." + encoded + ".sig"
}
