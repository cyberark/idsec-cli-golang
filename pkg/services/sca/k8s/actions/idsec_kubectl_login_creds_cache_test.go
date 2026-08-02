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
	idseckeyring "github.com/cyberark/idsec-sdk-golang/pkg/common/keyring"
	"github.com/cyberark/idsec-sdk-golang/pkg/models"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
	k8sservice "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s"
	k8smodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s/models"
)

func TestBuildSCAK8sCacheKey(t *testing.T) {
	const (
		testUUID = "91ff5db2-24c9-4a2b-b414-ec416dfbd43f"
		testSID  = "sid-abc-123"
	)
	tests := []struct {
		name        string
		profileName string
		csp         string
		roleKey     string
		fqdn        string
		userUUID    string
		namespace   string
		sessionID   string
		expected    string
	}{
		{
			name:        "all_fields_set",
			profileName: "prod",
			csp:         "AWS",
			roleKey:     "arn:aws:iam::123456789012:role/k8s-role",
			fqdn:        "cluster.gr7.us-east-1.eks.amazonaws.com",
			userUUID:    testUUID,
			namespace:   "",
			sessionID:   testSID,
			expected:    "prod:AWS:arn_aws_iam__123456789012_role/k8s-role:cluster.gr7.us-east-1.eks.amazonaws.com:" + testUUID + ":" + testSID,
		},
		{
			name:        "with_namespace",
			profileName: "prod",
			csp:         "AZURE",
			roleKey:     "role-guid",
			fqdn:        "cluster.eastus.azmk8s.io",
			userUUID:    testUUID,
			namespace:   "remediation-tracker",
			sessionID:   testSID,
			expected:    "prod:AZURE:role-guid:cluster.eastus.azmk8s.io:" + testUUID + ":remediation-tracker:" + testSID,
		},
		{
			name:        "csp_is_uppercased",
			profileName: "dev",
			csp:         "azure",
			roleKey:     "role-guid",
			fqdn:        "cluster.eastus.azmk8s.io",
			userUUID:    testUUID,
			namespace:   "",
			sessionID:   testSID,
			expected:    "dev:AZURE:role-guid:cluster.eastus.azmk8s.io:" + testUUID + ":" + testSID,
		},
		{
			name:        "profile_name_colon_sanitized",
			profileName: "org:prod",
			csp:         "AWS",
			roleKey:     "arn:aws:iam::123:role/foo",
			fqdn:        "cluster.example.com",
			userUUID:    testUUID,
			namespace:   "",
			sessionID:   testSID,
			expected:    "org_prod:AWS:arn_aws_iam__123_role/foo:cluster.example.com:" + testUUID + ":" + testSID,
		},
		{
			name:        "profile_name_case_preserved",
			profileName: "MyProfile",
			csp:         "AWS",
			roleKey:     "arn:aws:iam::123:role/foo",
			fqdn:        "cluster.example.com",
			userUUID:    testUUID,
			namespace:   "",
			sessionID:   testSID,
			expected:    "MyProfile:AWS:arn_aws_iam__123_role/foo:cluster.example.com:" + testUUID + ":" + testSID,
		},
		{
			name:        "namespace_colon_sanitized",
			profileName: "prod",
			csp:         "AZURE",
			roleKey:     "role-guid",
			fqdn:        "cluster.azmk8s.io",
			userUUID:    testUUID,
			namespace:   "ns:foo",
			sessionID:   testSID,
			expected:    "prod:AZURE:role-guid:cluster.azmk8s.io:" + testUUID + ":ns_foo:" + testSID,
		},
		{
			name:        "user_uuid_trimmed_only_not_lowercased",
			profileName: "prod",
			csp:         "AWS",
			roleKey:     "role",
			fqdn:        "cluster.example.com",
			userUUID:    "  " + testUUID + "  ",
			namespace:   "",
			sessionID:   testSID,
			expected:    "prod:AWS:role:cluster.example.com:" + testUUID + ":" + testSID,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := buildSCAK8sCacheKey(tt.profileName, tt.csp, tt.roleKey, tt.fqdn, tt.userUUID, tt.namespace, tt.sessionID)
			if got != tt.expected {
				t.Errorf("buildSCAK8sCacheKey = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestBuildSCAK8sCacheKey_AzureRoleIsShortened(t *testing.T) {
	const testUUID = "91ff5db2-24c9-4a2b-b414-ec416dfbd43f"

	t.Run("azure_role_definition_truncated_to_uuid", func(t *testing.T) {
		t.Parallel()
		longAzureRoleID := "/subscriptions/00000000-1111-2222-3333-444444444444/providers/Microsoft.Authorization/roleDefinitions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
		got := buildSCAK8sCacheKey("prod", "AZURE", longAzureRoleID, "cluster.eastus.azmk8s.io", testUUID, "", "sid-1")
		want := "prod:AZURE:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee:cluster.eastus.azmk8s.io:" + testUUID + ":sid-1"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("aws_role_arn_colons_sanitized", func(t *testing.T) {
		t.Parallel()
		awsRoleARN := "arn:aws:iam::123456789012:role/k8s_sca_test_role"
		got := buildSCAK8sCacheKey("prod", "AWS", awsRoleARN, "cluster.eks.amazonaws.com", testUUID, "", "sid-1")
		want := "prod:AWS:arn_aws_iam__123456789012_role/k8s_sca_test_role:cluster.eks.amazonaws.com:" + testUUID + ":sid-1"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})
}

func TestBuildSCAK8sCacheKey_DifferentUserUUIDsProduceDifferentKeys(t *testing.T) {
	t.Parallel()
	keyA := buildSCAK8sCacheKey("prod", "AWS", "arn:aws:iam::123:role/foo", "cluster.eks.amazonaws.com", "uuid-a", "", "sid-1")
	keyB := buildSCAK8sCacheKey("prod", "AWS", "arn:aws:iam::123:role/foo", "cluster.eks.amazonaws.com", "uuid-b", "", "sid-1")
	if keyA == keyB {
		t.Errorf("expected per-user cache keys to differ; both yielded %q", keyA)
	}
}

func TestBuildSCAK8sCacheKey_DifferentProfilesIsolateKeys(t *testing.T) {
	t.Parallel()
	const testUUID = "91ff5db2-24c9-4a2b-b414-ec416dfbd43f"
	keyA := buildSCAK8sCacheKey("prod", "AWS", "role", "cluster.eks.amazonaws.com", testUUID, "", "sid-1")
	keyB := buildSCAK8sCacheKey("dev", "AWS", "role", "cluster.eks.amazonaws.com", testUUID, "", "sid-1")
	if keyA == keyB {
		t.Errorf("expected per-profile cache keys to differ; both yielded %q", keyA)
	}
}

func TestBuildSCAK8sCacheKey_DifferentNamespacesIsolateKeys(t *testing.T) {
	t.Parallel()
	const testUUID = "91ff5db2-24c9-4a2b-b414-ec416dfbd43f"
	keyNS := buildSCAK8sCacheKey("prod", "AZURE", "role", "cluster.azmk8s.io", testUUID, "remediation-tracker", "sid-1")
	keyNoNS := buildSCAK8sCacheKey("prod", "AZURE", "role", "cluster.azmk8s.io", testUUID, "", "sid-1")
	if keyNS == keyNoNS {
		t.Errorf("expected namespace-scoped and cluster-scoped keys to differ; both = %q", keyNS)
	}
}

func TestSanitizeCacheSegment(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input string
		want  string
	}{
		{"prod", "prod"},
		{"org:prod", "org_prod"},
		{"  prod  ", "prod"},
		{"ns:foo:bar", "ns_foo_bar"},
		{"", ""},
		{"  ", ""},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()
			if got := sanitizeCacheSegment(tt.input); got != tt.want {
				t.Errorf("sanitizeCacheSegment(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
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

func TestIsCachedElevateStillValid_SessionExpTime(t *testing.T) {
	now := time.Date(2026, 5, 21, 9, 0, 0, 0, time.UTC)
	result := &k8smodels.IdsecSCAK8sElevateResult{
		SessionID:      "sess-1",
		SessionExpTime: "2026-05-21T10:21:07.240104+00:00",
	}

	valid, _ := isCachedElevateStillValid(result, now)
	if !valid {
		t.Fatal("expected valid when sessionExpTime is >5m in the future")
	}

	valid, _ = isCachedElevateStillValid(result, time.Date(2026, 5, 21, 10, 21, 8, 0, time.UTC))
	if valid {
		t.Fatal("expected invalid after sessionExpTime")
	}
}

func TestIsCachedElevateStillValid_ShortSession(t *testing.T) {
	now := time.Date(2026, 5, 21, 12, 46, 0, 0, time.UTC)
	result := &k8smodels.IdsecSCAK8sElevateResult{
		SessionID:      "sess-short",
		SessionExpTime: "2026-05-21T12:46:30+00:00",
	}

	valid, reason := isCachedElevateStillValid(result, now.Add(5*time.Second))
	if !valid {
		t.Fatalf("expected cache hit 5s into a 30s session, got invalid: %s", reason)
	}

	valid, _ = isCachedElevateStillValid(result, now.Add(31*time.Second))
	if valid {
		t.Fatal("expected invalid after sessionExpTime passed")
	}
}

func TestIsCachedElevateStillValid_MissingSessionExpTime(t *testing.T) {
	now := time.Now()
	result := &k8smodels.IdsecSCAK8sElevateResult{SessionID: "sess-1"}

	valid, reason := isCachedElevateStillValid(result, now)
	if valid {
		t.Fatal("expected invalid when sessionExpTime is missing")
	}
	if !strings.Contains(reason, "missing sessionExpTime") {
		t.Fatalf("expected reason to mention missing sessionExpTime, got %q", reason)
	}
}

func TestIsCachedElevateStillValid_AWSIAMSessionExpTime(t *testing.T) {
	now := time.Date(2026, 7, 20, 9, 0, 0, 0, time.UTC)
	result := &k8smodels.IdsecSCAK8sElevateResult{
		SessionID:      "sess-aws-iam",
		SessionExpTime: "2026-07-20T10:00:00+00:00",
	}

	valid, reason := isCachedElevateStillValid(result, now)
	if !valid {
		t.Fatalf("expected valid when sessionExpTime is >5m in the future; reason=%s", reason)
	}
	if !strings.Contains(reason, "sessionExpTime") {
		t.Fatalf("expected reason to reference sessionExpTime, got %q", reason)
	}

	valid, _ = isCachedElevateStillValid(result, time.Date(2026, 7, 20, 10, 0, 1, 0, time.UTC))
	if valid {
		t.Fatal("expected invalid after sessionExpTime for AWS IAM")
	}
}

func TestIsCachedElevateStillValid_AWSIAMSessionExpTimeExpired(t *testing.T) {
	result := &k8smodels.IdsecSCAK8sElevateResult{
		SessionID:      "sess-aws-iam",
		SessionExpTime: "2026-07-20T10:00:00+00:00",
	}

	valid, reason := isCachedElevateStillValid(result, time.Date(2026, 7, 20, 10, 0, 1, 0, time.UTC))
	if valid {
		t.Fatalf("expected invalid after sessionExpTime for AWS IAM; reason=%s", reason)
	}
	if !strings.Contains(reason, "expired") {
		t.Fatalf("expected reason to mention expired, got %q", reason)
	}
}

func TestLoadCachedElevateKeyring(t *testing.T) {
	const testUUID = "91ff5db2-24c9-4a2b-b414-ec416dfbd43f"

	t.Run("empty_keyring_returns_nil", func(t *testing.T) {
		t.Parallel()
		result, _, _, err := LoadCachedElevateKeyringWithReason(
			"prod", "AWS", "arn:aws:iam::123:role/k8s-role",
			"745445889F087548523CF96B3D365FF0.gr7.us-east-1.eks.amazonaws.com",
			testUUID, "", "sid-1",
		)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result != nil {
			t.Errorf("expected nil result but got %+v", result)
		}
	})
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

func (m *memoryKeyring) ListKeys(serviceName string) ([]string, error) {
	prefix := serviceName + "\x00"
	keys := make([]string, 0)
	for k := range m.items {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, strings.TrimPrefix(k, prefix))
		}
	}
	return keys, nil
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

// withAllCacheKeyrings wires elevate + execcred primary/basic and AWS IDC OIDC
// primary to the same in-memory stores.
func withAllCacheKeyrings(t *testing.T, primary, basic *memoryKeyring) {
	t.Helper()
	withExecCredentialKeyrings(t, primary, basic)
	oldElev := krElevateCreds
	oldElevBasic := krBasicFallback
	oldOIDC := krAWSIDCOIDC
	krElevateCreds = readyTestKeyring(primary)
	krBasicFallback = readyTestKeyring(basic)
	krAWSIDCOIDC = readyTestKeyring(primary)
	t.Cleanup(func() {
		krElevateCreds = oldElev
		krBasicFallback = oldElevBasic
		krAWSIDCOIDC = oldOIDC
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

// TestBuildSCAK8sCacheKey_Shape verifies the key format is
// profileName:CSP:shortRole:fqdn:userUUID[:namespace]:sessionID.
func TestBuildSCAK8sCacheKey_Shape(t *testing.T) {
	t.Parallel()
	const testUUID = "91ff5db2-24c9-4a2b-b414-ec416dfbd43f"
	got := buildSCAK8sCacheKey(
		"prod",
		"aws",
		"arn:aws:iam::123456789012:role/k8s-role",
		"cluster.example.com",
		testUUID,
		"",
		"sid-abc-123",
	)
	want := "prod:AWS:arn_aws_iam__123456789012_role/k8s-role:cluster.example.com:" + testUUID + ":sid-abc-123"
	if got != want {
		t.Errorf("buildSCAK8sCacheKey = %q, want %q", got, want)
	}
}

// TestBuildSCAK8sCacheKey_WithNamespace verifies namespace is included in the key.
func TestBuildSCAK8sCacheKey_WithNamespace(t *testing.T) {
	t.Parallel()
	const testUUID = "91ff5db2-24c9-4a2b-b414-ec416dfbd43f"
	got := buildSCAK8sCacheKey("prod", "AZURE", "role-guid", "cluster.azmk8s.io", testUUID, "remediation-tracker", "sid-1")
	want := "prod:AZURE:role-guid:cluster.azmk8s.io:" + testUUID + ":remediation-tracker:sid-1"
	if got != want {
		t.Errorf("buildSCAK8sCacheKey with namespace = %q, want %q", got, want)
	}
}

// TestBuildSCAK8sCacheKey_AzureRoleShortened verifies the Azure long-form
// roleDefinitions/<guid> resource IDs are shortened to just the trailing GUID.
func TestBuildSCAK8sCacheKey_AzureRoleShortened(t *testing.T) {
	t.Parallel()
	const testUUID = "91ff5db2-24c9-4a2b-b414-ec416dfbd43f"
	roleID := "/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	got := buildSCAK8sCacheKey("prod", "AZURE", roleID, "mycluster.eastus.azmk8s.io", testUUID, "", "sid-xyz")
	want := "prod:AZURE:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee:mycluster.eastus.azmk8s.io:" + testUUID + ":sid-xyz"
	if got != want {
		t.Errorf("buildSCAK8sCacheKey azure = %q, want %q", got, want)
	}
}

func TestBuildSCAK8sCacheKey_NoOrganizationID(t *testing.T) {
	t.Parallel()
	const testUUID = "91ff5db2-24c9-4a2b-b414-ec416dfbd43f"
	const orgID = "00000000-1111-2222-3333-444444444444"
	got := buildSCAK8sCacheKey("prod", "AZURE", "role-guid", "cluster.azmk8s.io", testUUID, "", "sid-1")
	if strings.Contains(got, orgID) {
		t.Errorf("key must not contain organizationID; got %q", got)
	}
}

// TestBuildSCAK8sCacheKey_DifferentSessionsRotateNamespace ensures rotation
// of internal_session_id (re-auth) automatically partitions cache namespaces.
func TestBuildSCAK8sCacheKey_DifferentSessionsRotateNamespace(t *testing.T) {
	t.Parallel()
	const testUUID = "91ff5db2-24c9-4a2b-b414-ec416dfbd43f"
	a := buildSCAK8sCacheKey("prod", "AWS", "role", "fqdn.example.com", testUUID, "", "sid-A")
	b := buildSCAK8sCacheKey("prod", "AWS", "role", "fqdn.example.com", testUUID, "", "sid-B")
	if a == b {
		t.Errorf("unified keys for different sessionIDs must differ; both = %q", a)
	}
}

// TestBuildSCAK8sCacheKey_DifferentCSPsDoNotCollide guards against AWS and Azure
// entries for the same identity colliding on the same key.
func TestBuildSCAK8sCacheKey_DifferentCSPsDoNotCollide(t *testing.T) {
	t.Parallel()
	const testUUID = "91ff5db2-24c9-4a2b-b414-ec416dfbd43f"
	a := buildSCAK8sCacheKey("prod", "AWS", "role", "fqdn.example.com", testUUID, "", "sid-1")
	b := buildSCAK8sCacheKey("prod", "AZURE", "role", "fqdn.example.com", testUUID, "", "sid-1")
	if a == b {
		t.Errorf("unified keys for different CSPs must differ; both = %q", a)
	}
}

// TestLoadUnifiedExecCredential_EmptySessionDisablesCache verifies that
// missing sessionID or userUUID disables the cache without touching the keyring.
func TestLoadUnifiedExecCredential_EmptySessionDisablesCache(t *testing.T) {
	t.Parallel()
	const testUUID = "91ff5db2-24c9-4a2b-b414-ec416dfbd43f"

	t.Run("empty_session_id", func(t *testing.T) {
		t.Parallel()
		entry, hitReason, missReason, err := LoadUnifiedExecCredential(
			"prod", "AWS", "role", "fqdn.example.com", testUUID, "", "", "",
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if entry != nil {
			t.Errorf("expected nil entry when sessionID is empty; got %+v", entry)
		}
		if hitReason != "" {
			t.Errorf("expected empty hitReason; got %q", hitReason)
		}
		if !strings.Contains(missReason, "sessionID") {
			t.Errorf("expected missReason to mention sessionID; got %q", missReason)
		}
	})

	t.Run("empty_user_uuid", func(t *testing.T) {
		t.Parallel()
		entry, hitReason, missReason, err := LoadUnifiedExecCredential(
			"prod", "AWS", "role", "fqdn.example.com", "", "", "sid-1", "",
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if entry != nil {
			t.Errorf("expected nil entry when userUUID is empty; got %+v", entry)
		}
		if hitReason != "" {
			t.Errorf("expected empty hitReason; got %q", hitReason)
		}
		if !strings.Contains(missReason, "userUUID") {
			t.Errorf("expected missReason to mention userUUID; got %q", missReason)
		}
	})
}

func TestLoadUnifiedExecCredential_UpdatesParentMarkerOnCacheHit(t *testing.T) {
	primary := newMemoryKeyring()
	basic := newMemoryKeyring()
	withExecCredentialKeyrings(t, primary, basic)
	withParentPID(t, 4242)

	const testUUID = "91ff5db2-24c9-4a2b-b414-ec416dfbd43f"
	key := buildSCAK8sCacheKey("prod", "AWS", "role", "fqdn.example.com", testUUID, "", "sid-1")
	storeCachedExecCredentialForTest(t, primary, key, validCachedExecCredential(time.Now().Add(15*time.Minute)))

	entry, hitReason, missReason, err := LoadUnifiedExecCredential(
		"prod", "AWS", "role", "fqdn.example.com", testUUID, "", "sid-1", "",
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

	const testUUID = "91ff5db2-24c9-4a2b-b414-ec416dfbd43f"
	expiresAt := time.Now().Add(15 * time.Minute)
	if err := SaveUnifiedExecCredential(
		"prod", "AWS", "role", "fqdn.example.com", testUUID, "",
		"sid-1", ExecCredMethodDirect, `{"status":{"token":"redacted"}}`, expiresAt, "",
	); err != nil {
		t.Fatalf("save unified credential: %v", err)
	}

	entry, hitReason, missReason, err := LoadUnifiedExecCredential(
		"prod", "AWS", "role", "fqdn.example.com", testUUID, "", "sid-1", "",
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

	key := buildSCAK8sCacheKey("prod", "AWS", "role", "fqdn.example.com", testUUID, "", "sid-1")
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

	const testUUID = "91ff5db2-24c9-4a2b-b414-ec416dfbd43f"
	expiresAt := time.Now().Add(15 * time.Minute)
	if err := SaveUnifiedExecCredential(
		"prod", "AWS", "role", "fqdn.example.com", testUUID, "",
		"sid-1", ExecCredMethodDirect, `{"status":{"token":"redacted"}}`, expiresAt, "",
	); err != nil {
		t.Fatalf("save unified credential: %v", err)
	}

	key := buildSCAK8sCacheKey("prod", "AWS", "role", "fqdn.example.com", testUUID, "", "sid-1")
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

	const testUUID = "91ff5db2-24c9-4a2b-b414-ec416dfbd43f"
	key := buildSCAK8sCacheKey("prod", "AWS", "role", "fqdn.example.com", testUUID, "", "sid-1")
	cached := validCachedExecCredential(time.Now().Add(-time.Minute))
	cached.LastServedParentPID = 6262
	storeCachedExecCredentialForTest(t, primary, key, cached)

	entry, hitReason, missReason, err := LoadUnifiedExecCredential(
		"prod", "AWS", "role", "fqdn.example.com", testUUID, "", "sid-1", "",
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

	const testUUID = "91ff5db2-24c9-4a2b-b414-ec416dfbd43f"
	key := buildSCAK8sCacheKey("prod", "AWS", "role", "fqdn.example.com", testUUID, "", "sid-1")
	cached := validCachedExecCredential(time.Now().Add(15 * time.Minute))
	cached.CSP = "AZURE"
	cached.LastServedParentPID = 7373
	storeCachedExecCredentialForTest(t, primary, key, cached)

	entry, hitReason, missReason, err := LoadUnifiedExecCredential(
		"prod", "AWS", "role", "fqdn.example.com", testUUID, "", "sid-1", "",
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

	const testUUID = "91ff5db2-24c9-4a2b-b414-ec416dfbd43f"
	key := buildSCAK8sCacheKey("prod", "AZURE", "role", "fqdn.example.com", testUUID, "", "sid-1")
	cached := validCachedExecCredential(time.Now().Add(15 * time.Minute))
	cached.CSP = k8smodels.CSPAzure
	cached.AzureCLIFingerprint = "old-fingerprint"
	cached.LastServedParentPID = 7474
	storeCachedExecCredentialForTest(t, primary, key, cached)

	entry, hitReason, missReason, err := LoadUnifiedExecCredential(
		"prod", "AZURE", "role", "fqdn.example.com", testUUID, "", "sid-1", "",
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

	const testUUID = "91ff5db2-24c9-4a2b-b414-ec416dfbd43f"
	key := buildSCAK8sCacheKey("prod", "AWS", "role", "fqdn.example.com", testUUID, "", "sid-1")
	storeCachedExecCredentialForTest(t, basic, key, validCachedExecCredential(time.Now().Add(15*time.Minute)))

	entry, hitReason, missReason, err := LoadUnifiedExecCredential(
		"prod", "AWS", "role", "fqdn.example.com", testUUID, "", "sid-1", "",
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

	const testUUID = "91ff5db2-24c9-4a2b-b414-ec416dfbd43f"
	key := buildSCAK8sCacheKey("prod", "AWS", "role", "fqdn.example.com", testUUID, "", "sid-1")
	storeCachedExecCredentialForTest(t, primary, key, validCachedExecCredential(time.Now().Add(15*time.Minute)))
	primary.setErr = errors.New("write failed")

	entry, hitReason, missReason, err := LoadUnifiedExecCredential(
		"prod", "AWS", "role", "fqdn.example.com", testUUID, "", "sid-1", "",
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

// TestSaveUnifiedExecCredential_GuardClauses asserts input-validation guards on Save.
func TestSaveUnifiedExecCredential_GuardClauses(t *testing.T) {
	t.Parallel()
	const testUUID = "91ff5db2-24c9-4a2b-b414-ec416dfbd43f"
	validExp := time.Now().Add(15 * time.Minute)
	validJSON := `{"apiVersion":"client.authentication.k8s.io/v1beta1","kind":"ExecCredential"}`

	cases := []struct {
		name      string
		sessionID string
		userUUID  string
		method    CachedExecCredentialMethod
		json      string
		expiresAt time.Time
		errSubstr string
	}{
		{name: "empty_sid", sessionID: "", userUUID: testUUID, method: ExecCredMethodDirect, json: validJSON, expiresAt: validExp, errSubstr: "sessionID is empty"},
		{name: "empty_user_uuid", sessionID: "sid-1", userUUID: "", method: ExecCredMethodDirect, json: validJSON, expiresAt: validExp, errSubstr: "userUUID is empty"},
		{name: "zero_expiry", sessionID: "sid-1", userUUID: testUUID, method: ExecCredMethodDirect, json: validJSON, expiresAt: time.Time{}, errSubstr: "expiresAt is zero"},
		{name: "empty_json", sessionID: "sid-1", userUUID: testUUID, method: ExecCredMethodDirect, json: "   ", expiresAt: validExp, errSubstr: "empty JSON payload"},
		{name: "unknown_method", sessionID: "sid-1", userUUID: testUUID, method: CachedExecCredentialMethod("bogus"), json: validJSON, expiresAt: validExp, errSubstr: "unknown execcred method"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := SaveUnifiedExecCredential(
				"prod", "AWS", "role", "fqdn.example.com", tc.userUUID, "",
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

// TestDeleteUnifiedExecCredential_EmptyClaimsIsNoop ensures Delete does not
// error on missing sessionID or userUUID.
func TestDeleteUnifiedExecCredential_EmptyClaimsIsNoop(t *testing.T) {
	t.Parallel()
	const testUUID = "91ff5db2-24c9-4a2b-b414-ec416dfbd43f"

	if err := DeleteUnifiedExecCredential("prod", "AWS", "role", "fqdn.example.com", testUUID, "", ""); err != nil {
		t.Fatalf("expected nil error for empty sessionID, got %v", err)
	}
	if err := DeleteUnifiedExecCredential("prod", "AWS", "role", "fqdn.example.com", "", "", "sid-1"); err != nil {
		t.Fatalf("expected nil error for empty userUUID, got %v", err)
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
			name: "aws_direct_min_eks_elevate",
			candidates: []ttlCandidate{
				{name: "eks", when: now.Add(14 * time.Minute), alreadyBuffered: true},
				{name: "elevate", when: now.Add(60 * time.Minute), skew: rawTokenEarlyRefreshBuffer},
			},
			want:       now.Add(14 * time.Minute),
			wantPicked: "eks",
		},
		{
			name: "aws_proxy_cert_only",
			candidates: []ttlCandidate{
				{name: "cert", when: now.Add(30 * time.Minute), alreadyBuffered: true},
			},
			want:       now.Add(30 * time.Minute),
			wantPicked: "cert",
		},
		{
			name: "azure_direct_min_aks_elevate",
			candidates: []ttlCandidate{
				{name: "aks", when: now.Add(45 * time.Minute), alreadyBuffered: true},
				{name: "elevate", when: now.Add(12 * time.Minute), skew: rawTokenEarlyRefreshBuffer},
			},
			want:       now.Add(11 * time.Minute),
			wantPicked: "elevate",
		},
		{
			name: "azure_proxy_min_cert_aks_elevate",
			candidates: []ttlCandidate{
				{name: "cert", when: now.Add(30 * time.Minute), alreadyBuffered: true},
				{name: "aks", when: now.Add(20 * time.Minute), skew: rawTokenEarlyRefreshBuffer},
				{name: "elevate", when: now.Add(60 * time.Minute), skew: rawTokenEarlyRefreshBuffer},
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
			ttlCandidate{name: "elevate", skipReason: "empty"},
		)
		if err == nil {
			t.Fatal("expected error when all candidates are missing expiration")
		}
		if !strings.Contains(err.Error(), "cert (missing)") || !strings.Contains(err.Error(), "elevate (empty)") {
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
	const testUUID = "91ff5db2-24c9-4a2b-b414-ec416dfbd43f"

	t.Run("empty_session_id", func(t *testing.T) {
		t.Parallel()
		result, hitReason, missReason, err := LoadCachedElevateKeyringWithReason(
			"prod", "AWS", "arn:aws:iam::123:role/foo", "cluster.eks.amazonaws.com", testUUID, "", "",
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != nil || hitReason != "" {
			t.Fatalf("expected empty result on disabled cache; got result=%v hitReason=%q", result, hitReason)
		}
		if !strings.Contains(missReason, "sessionID") {
			t.Errorf("missReason = %q, want mention of sessionID", missReason)
		}
	})

	t.Run("empty_user_uuid", func(t *testing.T) {
		t.Parallel()
		result, hitReason, missReason, err := LoadCachedElevateKeyringWithReason(
			"prod", "AWS", "arn:aws:iam::123:role/foo", "cluster.eks.amazonaws.com", "", "", "sid-1",
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != nil || hitReason != "" {
			t.Fatalf("expected empty result when userUUID is empty; got result=%v hitReason=%q", result, hitReason)
		}
		if !strings.Contains(missReason, "userUUID") {
			t.Errorf("missReason = %q, want mention of userUUID", missReason)
		}
	})
}

func TestSaveElevateCreds_EmptyClaimsReturnsError(t *testing.T) {
	t.Parallel()
	const testUUID = "91ff5db2-24c9-4a2b-b414-ec416dfbd43f"
	result := &k8smodels.IdsecSCAK8sElevateResult{SessionID: "s"}

	t.Run("empty_session_id", func(t *testing.T) {
		t.Parallel()
		err := SaveElevateCreds("prod", "AWS", "role", "fqdn", testUUID, "", "", result)
		if err == nil {
			t.Fatal("expected error for empty sessionID, got nil")
		}
		if !strings.Contains(err.Error(), "sessionID is empty") {
			t.Errorf("error %q does not contain 'sessionID is empty'", err.Error())
		}
	})

	t.Run("empty_user_uuid", func(t *testing.T) {
		t.Parallel()
		err := SaveElevateCreds("prod", "AWS", "role", "fqdn", "", "", "sid-1", result)
		if err == nil {
			t.Fatal("expected error for empty userUUID, got nil")
		}
		if !strings.Contains(err.Error(), "userUUID is empty") {
			t.Errorf("error %q does not contain 'userUUID is empty'", err.Error())
		}
	})
}

func TestDeriveElevateExpiry_UnparseableSessionExpTimeErrors(t *testing.T) {
	t.Parallel()
	result := &k8smodels.IdsecSCAK8sElevateResult{SessionExpTime: "not-a-time"}
	_, err := deriveElevateExpiry(result)
	if err == nil {
		t.Fatal("expected error for unparseable sessionExpTime")
	}
	if !strings.Contains(err.Error(), "not parseable") {
		t.Errorf("error = %q, want mention of not parseable", err.Error())
	}
}

func TestDeriveElevateExpiry_MissingSessionExpTimeErrors(t *testing.T) {
	t.Parallel()
	result := &k8smodels.IdsecSCAK8sElevateResult{SessionID: "sess-1"}
	_, err := deriveElevateExpiry(result)
	if err == nil {
		t.Fatal("expected error for missing sessionExpTime")
	}
	if !strings.Contains(err.Error(), "missing sessionExpTime") {
		t.Errorf("error = %q, want mention of missing sessionExpTime", err.Error())
	}
}

func TestDeriveElevateExpiry_ValidSessionExpTime(t *testing.T) {
	t.Parallel()
	result := &k8smodels.IdsecSCAK8sElevateResult{
		SessionExpTime: "2026-07-20T10:00:00+00:00",
	}
	exp, err := deriveElevateExpiry(result)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := time.Date(2026, 7, 20, 10, 0, 0, 0, time.UTC)
	if !exp.Equal(want) {
		t.Errorf("expected %s, got %s", want.Format(time.RFC3339), exp.Format(time.RFC3339))
	}
}

func TestDeriveElevateExpiry_NilResultErrors(t *testing.T) {
	t.Parallel()
	_, err := deriveElevateExpiry(nil)
	if err == nil {
		t.Fatal("expected error for nil result")
	}
}

func TestApplyFlowExecCredentialTTL_LogsCandidatesAndFinalTimestamp(t *testing.T) {
	t.Setenv("IDSEC_VERBOSE", "true")
	cmd := &cobra.Command{Use: "kubectl-login"}
	now := time.Date(2026, 6, 11, 10, 0, 0, 0, time.UTC)
	cred := k8sservice.BuildProxyExecCredential("CERT", "KEY", now.Add(30*time.Minute))
	aksToken := testJWTWithExp(now.Add(20 * time.Minute))

	stderr := captureKubectlLoginStderr(t, func() {
		(&IdsecKubectlLoginAction{}).applyFlowExecCredentialTTL(
			cmd, execCredFlowAzureProxy, cred, now.Add(60*time.Minute), aksToken,
		)
	})

	logs := string(stderr)
	for _, want := range []string{
		"azure proxy effective TTL candidates",
		"cert: raw=2026-06-11T10:30:00Z effective=2026-06-11T10:30:00Z source=already-buffered",
		"aks: raw=2026-06-11T10:20:00Z effective=2026-06-11T10:19:00Z source=raw skew=1m0s",
		"elevate: raw=2026-06-11T11:00:00Z effective=2026-06-11T10:59:00Z source=raw skew=1m0s",
		"azure proxy effective TTL: selected=aks expirationTimestamp=2026-06-11T10:19:00Z",
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("expected logs to contain %q; got %s", want, logs)
		}
	}
	if strings.Contains(logs, "idtokenlifetime") {
		t.Errorf("idtokenlifetime must not appear in TTL candidates; got %s", logs)
	}
	if got := cred.Status.ExpirationTimestamp; got != "2026-06-11T10:19:00Z" {
		t.Errorf("expected final expirationTimestamp to be rewritten, got %q", got)
	}
}

func TestApplyFlowExecCredentialTTL_AWSProxyUsesCertExpiryOnly(t *testing.T) {
	t.Setenv("IDSEC_VERBOSE", "true")
	cmd := &cobra.Command{Use: "kubectl-login"}

	now := time.Date(2026, 6, 11, 10, 0, 0, 0, time.UTC)
	cred := k8sservice.BuildProxyExecCredential("CERT", "KEY", now.Add(30*time.Minute))

	stderr := captureKubectlLoginStderr(t, func() {
		(&IdsecKubectlLoginAction{}).applyFlowExecCredentialTTL(
			cmd, execCredFlowAWSProxy, cred, time.Time{}, "",
		)
	})

	logs := string(stderr)
	if !strings.Contains(logs, "effective TTL candidates") {
		t.Errorf("expected TTL candidate logs with IDSEC_VERBOSE=true, got %s", stderr)
	}
	if strings.Contains(logs, "idtokenlifetime") {
		t.Errorf("idtokenlifetime must not appear in AWS-proxy TTL candidates; got %s", logs)
	}
	// Cert expiry is already buffered by BuildProxyExecCredential; no extra id_token cap.
	if got := cred.Status.ExpirationTimestamp; got != "2026-06-11T10:30:00Z" {
		t.Errorf("expected AWS-proxy TTL to equal cert expirationTimestamp, got %q", got)
	}
}

func testJWTWithExp(exp time.Time) string {
	payload := fmt.Sprintf(`{"exp":%d}`, exp.Unix())
	encoded := base64.RawURLEncoding.EncodeToString([]byte(payload))
	return "eyJhbGciOiJIUzI1NiJ9." + encoded + ".sig"
}

func setupKubectlLoginISPKeyringTest(t *testing.T) {
	t.Helper()
	t.Setenv("IDSEC_BASIC_KEYRING", "true")
	t.Setenv("IDSEC_KEYRING_FOLDER", t.TempDir())
}

func seedExpiredKubectlLoginISPKeyringToken(t *testing.T, profile *models.IdsecProfile, username string) {
	t.Helper()
	seedExpiredKubectlLoginISPKeyringTokenWithClaims(t, profile, username, "sid-expired", "91ff5db2-24c9-4a2b-b414-ec416dfbd43f")
}

func seedExpiredKubectlLoginISPKeyringTokenWithClaims(t *testing.T, profile *models.IdsecProfile, username, sessionID, userUUID string) {
	t.Helper()
	kr := idseckeyring.NewIdsecKeyring("IdsecISPAuth")
	past := time.Now().Add(-1 * time.Hour)
	if err := kr.SaveToken(profile, &authmodels.IdsecToken{
		Token:        testISPJWT(sessionID, userUUID),
		Username:     username,
		ExpiresIn:    commonmodels.IdsecRFC3339Time(past),
		RefreshToken: "refresh-token",
		TokenType:    authmodels.JWT,
	}, username, true); err != nil {
		t.Fatalf("failed to seed ISP keyring: %v", err)
	}
}

func testISPJWT(sessionID, userUUID string) string {
	payload := fmt.Sprintf(`{"internal_session_id":%q,"user_uuid":%q}`, sessionID, userUUID)
	encoded := base64.RawURLEncoding.EncodeToString([]byte(payload))
	return "eyJhbGciOiJIUzI1NiJ9." + encoded + ".sig"
}

func TestLoadCachedISPSession(t *testing.T) {
	setupKubectlLoginISPKeyringTest(t)

	const username = "user@cyberark.cloud.1234"
	profile := &models.IdsecProfile{ProfileName: "has-cached-isp-session-test"}

	cached, claims, err := loadCachedISPSession(profile, username)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cached {
		t.Fatal("expected no cached ISP session for empty keyring")
	}
	if claims.SessionID != "" || claims.UserUUID != "" {
		t.Fatalf("expected empty claims when no cache, got %+v", claims)
	}

	seedExpiredKubectlLoginISPKeyringToken(t, profile, username)

	cached, claims, err = loadCachedISPSession(profile, username)
	if err != nil {
		t.Fatalf("unexpected error after seeding cache: %v", err)
	}
	if !cached {
		t.Fatal("expected cached ISP session for expired refreshable token")
	}
	if claims.SessionID != "sid-expired" || claims.UserUUID != "91ff5db2-24c9-4a2b-b414-ec416dfbd43f" {
		t.Fatalf("expected pre-refresh claims from seeded JWT, got %+v", claims)
	}
}

func TestLoadCachedISPSession_UnparseableTokenStillRefreshEligible(t *testing.T) {
	setupKubectlLoginISPKeyringTest(t)

	const username = "user@cyberark.cloud.1234"
	profile := &models.IdsecProfile{ProfileName: "kubectl-login-opaque-token-test"}
	kr := idseckeyring.NewIdsecKeyring("IdsecISPAuth")
	past := time.Now().Add(-1 * time.Hour)
	if err := kr.SaveToken(profile, &authmodels.IdsecToken{
		Token:        "not-a-jwt",
		Username:     username,
		ExpiresIn:    commonmodels.IdsecRFC3339Time(past),
		RefreshToken: "refresh-token",
		TokenType:    authmodels.JWT,
	}, username, true); err != nil {
		t.Fatalf("failed to seed ISP keyring: %v", err)
	}

	hasCache, claims, err := loadCachedISPSession(profile, username)
	if err != nil {
		t.Fatalf("unexpected cache probe error: %v", err)
	}
	if !hasCache {
		t.Fatal("expected opaque/unparseable token entry to remain refresh-eligible")
	}
	if claims.SessionID != "" || claims.UserUUID != "" {
		t.Fatalf("expected empty claims for unparseable token, got %+v", claims)
	}
}

func TestLoadCachedISPSession_ExpiredStillRefreshEligible(t *testing.T) {
	setupKubectlLoginISPKeyringTest(t)

	const username = "user@cyberark.cloud.1234"
	profile := &models.IdsecProfile{ProfileName: "kubectl-login-expired-cache-test"}
	seedExpiredKubectlLoginISPKeyringToken(t, profile, username)

	hasCache, _, err := loadCachedISPSession(profile, username)
	if err != nil {
		t.Fatalf("unexpected cache probe error: %v", err)
	}
	if !hasCache {
		t.Fatal("expected expired refreshable session to remain cache-eligible for silent refresh")
	}
}

func TestParseCacheKeyAndRewrite(t *testing.T) {
	t.Parallel()
	const testUUID = "91ff5db2-24c9-4a2b-b414-ec416dfbd43f"

	key := buildSCAK8sCacheKey("prod", "AWS", "arn:aws:iam::123:role/foo", "fqdn.example.com", testUUID, "ns:a", "sid-old")
	fields, ok := parseCacheKey(key)
	if !ok {
		t.Fatalf("parseCacheKey failed for %q", key)
	}
	if fields.profileName != "prod" || fields.userUUID != testUUID || fields.sessionID != "sid-old" {
		t.Fatalf("unexpected fields: %+v", fields)
	}
	if !keyBelongsToUser(key, "prod", testUUID) {
		t.Fatal("expected keyBelongsToUser")
	}
	if !keyMatchesSession(key, "sid-old") {
		t.Fatal("expected keyMatchesSession")
	}
	newKey, ok := rewriteCacheKeySession(key, "sid-new")
	if !ok {
		t.Fatal("rewriteCacheKeySession failed")
	}
	want := buildSCAK8sCacheKey("prod", "AWS", "arn:aws:iam::123:role/foo", "fqdn.example.com", testUUID, "ns:a", "sid-new")
	if newKey != want {
		t.Fatalf("rewrite got %q want %q", newKey, want)
	}
}

func TestRemapUserCacheSessionKeys_MultipleClusters(t *testing.T) {
	primary := newMemoryKeyring()
	basic := newMemoryKeyring()
	withAllCacheKeyrings(t, primary, basic)

	const (
		profile = "prod"
		uuid    = "91ff5db2-24c9-4a2b-b414-ec416dfbd43f"
		oldSID  = "sid-old"
		newSID  = "sid-new"
	)

	keyAOld := buildSCAK8sCacheKey(profile, "AWS", "role-a", "a.example.com", uuid, "", oldSID)
	keyBOld := buildSCAK8sCacheKey(profile, "AZURE", "role-b", "b.example.com", uuid, "ns1", oldSID)
	keyOtherUser := buildSCAK8sCacheKey(profile, "AWS", "role-c", "c.example.com", "other-uuid", "", oldSID)

	storeCachedExecCredentialForTest(t, primary, keyAOld, validCachedExecCredential(time.Now().Add(15*time.Minute)))
	storeCachedExecCredentialForTest(t, primary, keyBOld, validCachedExecCredential(time.Now().Add(15*time.Minute)))
	storeCachedExecCredentialForTest(t, primary, keyOtherUser, validCachedExecCredential(time.Now().Add(15*time.Minute)))

	elevPayload, _ := json.Marshal(cachedElevateCreds{
		ElevateResult: &k8smodels.IdsecSCAK8sElevateResult{SessionID: "elev"},
		SavedAt:       time.Now().UTC(),
	})
	_ = primary.SetPassword(elevateCredsServiceName, keyAOld, string(elevPayload))

	oidcPayload, _ := json.Marshal(cachedAWSOIDCAccessToken{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		ExpiresAt:    time.Now().UTC().Add(time.Hour),
		SavedAt:      time.Now().UTC(),
	})
	_ = primary.SetPassword(awsIDCOIDCCredsServiceName, keyAOld, string(oidcPayload))

	remapUserCacheSessionKeys(profile, uuid, oldSID, newSID)

	keyANew := buildSCAK8sCacheKey(profile, "AWS", "role-a", "a.example.com", uuid, "", newSID)
	keyBNew := buildSCAK8sCacheKey(profile, "AZURE", "role-b", "b.example.com", uuid, "ns1", newSID)

	if _, ok := loadCachedExecCredentialForTest(t, primary, keyANew); !ok {
		t.Fatal("expected cluster A remapped under new SID")
	}
	if _, ok := loadCachedExecCredentialForTest(t, primary, keyBNew); !ok {
		t.Fatal("expected cluster B remapped under new SID")
	}
	if _, ok := loadCachedExecCredentialForTest(t, primary, keyAOld); ok {
		t.Fatal("expected old cluster A key deleted")
	}
	if _, ok := loadCachedExecCredentialForTest(t, primary, keyOtherUser); !ok {
		t.Fatal("expected other-user key untouched")
	}
	if data, _ := primary.GetPassword(elevateCredsServiceName, keyANew); data == "" {
		t.Fatal("expected elevate entry remapped")
	}
	if data, _ := primary.GetPassword(awsIDCOIDCCredsServiceName, keyANew); data == "" {
		t.Fatal("expected AWS IDC OIDC entry remapped")
	}
	if data, _ := primary.GetPassword(awsIDCOIDCCredsServiceName, keyAOld); data != "" {
		t.Fatal("expected old AWS IDC OIDC key deleted")
	}

	// Idempotent: new already present → delete old only (no overwrite).
	storeCachedExecCredentialForTest(t, primary, keyAOld, validCachedExecCredential(time.Now().Add(time.Hour)))
	remapUserCacheSessionKeys(profile, uuid, oldSID, newSID)
	if _, ok := loadCachedExecCredentialForTest(t, primary, keyAOld); ok {
		t.Fatal("expected leftover old key deleted on second remap")
	}
}

func TestPurgeUserCacheEntries(t *testing.T) {
	primary := newMemoryKeyring()
	basic := newMemoryKeyring()
	withAllCacheKeyrings(t, primary, basic)

	const (
		profile = "prod"
		uuid    = "91ff5db2-24c9-4a2b-b414-ec416dfbd43f"
	)
	keep := buildSCAK8sCacheKey(profile, "AWS", "role", "a.example.com", "other-uuid", "", "sid-1")
	drop := buildSCAK8sCacheKey(profile, "AWS", "role", "a.example.com", uuid, "", "sid-1")
	storeCachedExecCredentialForTest(t, primary, keep, validCachedExecCredential(time.Now().Add(15*time.Minute)))
	storeCachedExecCredentialForTest(t, primary, drop, validCachedExecCredential(time.Now().Add(15*time.Minute)))

	oidcPayload, _ := json.Marshal(cachedAWSOIDCAccessToken{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		ExpiresAt:    time.Now().UTC().Add(time.Hour),
		SavedAt:      time.Now().UTC(),
	})
	_ = primary.SetPassword(awsIDCOIDCCredsServiceName, drop, string(oidcPayload))
	_ = primary.SetPassword(awsIDCOIDCCredsServiceName, keep, string(oidcPayload))

	purgeUserCacheEntries(profile, uuid)

	if _, ok := loadCachedExecCredentialForTest(t, primary, drop); ok {
		t.Fatal("expected user entry purged")
	}
	if _, ok := loadCachedExecCredentialForTest(t, primary, keep); !ok {
		t.Fatal("expected other-user entry kept")
	}
	if data, _ := primary.GetPassword(awsIDCOIDCCredsServiceName, drop); data != "" {
		t.Fatal("expected user AWS IDC OIDC entry purged")
	}
	if data, _ := primary.GetPassword(awsIDCOIDCCredsServiceName, keep); data == "" {
		t.Fatal("expected other-user AWS IDC OIDC entry kept")
	}
}

func TestPurgeUserCacheEntries_EmptyUserUUIDPurgesWholeProfile(t *testing.T) {
	primary := newMemoryKeyring()
	basic := newMemoryKeyring()
	withAllCacheKeyrings(t, primary, basic)

	const profile = "prod"
	userA := buildSCAK8sCacheKey(profile, "AWS", "role", "a.example.com", "uuid-a", "", "sid-1")
	userB := buildSCAK8sCacheKey(profile, "AWS", "role", "b.example.com", "uuid-b", "", "sid-1")
	otherProfile := buildSCAK8sCacheKey("other", "AWS", "role", "c.example.com", "uuid-a", "", "sid-1")
	storeCachedExecCredentialForTest(t, primary, userA, validCachedExecCredential(time.Now().Add(15*time.Minute)))
	storeCachedExecCredentialForTest(t, primary, userB, validCachedExecCredential(time.Now().Add(15*time.Minute)))
	storeCachedExecCredentialForTest(t, primary, otherProfile, validCachedExecCredential(time.Now().Add(15*time.Minute)))

	purgeUserCacheEntries(profile, "")

	if _, ok := loadCachedExecCredentialForTest(t, primary, userA); ok {
		t.Fatal("expected profile user A purged when uuid unavailable")
	}
	if _, ok := loadCachedExecCredentialForTest(t, primary, userB); ok {
		t.Fatal("expected profile user B purged when uuid unavailable")
	}
	if _, ok := loadCachedExecCredentialForTest(t, primary, otherProfile); !ok {
		t.Fatal("expected other profile entry kept")
	}
}

func TestExecCredTTLCandidates_NoIDTokenLifetime(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 6, 11, 10, 0, 0, 0, time.UTC)
	cred := k8sservice.BuildProxyExecCredential("CERT", "KEY", now.Add(30*time.Minute))

	cands := execCredTTLCandidates(execCredFlowAWSProxy, cred, time.Time{}, "")
	if len(cands) != 1 || cands[0].name != "cert" {
		t.Fatalf("AWS-proxy candidates = %+v, want only cert", cands)
	}
	for _, c := range cands {
		if c.name == "idtokenlifetime" {
			t.Fatal("idtokenlifetime must not be a TTL candidate")
		}
	}
}

func TestExecCredTTLCandidates_AWSIDCProxy_IncludesCertEKSAndElevate(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 6, 11, 10, 0, 0, 0, time.UTC)
	certExpiry := now.Add(30 * time.Minute)
	elevateExpiry := now.Add(45 * time.Minute)
	eksExpiry := now.Add(14 * time.Minute)

	cred := k8sservice.BuildProxyExecCredential("CERT", "KEY", certExpiry)
	eksExpirationTimestamp := eksExpiry.UTC().Format(time.RFC3339)

	cands := execCredTTLCandidates(execCredFlowAWSIDCProxy, cred, elevateExpiry, eksExpirationTimestamp)
	if len(cands) != 3 {
		t.Fatalf("AWS IDC proxy candidates = %+v, want 3 (cert, eks, elevate)", cands)
	}

	wantNames := map[string]bool{"cert": false, "eks": false, "elevate": false}
	for _, c := range cands {
		if _, ok := wantNames[c.name]; !ok {
			t.Errorf("unexpected candidate %q", c.name)
		}
		wantNames[c.name] = true
	}
	for name, found := range wantNames {
		if !found {
			t.Errorf("missing expected candidate %q", name)
		}
	}
}
