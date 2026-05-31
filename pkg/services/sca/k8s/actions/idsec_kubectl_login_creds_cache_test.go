package actions

import (
	"strings"
	"testing"
	"time"

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

			got := buildCacheKey(tt.csp, tt.roleKey, tt.fqdn, tt.username)
			if got != tt.expected {
				t.Errorf("buildCacheKey(%q, %q, %q, %q) = %q, want %q",
					tt.csp, tt.roleKey, tt.fqdn, tt.username, got, tt.expected)
			}
		})
	}
}

func TestBuildCacheKey_AzureRoleIsShortened(t *testing.T) {
	t.Run("success_azure_role_definition_is_truncated_to_uuid", func(t *testing.T) {
		t.Parallel()

		longAzureRoleID := "/subscriptions/00000000-1111-2222-3333-444444444444/providers/Microsoft.Authorization/roleDefinitions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
		key := buildCacheKey("AZURE", longAzureRoleID, "mycluster.eastus.azmk8s.io", "alice@example.com")
		expected := "AZURE:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee:mycluster.eastus.azmk8s.io:alice@example.com"
		if key != expected {
			t.Errorf("expected key %q, got %q", expected, key)
		}
	})

	t.Run("success_aws_role_arn_is_kept_as_is", func(t *testing.T) {
		t.Parallel()

		awsRoleARN := "arn:aws:iam::123456789012:role/k8s_sca_test_role"
		key := buildCacheKey("AWS", awsRoleARN, "cluster.eks.amazonaws.com", "alice@example.com")
		expected := "AWS:arn:aws:iam::123456789012:role/k8s_sca_test_role:cluster.eks.amazonaws.com:alice@example.com"
		if key != expected {
			t.Errorf("expected key %q, got %q", expected, key)
		}
	})
}

func TestBuildCacheKey_DifferentUsernamesProduceDifferentKeys(t *testing.T) {
	t.Parallel()

	keyAlice := buildCacheKey("AWS", "arn:aws:iam::123:role/foo", "cluster.eks.amazonaws.com", "alice@example.com")
	keyBob := buildCacheKey("AWS", "arn:aws:iam::123:role/foo", "cluster.eks.amazonaws.com", "bob@example.com")
	if keyAlice == keyBob {
		t.Errorf("expected per-user cache keys to differ; both yielded %q", keyAlice)
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

		key := buildCacheKey("AWS", "arn:aws:iam::123:role/foo", "mycluster.eks.amazonaws.com", "alice@example.com")
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

func TestIsCachedAKSTokenStillValid(t *testing.T) {
	now := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)
	exp := now.Add(2 * time.Hour)

	valid, _ := isCachedAKSTokenStillValid(exp, now.Add(30*time.Minute))
	if !valid {
		t.Fatal("expected valid AKS token 90m before JWT exp")
	}

	valid, _ = isCachedAKSTokenStillValid(exp, now.Add(2*time.Hour-time.Minute))
	if valid {
		t.Fatal("expected invalid within JWT refresh buffer")
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

			result, _, _, err := LoadCachedElevateKeyringWithReason(tt.csp, tt.roleKey, tt.fqdn, tt.username, tt.ttl)

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
