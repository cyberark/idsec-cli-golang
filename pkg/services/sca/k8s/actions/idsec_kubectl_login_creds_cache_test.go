package actions

import (
	"strings"
	"testing"
	"time"
)

func TestBuildCacheKey(t *testing.T) {
	tests := []struct {
		name     string
		csp      string
		roleKey  string
		fqdn     string
		expected string
	}{
		{
			name:     "success_formats_correctly",
			csp:      "AWS",
			roleKey:  "arn:aws:iam::123456789012:role/k8s-role",
			fqdn:     "745445889F087548523CF96B3D365FF0.gr7.us-east-1.eks.amazonaws.com",
			expected: "AWS:arn:aws:iam::123456789012:role/k8s-role:745445889F087548523CF96B3D365FF0.gr7.us-east-1.eks.amazonaws.com",
		},
		{
			name:     "success_uppercases_csp",
			csp:      "azure",
			roleKey:  "my-role",
			fqdn:     "mycluster.eastus.azmk8s.io",
			expected: "AZURE:my-role:mycluster.eastus.azmk8s.io",
		},
		{
			name:     "success_mixed_case_csp_is_uppercased",
			csp:      "Aws",
			roleKey:  "role-name",
			fqdn:     "cluster.example.com",
			expected: "AWS:role-name:cluster.example.com",
		},
		{
			name:     "success_empty_fqdn_produces_trailing_separator",
			csp:      "AWS",
			roleKey:  "arn:aws:iam::123:role/foo",
			fqdn:     "",
			expected: "AWS:arn:aws:iam::123:role/foo:",
		},
		{
			name:     "success_empty_role_key_produces_consecutive_separators",
			csp:      "AWS",
			roleKey:  "",
			fqdn:     "cluster.eks.amazonaws.com",
			expected: "AWS::cluster.eks.amazonaws.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := buildCacheKey(tt.csp, tt.roleKey, tt.fqdn)
			if got != tt.expected {
				t.Errorf("buildCacheKey(%q, %q, %q) = %q, want %q",
					tt.csp, tt.roleKey, tt.fqdn, got, tt.expected)
			}
		})
	}
}

func TestBuildCacheKey_Format(t *testing.T) {
	t.Run("success_key_contains_three_colon_separated_parts", func(t *testing.T) {
		t.Parallel()

		key := buildCacheKey("AWS", "arn:aws:iam::123:role/foo", "mycluster.eks.amazonaws.com")
		// The key must start with the uppercased CSP.
		if !strings.HasPrefix(key, "AWS:") {
			t.Errorf("expected key to start with 'AWS:', got %q", key)
		}
		// The key must end with the fqdn.
		if !strings.HasSuffix(key, ":mycluster.eks.amazonaws.com") {
			t.Errorf("expected key to end with ':mycluster.eks.amazonaws.com', got %q", key)
		}
		// The role ARN portion must be present.
		if !strings.Contains(key, "arn:aws:iam::123:role/foo") {
			t.Errorf("expected key to contain role ARN, got %q", key)
		}
	})
}

func TestLoadCachedCreds(t *testing.T) {
	tests := []struct {
		name        string
		csp         string
		roleKey     string
		fqdn        string
		ttl         time.Duration
		expectNil   bool
		expectError bool
	}{
		{
			name:        "success_ttl_zero_returns_nil_without_keyring_access",
			csp:         "AWS",
			roleKey:     "arn:aws:iam::123:role/k8s-role",
			fqdn:        "745445889F087548523CF96B3D365FF0.gr7.us-east-1.eks.amazonaws.com",
			ttl:         0,
			expectNil:   true,
			expectError: false,
		},
		{
			name:        "success_ttl_zero_for_azure_stub_returns_nil",
			csp:         "AZURE",
			roleKey:     "azure-role",
			fqdn:        "mycluster.eastus.azmk8s.io",
			ttl:         0,
			expectNil:   true,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := LoadCachedCreds(tt.csp, tt.roleKey, tt.fqdn, tt.ttl)

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
