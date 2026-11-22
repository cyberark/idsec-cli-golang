package actions

import (
	"testing"

	"github.com/cyberark/idsec-cli-golang/pkg/agentmode"
	authcommon "github.com/cyberark/idsec-sdk-golang/pkg/auth/common"
)

// agentmode is a leaf package and can't import the SDK, so the SDK reasons it
// mirrors are pinned here.
func TestAgentmodeCodesMatchSDKReasons(t *testing.T) {
	tests := []struct {
		name   string
		code   agentmode.Code
		reason authcommon.Reason
	}{
		{"success_mfa_required", agentmode.CodeMFARequired, authcommon.ReasonMFARequired},
		{"success_endpoint_unreachable", agentmode.CodeEndpointUnreachable, authcommon.ReasonEndpointUnreachable},
		{"success_keyring_failure", agentmode.CodeKeyringFailure, authcommon.ReasonKeyringFailure},
		{"success_certificate_error", agentmode.CodeCertificateError, authcommon.ReasonCertificateError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.code != agentmode.Code(tt.reason) {
				t.Errorf("agentmode code %q != SDK reason %q", tt.code, tt.reason)
			}
		})
	}
}

func TestLoginReasonsMatchAgentmodeCodes(t *testing.T) {
	tests := []struct {
		name      string
		reason    string
		code      agentmode.Code
		published string
	}{
		{"success_profile_not_found", loginReasonProfileNotFound, agentmode.CodeProfileNotFound, "PROFILE_NOT_FOUND"},
		{"success_username_required", loginReasonUsernameRequired, agentmode.CodeUsernameRequired, "USERNAME_REQUIRED"},
		{"success_secret_required", loginReasonSecretRequired, agentmode.CodeSecretRequired, "SECRET_REQUIRED"},
		{"success_config_error", loginReasonConfigError, agentmode.CodeConfigError, "CONFIG_ERROR"},
		{"success_auth_failed", loginReasonAuthFailed, agentmode.CodeAuthFailed, "AUTH_FAILED"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.reason != string(tt.code) {
				t.Errorf("login reason %q != agentmode code %q", tt.reason, tt.code)
			}
			if tt.reason != tt.published {
				t.Errorf("login reason %q != published value %q (docs/commands/login.md)", tt.reason, tt.published)
			}
		})
	}
}
