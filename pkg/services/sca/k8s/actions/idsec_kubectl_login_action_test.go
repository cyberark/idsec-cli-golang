package actions

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/cyberark/idsec-cli-golang/pkg/actions/testutils"
	"github.com/cyberark/idsec-sdk-golang/pkg/config"
	"github.com/cyberark/idsec-sdk-golang/pkg/profiles"
	k8sservice "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s"
	k8smodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s/models"
)

func TestNewIdsecKubectlLoginAction(t *testing.T) {
	tests := []struct {
		name         string
		loader       *profiles.ProfileLoader
		validateFunc func(t *testing.T, action *IdsecKubectlLoginAction)
	}{
		{
			name:   "success_with_profile_loader",
			loader: testutils.NewMockProfileLoader().AsProfileLoader(),
			validateFunc: func(t *testing.T, action *IdsecKubectlLoginAction) {
				if action == nil {
					t.Fatal("expected non-nil action")
				}
				if action.profilesLoader == nil {
					t.Error("expected profilesLoader to be set")
				}
			},
		},
		{
			name:   "success_with_nil_loader",
			loader: nil,
			validateFunc: func(t *testing.T, action *IdsecKubectlLoginAction) {
				if action == nil {
					t.Fatal("expected non-nil action even with nil loader")
				}
				if action.profilesLoader != nil {
					t.Error("expected profilesLoader to remain nil")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			action := NewIdsecKubectlLoginAction(tt.loader)
			tt.validateFunc(t, action)
		})
	}
}

func TestIdsecKubectlLoginAction_DefineAction(t *testing.T) {
	tests := []struct {
		name         string
		setupRoot    func() *cobra.Command
		validateFunc func(t *testing.T, root *cobra.Command)
	}{
		{
			name: "success_adds_kubectl_login_alias",
			setupRoot: func() *cobra.Command {
				return &cobra.Command{Use: "idsec"}
			},
			validateFunc: func(t *testing.T, root *cobra.Command) {
				cmd, _, err := root.Find([]string{"kubectl-login"})
				if err != nil {
					t.Fatalf("unexpected error finding kubectl-login: %v", err)
				}
				if cmd == nil || cmd.Use != "kubectl-login" {
					t.Error("expected kubectl-login command to be added to root")
				}
			},
		},
		{
			name: "success_alias_is_hidden",
			setupRoot: func() *cobra.Command {
				return &cobra.Command{Use: "idsec"}
			},
			validateFunc: func(t *testing.T, root *cobra.Command) {
				cmd, _, _ := root.Find([]string{"kubectl-login"})
				if cmd == nil || cmd.Use != "kubectl-login" {
					t.Fatal("kubectl-login command not found")
				}
				if !cmd.Hidden {
					t.Error("expected kubectl-login to be hidden")
				}
			},
		},
		{
			name: "success_alias_has_expected_flags",
			setupRoot: func() *cobra.Command {
				return &cobra.Command{Use: "idsec"}
			},
			validateFunc: func(t *testing.T, root *cobra.Command) {
				cmd, _, _ := root.Find([]string{"kubectl-login"})
				if cmd == nil || cmd.Use != "kubectl-login" {
					t.Fatal("kubectl-login command not found")
				}

				expectedFlags := []string{
					"csp",
					"role-id",
					"fqdn",
					"organization-id",
					"namespace-id",
				}
				for _, flag := range expectedFlags {
					if cmd.Flags().Lookup(flag) == nil {
						t.Errorf("expected flag %q to be registered on kubectl-login", flag)
					}
				}
			},
		},
		{
			name: "success_alias_does_not_register_removed_flags",
			setupRoot: func() *cobra.Command {
				return &cobra.Command{Use: "idsec"}
			},
			validateFunc: func(t *testing.T, root *cobra.Command) {
				cmd, _, _ := root.Find([]string{"kubectl-login"})
				if cmd == nil || cmd.Use != "kubectl-login" {
					t.Fatal("kubectl-login command not found")
				}
				removedFlags := []string{
					"profile-name",
					"role-name",
					"roleId",
					"organizationId",
					"namespaceId",
					"target-id",
					"workspace-id",
					"tenant-id",
				}
				for _, flag := range removedFlags {
					if cmd.Flags().Lookup(flag) != nil {
						t.Errorf("flag %q must not be registered after simplification", flag)
					}
				}
			},
		},
		{
			name: "success_alias_silence_usage_is_set",
			setupRoot: func() *cobra.Command {
				return &cobra.Command{Use: "idsec"}
			},
			validateFunc: func(t *testing.T, root *cobra.Command) {
				cmd, _, _ := root.Find([]string{"kubectl-login"})
				if cmd == nil || cmd.Use != "kubectl-login" {
					t.Fatal("kubectl-login command not found")
				}
				if !cmd.SilenceUsage {
					t.Error("expected SilenceUsage to be true on kubectl-login alias")
				}
			},
		},
		{
			name: "success_overrides_elevate_run_when_subtree_exists",
			setupRoot: func() *cobra.Command {
				// Build a fake exec → sca → k8s → elevate subtree that mirrors the real CLI.
				root := &cobra.Command{Use: "idsec"}
				execCmd := &cobra.Command{Use: "exec"}
				scaCmd := &cobra.Command{Use: "sca"}
				k8sCmd := &cobra.Command{Use: "k8s"}
				elevateCmd := &cobra.Command{Use: "elevate"}
				// Register all elevate flags so flag reads in Run won't fail.
				addElevateFlags(elevateCmd)
				k8sCmd.AddCommand(elevateCmd)
				scaCmd.AddCommand(k8sCmd)
				execCmd.AddCommand(scaCmd)
				root.AddCommand(execCmd)
				return root
			},
			validateFunc: func(t *testing.T, root *cobra.Command) {
				elevate := findNestedCommand(root, "exec", "sca", "k8s", "elevate")
				if elevate == nil {
					t.Fatal("elevate command not found in tree after DefineAction")
				}
				if elevate.Run == nil {
					t.Error("expected Run to be overridden on elevate command")
				}
				if !elevate.SilenceUsage {
					t.Error("expected SilenceUsage to be true on elevate command after override")
				}
				if !elevate.Hidden {
					t.Error("expected elevate command to be hidden from help")
				}
			},
		},
		{
			name: "success_no_panic_when_elevate_subtree_missing",
			setupRoot: func() *cobra.Command {
				return &cobra.Command{Use: "idsec"}
			},
			validateFunc: func(t *testing.T, root *cobra.Command) {
				cmd, _, _ := root.Find([]string{"kubectl-login"})
				if cmd == nil || cmd.Use != "kubectl-login" {
					t.Error("expected kubectl-login to still be registered even without exec subtree")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			root := tt.setupRoot()
			action := NewIdsecKubectlLoginAction(testutils.NewMockProfileLoader().AsProfileLoader())
			action.DefineAction(root)

			tt.validateFunc(t, root)
		})
	}
}

func TestFindNestedCommand(t *testing.T) {
	tests := []struct {
		name      string
		buildTree func() *cobra.Command
		segments  []string
		expectNil bool
		expectUse string
	}{
		{
			name: "success_finds_top_level_command",
			buildTree: func() *cobra.Command {
				root := &cobra.Command{Use: "root"}
				root.AddCommand(&cobra.Command{Use: "exec"})
				return root
			},
			segments:  []string{"exec"},
			expectNil: false,
			expectUse: "exec",
		},
		{
			name: "success_finds_nested_command",
			buildTree: func() *cobra.Command {
				root := &cobra.Command{Use: "root"}
				execCmd := &cobra.Command{Use: "exec"}
				scaCmd := &cobra.Command{Use: "sca"}
				k8sCmd := &cobra.Command{Use: "k8s"}
				elevateCmd := &cobra.Command{Use: "elevate"}
				k8sCmd.AddCommand(elevateCmd)
				scaCmd.AddCommand(k8sCmd)
				execCmd.AddCommand(scaCmd)
				root.AddCommand(execCmd)
				return root
			},
			segments:  []string{"exec", "sca", "k8s", "elevate"},
			expectNil: false,
			expectUse: "elevate",
		},
		{
			name: "success_returns_nil_when_first_segment_missing",
			buildTree: func() *cobra.Command {
				root := &cobra.Command{Use: "root"}
				root.AddCommand(&cobra.Command{Use: "exec"})
				return root
			},
			segments:  []string{"nonexistent"},
			expectNil: true,
		},
		{
			name: "success_returns_nil_when_deep_segment_missing",
			buildTree: func() *cobra.Command {
				root := &cobra.Command{Use: "root"}
				execCmd := &cobra.Command{Use: "exec"}
				root.AddCommand(execCmd)
				return root
			},
			segments:  []string{"exec", "sca"},
			expectNil: true,
		},
		{
			name: "success_returns_root_for_empty_names",
			buildTree: func() *cobra.Command {
				return &cobra.Command{Use: "root"}
			},
			segments:  []string{},
			expectNil: false,
			expectUse: "root",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			root := tt.buildTree()
			result := findNestedCommand(root, tt.segments...)

			if tt.expectNil {
				if result != nil {
					t.Errorf("expected nil, got command with Use=%q", result.Use)
				}
				return
			}

			if result == nil {
				t.Fatal("expected non-nil command, got nil")
			}
			if result.Use != tt.expectUse {
				t.Errorf("expected Use=%q, got %q", tt.expectUse, result.Use)
			}
		})
	}
}

func TestFindMatchingEvalResult(t *testing.T) {
	fqdn := "cluster.example.com"
	otherFQDN := "other.example.com"
	results := []k8smodels.IdsecSCAK8sEvaluateResult{
		{
			Role:   k8smodels.IdsecSCAk8sListClustersRole{ID: "role-1"},
			Target: k8smodels.IdsecSCAk8sListClustersTarget{FQDN: &fqdn},
		},
		{
			Role:   k8smodels.IdsecSCAk8sListClustersRole{ID: "role-2"},
			Target: k8smodels.IdsecSCAk8sListClustersTarget{FQDN: &fqdn},
		},
		{
			Role:   k8smodels.IdsecSCAk8sListClustersRole{ID: "role-3"},
			Target: k8smodels.IdsecSCAk8sListClustersTarget{FQDN: &otherFQDN},
		},
	}

	tests := []struct {
		name     string
		fqdn     string
		roleID   string
		wantRole string
		wantNil  bool
	}{
		{
			name:     "matches_fqdn_and_role_id",
			fqdn:     fqdn,
			roleID:   "role-2",
			wantRole: "role-2",
		},
		{
			name:    "returns_nil_when_role_id_empty",
			fqdn:    fqdn,
			wantNil: true,
		},
		{
			name:    "returns_nil_when_fqdn_empty",
			roleID:  "role-3",
			wantNil: true,
		},
		{
			name:    "returns_nil_when_role_id_does_not_match_fqdn",
			fqdn:    fqdn,
			roleID:  "role-3",
			wantNil: true,
		},
		{
			name:    "returns_nil_when_no_selectors_provided",
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := findMatchingEvalResult(results, tt.fqdn, tt.roleID)
			if tt.wantNil {
				if got != nil {
					t.Fatalf("expected nil, got role %q", got.Role.ID)
				}
				return
			}
			if got == nil {
				t.Fatal("expected result, got nil")
			}
			if got.Role.ID != tt.wantRole {
				t.Errorf("expected role %q, got %q", tt.wantRole, got.Role.ID)
			}
		})
	}
}

func TestAddElevateFlags(t *testing.T) {
	tests := []struct {
		name         string
		validateFunc func(t *testing.T, cmd *cobra.Command)
	}{
		{
			name: "success_all_flags_registered",
			validateFunc: func(t *testing.T, cmd *cobra.Command) {
				expectedFlags := []string{
					"csp",
					"role-id",
					"fqdn",
					"organization-id",
					"namespace-id",
				}
				for _, flag := range expectedFlags {
					if cmd.Flags().Lookup(flag) == nil {
						t.Errorf("expected flag %q to be registered", flag)
					}
				}
			},
		},
		{
			name: "success_profile_name_flag_is_not_registered",
			validateFunc: func(t *testing.T, cmd *cobra.Command) {
				if flag := cmd.Flags().Lookup("profile-name"); flag != nil {
					t.Errorf("profile-name flag must not be registered on kubectl-login alias")
				}
			},
		},
		{
			name: "success_all_flags_have_empty_defaults",
			validateFunc: func(t *testing.T, cmd *cobra.Command) {
				flagsWithEmptyDefault := []string{
					"csp",
					"role-id",
					"fqdn",
					"organization-id",
					"namespace-id",
				}
				for _, name := range flagsWithEmptyDefault {
					flag := cmd.Flags().Lookup(name)
					if flag == nil {
						t.Errorf("flag %q not found", name)
						continue
					}
					if flag.DefValue != "" {
						t.Errorf("expected flag %q default to be empty, got %q", name, flag.DefValue)
					}
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cmd := &cobra.Command{Use: "kubectl-login"}
			addElevateFlags(cmd)

			tt.validateFunc(t, cmd)
		})
	}
}

func TestKubectlLoginDiagnosticsEnabled(t *testing.T) {
	tests := []struct {
		name string
		env  string
		want bool
	}{
		{name: "env_IDSEC_VERBOSE_true", env: "true", want: true},
		{name: "env_IDSEC_VERBOSE_1", env: "1", want: true},
		{name: "disabled_by_default", env: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.env == "" {
				t.Setenv("IDSEC_VERBOSE", "")
			} else {
				t.Setenv("IDSEC_VERBOSE", tt.env)
			}
			if got := kubectlLoginDiagnosticsEnabled(); got != tt.want {
				t.Errorf("kubectlLoginDiagnosticsEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKubectlLoginVerbose_WritesToStderrOnly(t *testing.T) {
	t.Setenv("IDSEC_VERBOSE", "true")

	stderr := captureKubectlLoginStderr(t, func() {
		kubectlLoginVerbose("diagnostic line %d", 42)
	})
	if !bytes.Contains(stderr, []byte("kubectl-login | ")) ||
		!bytes.Contains(stderr, []byte(" | DEBUG | diagnostic line 42")) {
		t.Fatalf("expected verbose line on stderr, got: %q", stderr)
	}
}

func TestKubectlLoginLogLevelInfoSuppressesDebug(t *testing.T) {
	t.Setenv("IDSEC_VERBOSE", "true")
	t.Setenv(k8sservice.KubectlLoginLogLevelEnvVar, "info")

	stderr := captureKubectlLoginStderr(t, func() {
		kubectlLoginInfo("info line")
		kubectlLoginVerbose("debug line")
	})
	logs := string(stderr)
	if !strings.Contains(logs, " | INFO | info line") {
		t.Fatalf("expected INFO line, got: %q", logs)
	}
	if strings.Contains(logs, "debug line") {
		t.Fatalf("did not expect DEBUG line at info level, got: %q", logs)
	}
}

func TestLogProxyExecCredential_DoesNotDumpCredentialJSON(t *testing.T) {
	t.Setenv("IDSEC_VERBOSE", "true")

	cred := &k8smodels.IdsecSCAK8sExecCredential{
		APIVersion: "client.authentication.k8s.io/v1beta1",
		Kind:       "ExecCredential",
		Status: k8smodels.IdsecSCAK8sExecCredentialStatus{
			ClientCertificateData: "CERTDATA",
			ClientKeyData:         "KEYDATA",
		},
	}

	stderr := captureKubectlLoginStderr(t, func() {
		logProxyExecCredential(cred, "test")
	})
	logs := string(stderr)
	if !strings.Contains(logs, "kubectl-login | ") ||
		!strings.Contains(logs, " | INFO | proxy ExecCredential (test):") {
		t.Fatalf("expected safe ExecCredential summary, got: %q", logs)
	}
	for _, forbidden := range []string{"ExecCredential JSON", "CERTDATA", "KEYDATA"} {
		if strings.Contains(logs, forbidden) {
			t.Fatalf("did not expect %q in verbose logs: %q", forbidden, logs)
		}
	}
}

func TestKubectlLoginLogLevelIsolationSuppressesSDKStdoutLogging(t *testing.T) {
	t.Setenv(config.IdsecLogLevelEnvVar, "info")
	originalKubectlLevel, hadKubectlLevel := os.LookupEnv(k8sservice.KubectlLoginLogLevelEnvVar)
	_ = os.Unsetenv(k8sservice.KubectlLoginLogLevelEnvVar)
	t.Cleanup(func() {
		if hadKubectlLevel {
			_ = os.Setenv(k8sservice.KubectlLoginLogLevelEnvVar, originalKubectlLevel)
		} else {
			_ = os.Unsetenv(k8sservice.KubectlLoginLogLevelEnvVar)
		}
	})

	restore := setupKubectlLoginLogging()

	if got := os.Getenv(config.IdsecLogLevelEnvVar); got != "CRITICAL" {
		t.Fatalf("expected SDK %s to be CRITICAL during kubectl-login, got %q", config.IdsecLogLevelEnvVar, got)
	}
	if got := os.Getenv(k8sservice.KubectlLoginLogLevelEnvVar); got != "info" {
		t.Fatalf("expected kubectl-login log level inherited from IDSEC_LOG_LEVEL, got %q", got)
	}
	if got := k8sservice.KubectlLoginEffectiveLogLevel(); got != k8sservice.KubectlLoginLogLevelInfo {
		t.Fatalf("expected effective kubectl-login level info from IDSEC_LOG_LEVEL, got %v", got)
	}

	restore()
	if got := os.Getenv(config.IdsecLogLevelEnvVar); got != "info" {
		t.Fatalf("expected original %s restored, got %q", config.IdsecLogLevelEnvVar, got)
	}
	if got := os.Getenv(k8sservice.KubectlLoginLogLevelEnvVar); got != "" {
		t.Fatalf("expected private kubectl-login log level restored to empty, got %q", got)
	}
}

func TestKubectlLoginLogLevelIsolationAlwaysSilencesSDKStdoutLogging(t *testing.T) {
	_ = os.Unsetenv(config.IdsecLogLevelEnvVar)
	originalKubectlLevel, hadKubectlLevel := os.LookupEnv(k8sservice.KubectlLoginLogLevelEnvVar)
	_ = os.Unsetenv(k8sservice.KubectlLoginLogLevelEnvVar)
	t.Cleanup(func() {
		_ = os.Unsetenv(config.IdsecLogLevelEnvVar)
		if hadKubectlLevel {
			_ = os.Setenv(k8sservice.KubectlLoginLogLevelEnvVar, originalKubectlLevel)
		} else {
			_ = os.Unsetenv(k8sservice.KubectlLoginLogLevelEnvVar)
		}
	})

	restore := setupKubectlLoginLogging()

	if got := os.Getenv(config.IdsecLogLevelEnvVar); got != "CRITICAL" {
		t.Fatalf("expected SDK %s to be CRITICAL even when unset before kubectl-login, got %q", config.IdsecLogLevelEnvVar, got)
	}
	if got := os.Getenv(k8sservice.KubectlLoginLogLevelEnvVar); got != "" {
		t.Fatalf("expected kubectl-login private log level unchanged when IDSEC_LOG_LEVEL unset, got %q", got)
	}

	restore()
	if got, ok := os.LookupEnv(config.IdsecLogLevelEnvVar); ok {
		t.Fatalf("expected %s restored to unset, got %q", config.IdsecLogLevelEnvVar, got)
	}
}

func requireNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestServeFromUnifiedCache_EmptySessionEarlyReturns asserts the helper
// short-circuits before any keyring I/O when sessionID is empty (the cache
// is keyed on internal_session_id; an empty value means "no cache").
func TestServeFromUnifiedCache_EmptySessionEarlyReturns(t *testing.T) {
	t.Setenv("IDSEC_VERBOSE", "true")
	a := &IdsecKubectlLoginAction{}
	cmd := &cobra.Command{Use: "kubectl-login"}

	stderr := captureKubectlLoginStderr(t, func() {
		req := buildKubectlLoginRequest("AWS", "role-id", "fqdn.example.com", "", "", "", kubectlLoginSession{
			ispUsername: "alice@example.com",
		})
		if served := a.serveFromUnifiedCache(cmd, req); served {
			t.Fatalf("expected served=false for empty sessionID")
		}
	})
	if bytes.Contains(stderr, []byte("unified cache lookup")) {
		t.Errorf("expected no cache-lookup verbose line for empty sessionID; got: %q", stderr)
	}
}

// TestSaveUnifiedExecCredential_EmptySessionNoOp asserts the helper is a
// no-op (no keyring write, no warning) when the session id cannot be
// extracted — matching the lookup-side guard in serveFromUnifiedCache.
func TestSaveUnifiedExecCredential_EmptySessionNoOp(t *testing.T) {
	t.Setenv("IDSEC_VERBOSE", "true")
	a := &IdsecKubectlLoginAction{}
	cmd := &cobra.Command{Use: "kubectl-login"}
	cred := &k8smodels.IdsecSCAK8sExecCredential{
		APIVersion: "client.authentication.k8s.io/v1beta1",
		Kind:       "ExecCredential",
		Status: k8smodels.IdsecSCAK8sExecCredentialStatus{
			Token:               "tok",
			ExpirationTimestamp: "2099-01-01T00:00:00Z",
		},
	}

	stderr := captureKubectlLoginStderr(t, func() {
		req := buildKubectlLoginRequest("AWS", "role-id", "fqdn.example.com", "", "", "", kubectlLoginSession{
			ispUsername: "alice@example.com",
		})
		a.saveUnifiedExecCredential(cmd, req, "direct", cred)
	})
	if bytes.Contains(stderr, []byte("unified cache saved")) {
		t.Errorf("expected no save attempt for empty sessionID; got: %q", stderr)
	}
	if bytes.Contains(stderr, []byte("unified cache save failed")) {
		t.Errorf("expected no save error for empty sessionID; got: %q", stderr)
	}
}

// TestSaveUnifiedExecCredential_NoExpirationSkipsSave asserts that an
// ExecCredential without status.expirationTimestamp is never persisted: the
// cache TTL contract requires an authoritative expiry per architect review.
func TestSaveUnifiedExecCredential_NoExpirationSkipsSave(t *testing.T) {
	t.Setenv("IDSEC_VERBOSE", "true")
	a := &IdsecKubectlLoginAction{}
	cmd := &cobra.Command{Use: "kubectl-login"}
	cred := &k8smodels.IdsecSCAK8sExecCredential{
		APIVersion: "client.authentication.k8s.io/v1beta1",
		Kind:       "ExecCredential",
		Status: k8smodels.IdsecSCAK8sExecCredentialStatus{
			Token: "tok",
		},
	}

	stderr := captureKubectlLoginStderr(t, func() {
		req := buildKubectlLoginRequest("AWS", "role-id", "fqdn.example.com", "", "", "", kubectlLoginSession{
			ispUsername: "alice@example.com",
			sessionID:   "sid-not-empty",
		})
		a.saveUnifiedExecCredential(cmd, req, "direct", cred)
	})
	if !strings.Contains(string(stderr), "skipping unified cache save: ExecCredential has no expirationTimestamp") {
		t.Errorf("expected verbose skip line about missing expirationTimestamp; got: %q", stderr)
	}
	if bytes.Contains(stderr, []byte("unified cache saved")) {
		t.Errorf("expected no save attempt when expirationTimestamp is missing; got: %q", stderr)
	}
}

func captureKubectlLoginStderr(t *testing.T, fn func()) []byte {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	fn()
	_ = w.Close()
	os.Stderr = old
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	_ = r.Close()
	return buf.Bytes()
}
