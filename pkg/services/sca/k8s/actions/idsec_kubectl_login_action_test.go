package actions

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/cyberark/idsec-cli-golang/pkg/actions/testutils"
	"github.com/cyberark/idsec-sdk-golang/pkg/profiles"
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
					"verbose",
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
					"verbose",
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

func TestKubectlLoginVerboseEnabled(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T) (*cobra.Command, func())
		want  bool
	}{
		{
			name: "env_IDSEC_VERBOSE_true",
			setup: func(t *testing.T) (*cobra.Command, func()) {
				t.Setenv("IDSEC_VERBOSE", "true")
				return &cobra.Command{Use: "kubectl-login"}, func() {}
			},
			want: true,
		},
		{
			name: "local_verbose_flag",
			setup: func(t *testing.T) (*cobra.Command, func()) {
				cmd := &cobra.Command{Use: "kubectl-login"}
				cmd.Flags().Bool("verbose", false, "")
				requireNoError(t, cmd.ParseFlags([]string{"--verbose"}))
				return cmd, func() {}
			},
			want: true,
		},
		{
			name: "exec_persistent_verbose_flag",
			setup: func(t *testing.T) (*cobra.Command, func()) {
				exec := &cobra.Command{Use: "exec"}
				exec.PersistentFlags().Bool("verbose", false, "")
				requireNoError(t, exec.ParseFlags([]string{"--verbose"}))
				elevate := &cobra.Command{Use: "elevate"}
				exec.AddCommand(elevate)
				return elevate, func() {}
			},
			want: true,
		},
		{
			name: "disabled_by_default",
			setup: func(t *testing.T) (*cobra.Command, func()) {
				t.Setenv("IDSEC_VERBOSE", "")
				return &cobra.Command{Use: "kubectl-login"}, func() {}
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, cleanup := tt.setup(t)
			defer cleanup()
			if got := kubectlLoginVerboseEnabled(cmd); got != tt.want {
				t.Errorf("kubectlLoginVerboseEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKubectlLoginVerbose_WritesToStderrOnly(t *testing.T) {
	t.Setenv("IDSEC_VERBOSE", "true")

	cmd := &cobra.Command{Use: "kubectl-login"}
	stderr := captureKubectlLoginStderr(t, func() {
		kubectlLoginVerbose(cmd, "diagnostic line %d", 42)
	})
	if !bytes.Contains(stderr, []byte("[kubectl-login] diagnostic line 42")) {
		t.Fatalf("expected verbose line on stderr, got: %q", stderr)
	}
}

func requireNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
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
