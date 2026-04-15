package actions

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/cyberark/idsec-cli-golang/pkg/actions/testutils"
	"github.com/cyberark/idsec-sdk-golang/pkg/profiles"
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
			name: "success_alias_has_all_flags",
			setupRoot: func() *cobra.Command {
				return &cobra.Command{Use: "idsec"}
			},
			validateFunc: func(t *testing.T, root *cobra.Command) {
				cmd, _, _ := root.Find([]string{"kubectl-login"})
				if cmd == nil || cmd.Use != "kubectl-login" {
					t.Fatal("kubectl-login command not found")
				}

				expectedFlags := []string{
					"profile-name",
					"csp",
					"role-id",
					"role-name",
					"fqdn",
					"target-id",
					"workspace-id",
					"tenant-id",
				}
				for _, flag := range expectedFlags {
					if cmd.Flags().Lookup(flag) == nil {
						t.Errorf("expected flag %q to be registered on kubectl-login", flag)
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
			},
		},
		{
			name: "success_no_panic_when_elevate_subtree_missing",
			setupRoot: func() *cobra.Command {
				return &cobra.Command{Use: "idsec"}
			},
			validateFunc: func(t *testing.T, root *cobra.Command) {
				// Only the kubectl-login alias should be present; no elevate override.
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

func TestAddElevateFlags(t *testing.T) {
	tests := []struct {
		name         string
		validateFunc func(t *testing.T, cmd *cobra.Command)
	}{
		{
			name: "success_all_flags_registered",
			validateFunc: func(t *testing.T, cmd *cobra.Command) {
				expectedFlags := []string{
					"profile-name",
					"csp",
					"role-id",
					"role-name",
					"fqdn",
					"target-id",
					"workspace-id",
					"tenant-id",
				}
				for _, flag := range expectedFlags {
					if cmd.Flags().Lookup(flag) == nil {
						t.Errorf("expected flag %q to be registered", flag)
					}
				}
			},
		},
		{
			name: "success_profile_name_has_default",
			validateFunc: func(t *testing.T, cmd *cobra.Command) {
				flag := cmd.Flags().Lookup("profile-name")
				if flag == nil {
					t.Fatal("profile-name flag not found")
				}
				expected := profiles.DefaultProfileName()
				if flag.DefValue != expected {
					t.Errorf("expected profile-name default %q, got %q", expected, flag.DefValue)
				}
			},
		},
		{
			name: "success_optional_flags_have_empty_defaults",
			validateFunc: func(t *testing.T, cmd *cobra.Command) {
				optionalFlags := []string{
					"csp",
					"role-id",
					"role-name",
					"fqdn",
					"target-id",
					"workspace-id",
					"tenant-id",
				}
				for _, name := range optionalFlags {
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
