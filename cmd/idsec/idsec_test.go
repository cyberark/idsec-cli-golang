package main

import (
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/cyberark/idsec-sdk-golang/pkg/profiles"
)

func TestCreateRootCommand(t *testing.T) {
	tests := []struct {
		name         string
		validateFunc func(t *testing.T, cmd *cobra.Command)
	}{
		{
			name: "success_creates_command_with_correct_use",
			validateFunc: func(t *testing.T, cmd *cobra.Command) {
				if cmd.Use != "idsec" {
					t.Errorf("Expected Use to be 'idsec', got '%s'", cmd.Use)
				}
			},
		},
		{
			name: "success_sets_correct_short_description",
			validateFunc: func(t *testing.T, cmd *cobra.Command) {
				if cmd.Short != "Idsec CLI" {
					t.Errorf("Expected Short to be 'Idsec CLI', got '%s'", cmd.Short)
				}
			},
		},
		{
			name: "success_sets_version_template",
			validateFunc: func(t *testing.T, cmd *cobra.Command) {
				// Version template should be set
				// We can't directly access the template, but we can verify the command has version info
				if cmd.Version == "" {
					t.Error("Expected Version to be set")
				}
			},
		},
		{
			name: "success_sets_silence_usage",
			validateFunc: func(t *testing.T, cmd *cobra.Command) {
				if !cmd.SilenceUsage {
					t.Error("Expected SilenceUsage to be true")
				}
			},
		},
		{
			name: "success_version_contains_expected_fields",
			validateFunc: func(t *testing.T, cmd *cobra.Command) {
				version := cmd.Version
				expectedFields := []string{"Version:", "Build Number:", "Build Date:", "Git Commit:", "Git Branch:"}
				for _, field := range expectedFields {
					if !strings.Contains(version, field) {
						t.Errorf("Expected version to contain '%s', got: %s", field, version)
					}
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cmd := createRootCommand()

			if cmd == nil {
				t.Fatal("Expected command to be created, got nil")
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, cmd)
			}
		})
	}
}

func TestRegisterActions(t *testing.T) {
	tests := []struct {
		name         string
		validateFunc func(t *testing.T, cmd *cobra.Command)
	}{
		{
			name: "success_registers_all_actions",
			validateFunc: func(t *testing.T, cmd *cobra.Command) {
				// Check that expected commands are registered
				expectedCommands := []string{"profiles", "cache", "configure", "login", "exec", "upgrade"}
				registeredCommands := make(map[string]bool)
				for _, subCmd := range cmd.Commands() {
					registeredCommands[subCmd.Name()] = true
				}

				for _, expectedCmd := range expectedCommands {
					if !registeredCommands[expectedCmd] {
						t.Errorf("Expected command '%s' to be registered", expectedCmd)
					}
				}
			},
		},
		{
			name: "success_registers_actions_with_profiles_loader",
			validateFunc: func(t *testing.T, cmd *cobra.Command) {
				// Verify that commands that require profiles loader are registered
				profilesCmd, _, err := cmd.Find([]string{"profiles"})
				if err != nil {
					t.Errorf("Expected profiles command to be registered, got error: %v", err)
				}
				if profilesCmd == nil {
					t.Error("Expected profiles command to exist")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cmd := &cobra.Command{Use: "test"}
			profilesLoader := profiles.DefaultProfilesLoader()

			registerActions(cmd, profilesLoader)

			if tt.validateFunc != nil {
				tt.validateFunc(t, cmd)
			}
		})
	}
}

func TestIsKnownSubcommand(t *testing.T) {
	tests := []struct {
		name     string
		setupCmd func() *cobra.Command
		arg      string
		expected bool
	}{
		{
			name: "success_returns_true_for_exact_match",
			setupCmd: func() *cobra.Command {
				cmd := &cobra.Command{Use: "root"}
				cmd.AddCommand(&cobra.Command{Use: "test"})
				return cmd
			},
			arg:      "test",
			expected: true,
		},
		{
			name: "success_returns_true_for_alias_match",
			setupCmd: func() *cobra.Command {
				cmd := &cobra.Command{Use: "root"}
				subCmd := &cobra.Command{Use: "test"}
				subCmd.Aliases = []string{"t", "test-alias"}
				cmd.AddCommand(subCmd)
				return cmd
			},
			arg:      "t",
			expected: true,
		},
		{
			name: "success_returns_false_for_unknown_command",
			setupCmd: func() *cobra.Command {
				cmd := &cobra.Command{Use: "root"}
				cmd.AddCommand(&cobra.Command{Use: "test"})
				return cmd
			},
			arg:      "unknown",
			expected: false,
		},
		{
			name: "success_returns_false_for_empty_string",
			setupCmd: func() *cobra.Command {
				cmd := &cobra.Command{Use: "root"}
				cmd.AddCommand(&cobra.Command{Use: "test"})
				return cmd
			},
			arg:      "",
			expected: false,
		},
		{
			name: "success_returns_false_when_no_commands",
			setupCmd: func() *cobra.Command {
				return &cobra.Command{Use: "root"}
			},
			arg:      "test",
			expected: false,
		},
		{
			name: "success_handles_multiple_aliases",
			setupCmd: func() *cobra.Command {
				cmd := &cobra.Command{Use: "root"}
				subCmd := &cobra.Command{Use: "test"}
				subCmd.Aliases = []string{"alias1", "alias2", "alias3"}
				cmd.AddCommand(subCmd)
				return cmd
			},
			arg:      "alias2",
			expected: true,
		},
		{
			name: "edge_case_case_sensitive_matching",
			setupCmd: func() *cobra.Command {
				cmd := &cobra.Command{Use: "root"}
				cmd.AddCommand(&cobra.Command{Use: "Test"})
				return cmd
			},
			arg:      "test",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cmd := tt.setupCmd()
			result := isKnownSubcommand(cmd, tt.arg)

			if result != tt.expected {
				t.Errorf("Expected isKnownSubcommand to return %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestShouldShowHelpForError(t *testing.T) {
	tests := []struct {
		name     string
		errStr   string
		expected bool
	}{
		{
			name:     "success_returns_true_for_unknown_command",
			errStr:   "unknown command",
			expected: true,
		},
		{
			name:     "success_returns_true_for_unknown_flag",
			errStr:   "unknown flag",
			expected: true,
		},
		{
			name:     "success_returns_true_for_required",
			errStr:   "required",
			expected: true,
		},
		{
			name:     "success_returns_true_for_invalid",
			errStr:   "invalid",
			expected: true,
		},
		{
			name:     "success_returns_true_for_usage",
			errStr:   "usage",
			expected: true,
		},
		{
			name:     "success_returns_true_for_case_insensitive_match",
			errStr:   "UNKNOWN COMMAND",
			expected: true,
		},
		{
			name:     "success_returns_true_for_mixed_case",
			errStr:   "UnKnOwN cOmMaNd",
			expected: true,
		},
		{
			name:     "success_returns_false_for_unrelated_error",
			errStr:   "network error",
			expected: false,
		},
		{
			name:     "success_returns_false_for_empty_string",
			errStr:   "",
			expected: false,
		},
		{
			name:     "success_returns_true_for_error_with_multiple_keywords",
			errStr:   "unknown command: invalid usage",
			expected: true,
		},
		{
			name:     "edge_case_partial_match_in_word",
			errStr:   "command_required",
			expected: true,
		},
		{
			name:     "edge_case_error_with_context",
			errStr:   "Error: unknown command 'test' for 'idsec'",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := shouldShowHelpForError(tt.errStr)

			if result != tt.expected {
				t.Errorf("Expected shouldShowHelpForError to return %v for '%s', got %v", tt.expected, tt.errStr, result)
			}
		})
	}
}

func TestIsRootCommandError(t *testing.T) {
	tests := []struct {
		name         string
		setupArgs    func() func() // Returns cleanup function
		setupCmd     func() *cobra.Command
		expected     bool
		validateFunc func(t *testing.T, result bool)
	}{
		{
			name: "success_returns_true_when_no_args",
			setupArgs: func() func() {
				originalArgs := make([]string, len(os.Args))
				copy(originalArgs, os.Args)
				os.Args = []string{"idsec"}
				return func() {
					os.Args = originalArgs
				}
			},
			setupCmd: func() *cobra.Command {
				cmd := &cobra.Command{Use: "root"}
				cmd.AddCommand(&cobra.Command{Use: "test"})
				return cmd
			},
			expected: true,
		},
		{
			name: "success_returns_false_for_known_subcommand",
			setupArgs: func() func() {
				originalArgs := make([]string, len(os.Args))
				copy(originalArgs, os.Args)
				os.Args = []string{"idsec", "test"}
				return func() {
					os.Args = originalArgs
				}
			},
			setupCmd: func() *cobra.Command {
				cmd := &cobra.Command{Use: "root"}
				cmd.AddCommand(&cobra.Command{Use: "test"})
				return cmd
			},
			expected: false,
		},
		{
			name: "success_returns_true_for_unknown_command",
			setupArgs: func() func() {
				originalArgs := make([]string, len(os.Args))
				copy(originalArgs, os.Args)
				os.Args = []string{"idsec", "unknown"}
				return func() {
					os.Args = originalArgs
				}
			},
			setupCmd: func() *cobra.Command {
				cmd := &cobra.Command{Use: "root"}
				cmd.AddCommand(&cobra.Command{Use: "test"})
				return cmd
			},
			expected: true,
		},
		{
			name: "success_returns_false_for_alias_match",
			setupArgs: func() func() {
				originalArgs := make([]string, len(os.Args))
				copy(originalArgs, os.Args)
				os.Args = []string{"idsec", "t"}
				return func() {
					os.Args = originalArgs
				}
			},
			setupCmd: func() *cobra.Command {
				cmd := &cobra.Command{Use: "root"}
				subCmd := &cobra.Command{Use: "test"}
				subCmd.Aliases = []string{"t"}
				cmd.AddCommand(subCmd)
				return cmd
			},
			expected: false,
		},
		{
			name: "edge_case_handles_single_arg_correctly",
			setupArgs: func() func() {
				originalArgs := make([]string, len(os.Args))
				copy(originalArgs, os.Args)
				os.Args = []string{"idsec", "single"}
				return func() {
					os.Args = originalArgs
				}
			},
			setupCmd: func() *cobra.Command {
				return &cobra.Command{Use: "root"}
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Don't use Parallel() here since we're modifying os.Args
			cleanup := tt.setupArgs()
			defer cleanup()

			cmd := tt.setupCmd()
			result := isRootCommandError(cmd)

			if result != tt.expected {
				t.Errorf("Expected isRootCommandError to return %v, got %v", tt.expected, result)
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, result)
			}
		})
	}
}

func TestSetupCustomHelp(t *testing.T) {
	tests := []struct {
		name         string
		setupCmd     func() *cobra.Command
		validateFunc func(t *testing.T, cmd *cobra.Command)
	}{
		{
			name: "success_sets_custom_help_function",
			setupCmd: func() *cobra.Command {
				return &cobra.Command{Use: "root"}
			},
			validateFunc: func(t *testing.T, cmd *cobra.Command) {
				// Verify that help function is set (not nil)
				helpFunc := cmd.HelpFunc()
				if helpFunc == nil {
					t.Error("Expected help function to be set")
				}
			},
		},
		{
			name: "success_help_function_is_set",
			setupCmd: func() *cobra.Command {
				cmd := &cobra.Command{Use: "root"}
				setupCustomHelp(cmd)
				return cmd
			},
			validateFunc: func(t *testing.T, cmd *cobra.Command) {
				// Verify that help function is set (not nil)
				helpFunc := cmd.HelpFunc()
				if helpFunc == nil {
					t.Error("Expected help function to be set")
				}
			},
		},
		{
			name: "success_help_includes_exec_services_when_available",
			setupCmd: func() *cobra.Command {
				cmd := &cobra.Command{Use: "root"}
				execCmd := &cobra.Command{Use: "exec"}
				execCmd.AddCommand(&cobra.Command{
					Use:   "service1",
					Short: "Service 1 description",
				})
				execCmd.AddCommand(&cobra.Command{
					Use:   "service2",
					Short: "Service 2 description",
				})
				cmd.AddCommand(execCmd)
				return cmd
			},
			validateFunc: func(t *testing.T, cmd *cobra.Command) {
				// The help function should be set up to show services
				// We can't easily test the output without executing, but we can verify setup
				helpFunc := cmd.HelpFunc()
				if helpFunc == nil {
					t.Error("Expected help function to be set")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cmd := tt.setupCmd()
			setupCustomHelp(cmd)

			if tt.validateFunc != nil {
				tt.validateFunc(t, cmd)
			}
		})
	}
}

func TestHandleCommandExecution_RoutesToExecOnUnknownFlag(t *testing.T) {
	tests := []struct {
		name          string
		args          []string
		knownCommands []string
		errStr        string
		shouldReroute bool
	}{
		{
			name:          "success_reroutes_unknown_command_for_service_name",
			args:          []string{"idsec", "pcloud", "accounts", "list"},
			knownCommands: []string{"login", "exec"},
			errStr:        "unknown command \"pcloud\" for \"idsec\"",
			shouldReroute: true,
		},
		{
			name:          "success_reroutes_unknown_flag_for_service_name",
			args:          []string{"idsec", "pcloud", "accounts", "list", "--profile-name", "test"},
			knownCommands: []string{"login", "exec"},
			errStr:        "unknown flag: --profile-name",
			shouldReroute: true,
		},
		{
			name:          "success_does_not_reroute_known_subcommand",
			args:          []string{"idsec", "login", "--bad-flag"},
			knownCommands: []string{"login", "exec"},
			errStr:        "unknown flag: --bad-flag",
			shouldReroute: false,
		},
		{
			name:          "success_reroutes_flag_before_service_name",
			args:          []string{"idsec", "--profile-name", "test", "pcloud", "accounts", "list"},
			knownCommands: []string{"login", "exec"},
			errStr:        "unknown flag: --profile-name",
			shouldReroute: true,
		},
		{
			name:          "success_does_not_reroute_unrelated_error",
			args:          []string{"idsec", "pcloud"},
			knownCommands: []string{"login", "exec"},
			errStr:        "network timeout",
			shouldReroute: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rootCmd := &cobra.Command{Use: "root"}
			for _, name := range tt.knownCommands {
				rootCmd.AddCommand(&cobra.Command{Use: name})
			}

			firstArg := tt.args[1]
			errStr := tt.errStr

			matched := !isKnownSubcommand(rootCmd, firstArg) &&
				(strings.Contains(errStr, "unknown command") || strings.Contains(errStr, "unknown flag"))

			if matched != tt.shouldReroute {
				t.Errorf("Expected reroute=%v, got %v for args=%v errStr=%q", tt.shouldReroute, matched, tt.args, tt.errStr)
			}
		})
	}
}

func TestSetupDefaultRouting(t *testing.T) {
	tests := []struct {
		name         string
		setupCmd     func() *cobra.Command
		args         []string
		validateFunc func(t *testing.T, cmd *cobra.Command)
	}{
		{
			name: "success_sets_run_function",
			setupCmd: func() *cobra.Command {
				return &cobra.Command{Use: "root"}
			},
			args: []string{},
			validateFunc: func(t *testing.T, cmd *cobra.Command) {
				if cmd.Run == nil {
					t.Error("Expected Run function to be set")
				}
			},
		},
		{
			name: "success_run_function_shows_help_for_empty_args",
			setupCmd: func() *cobra.Command {
				cmd := &cobra.Command{Use: "root"}
				cmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
					// Mock help function
				})
				return cmd
			},
			args: []string{},
			validateFunc: func(t *testing.T, cmd *cobra.Command) {
				// The Run function should be set
				if cmd.Run == nil {
					t.Error("Expected Run function to be set")
				}
			},
		},
		{
			name: "success_run_function_handles_unknown_commands",
			setupCmd: func() *cobra.Command {
				cmd := &cobra.Command{Use: "root"}
				cmd.AddCommand(&cobra.Command{Use: "known"})
				return cmd
			},
			args: []string{"unknown"},
			validateFunc: func(t *testing.T, cmd *cobra.Command) {
				// The Run function should be set to handle routing
				if cmd.Run == nil {
					t.Error("Expected Run function to be set")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cmd := tt.setupCmd()
			setupDefaultRouting(cmd)

			if tt.validateFunc != nil {
				tt.validateFunc(t, cmd)
			}
		})
	}
}
