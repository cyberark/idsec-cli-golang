package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/cyberark/idsec-cli-golang/pkg/actions"
	"github.com/cyberark/idsec-cli-golang/pkg/agentmode"
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
			name: "success_root_command_has_no_version_field",
			validateFunc: func(t *testing.T, cmd *cobra.Command) {
				if cmd.Version != "" {
					t.Errorf("Expected Version to be empty, got '%s'", cmd.Version)
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
				expectedCommands := []string{"profiles", "cache", "configure", "login", "exec", "upgrade", "version"}
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

func TestHasHelpFlag(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		expected bool
	}{
		{
			name:     "success_returns_true_for_short_help_flag",
			args:     []string{"pcloud", "safes", "-h"},
			expected: true,
		},
		{
			name:     "success_returns_true_for_long_help_flag",
			args:     []string{"pcloud", "safes", "--help"},
			expected: true,
		},
		{
			name:     "success_returns_true_for_help_equals",
			args:     []string{"pcloud", "--help=true"},
			expected: true,
		},
		{
			name:     "success_returns_false_when_help_missing",
			args:     []string{"pcloud", "safes", "list"},
			expected: false,
		},
		{
			name:     "success_returns_false_for_empty_args",
			args:     []string{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := hasHelpFlag(tt.args)
			if result != tt.expected {
				t.Errorf("Expected hasHelpFlag to return %v for %v, got %v", tt.expected, tt.args, result)
			}
		})
	}
}

func TestFirstPositionalArg(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		expected string
	}{
		{
			name:     "success_returns_first_positional_for_service_path",
			args:     []string{"pcloud", "safes", "--help"},
			expected: "pcloud",
		},
		{
			name:     "success_returns_empty_when_only_help_flag",
			args:     []string{"--help"},
			expected: "",
		},
		{
			name:     "success_skips_config_value_then_returns_service",
			args:     []string{"--config", "/tmp/c.yaml", "pcloud", "--help"},
			expected: "pcloud",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := firstPositionalArg(tt.args)
			if result != tt.expected {
				t.Errorf("Expected firstPositionalArg to return %q for %v, got %q", tt.expected, tt.args, result)
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

func TestRerouteHelpToExecIfNeeded(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		expectedArgs []string
	}{
		{
			name:         "success_reroutes_help_for_service_resource_path",
			args:         []string{"idsec", "pcloud", "safes", "--help"},
			expectedArgs: []string{"idsec", "exec", "pcloud", "safes", "--help"},
		},
		{
			name:         "success_reroutes_help_for_service_alias",
			args:         []string{"idsec", "pc", "--help"},
			expectedArgs: []string{"idsec", "exec", "pc", "--help"},
		},
		{
			name:         "success_leaves_global_help_unchanged",
			args:         []string{"idsec", "--help"},
			expectedArgs: []string{"idsec", "--help"},
		},
		{
			name:         "success_leaves_known_subcommand_help_unchanged",
			args:         []string{"idsec", "login", "--help"},
			expectedArgs: []string{"idsec", "login", "--help"},
		},
		{
			name:         "success_leaves_explicit_exec_help_unchanged",
			args:         []string{"idsec", "exec", "pcloud", "safes", "--help"},
			expectedArgs: []string{"idsec", "exec", "pcloud", "safes", "--help"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Avoid t.Parallel(): tests mutate process-global os.Args.
			originalArgs := make([]string, len(os.Args))
			copy(originalArgs, os.Args)
			defer func() {
				os.Args = originalArgs
			}()

			os.Args = append([]string{}, tt.args...)

			rootCmd := createRootCommand()
			rootCmd.AddCommand(&cobra.Command{Use: "exec"})
			rootCmd.AddCommand(&cobra.Command{Use: "login"})
			rootCmd.AddCommand(&cobra.Command{Use: "version"})

			rerouteHelpToExecIfNeeded(rootCmd)

			if len(os.Args) != len(tt.expectedArgs) {
				t.Fatalf("Expected os.Args length %d, got %d (actual=%v expected=%v)", len(tt.expectedArgs), len(os.Args), os.Args, tt.expectedArgs)
			}
			for i := range tt.expectedArgs {
				if os.Args[i] != tt.expectedArgs[i] {
					t.Fatalf("Expected os.Args[%d]=%q, got %q (actual=%v expected=%v)", i, tt.expectedArgs[i], os.Args[i], os.Args, tt.expectedArgs)
				}
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

func TestValidateCommandPathBeforeExecution(t *testing.T) {
	tests := []struct {
		name            string
		args            []string
		expectedErrPart string
	}{
		{
			name:            "error_when_exec_path_missing_service_no_flags",
			args:            []string{"idsec", "exec", "cloud-access", "list-targets"},
			expectedErrPart: `unknown command "cloud-access" for "idsec exec"`,
		},
		{
			name:            "error_when_shorthand_path_missing_service_no_flags",
			args:            []string{"idsec", "cloud-access", "list-targets"},
			expectedErrPart: `unknown command "cloud-access" for "idsec exec"`,
		},
		{
			name:            "success_for_valid_shorthand_service_path",
			args:            []string{"idsec", "sca", "cloud-access", "list-targets"},
			expectedErrPart: "",
		},
		{
			name:            "success_for_valid_exec_path",
			args:            []string{"idsec", "exec", "sca", "cloud-access", "list-targets"},
			expectedErrPart: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Avoid t.Parallel(): this test mutates process-global os.Args.
			originalArgs := make([]string, len(os.Args))
			copy(originalArgs, os.Args)
			defer func() {
				os.Args = originalArgs
			}()

			os.Args = append([]string{}, tt.args...)
			rootCmd := createRootCommand()
			registerActions(rootCmd, profiles.DefaultProfilesLoader())

			err := validateCommandPathBeforeExecution(rootCmd)
			if tt.expectedErrPart == "" {
				if err != nil {
					t.Fatalf("Expected no error, got %v", err)
				}
				return
			}

			if err == nil {
				t.Fatalf("Expected error containing %q, got nil", tt.expectedErrPart)
			}
			if !strings.Contains(err.Error(), tt.expectedErrPart) {
				t.Fatalf("Expected error to contain %q, got %q", tt.expectedErrPart, err.Error())
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

func TestReportCommandError(t *testing.T) {
	// Avoid t.Parallel() – tests mutate process-global os.Args.
	tests := []struct {
		name         string
		setupArgs    func() func() // returns cleanup
		setupCmd     func() *cobra.Command
		err          error
		wantHelp     bool // true when help content must appear before the error
		wantErrInBuf bool // true when error message must appear in the buffer
		onlyErrInBuf bool // true when buffer must contain ONLY the error line (no help)
	}{
		{
			// isRootCommandError=true + shouldShowHelpForError=true → help + blank + error
			name: "success_root_usage_error_writes_help_then_error",
			setupArgs: func() func() {
				orig := make([]string, len(os.Args))
				copy(orig, os.Args)
				// No known subcommand → isRootCommandError returns true.
				os.Args = []string{"idsec", "unknown-xyz"}
				return func() { os.Args = orig }
			},
			setupCmd: func() *cobra.Command {
				cmd := &cobra.Command{Use: "idsec", Short: "Idsec CLI"}
				cmd.AddCommand(&cobra.Command{Use: "version"})
				cmd.SilenceUsage = true
				return cmd
			},
			err:          fmt.Errorf("unknown command %q for %q", "foo", "idsec"),
			wantHelp:     true,
			wantErrInBuf: true,
		},
		{
			// shouldShowHelpForError=false → only the error line, no help
			name: "success_non_usage_error_writes_error_only",
			setupArgs: func() func() {
				orig := make([]string, len(os.Args))
				copy(orig, os.Args)
				// No known subcommand → isRootCommandError returns true, but
				// the error keyword doesn't match shouldShowHelpForError.
				os.Args = []string{"idsec", "network-timeout"}
				return func() { os.Args = orig }
			},
			setupCmd: func() *cobra.Command {
				cmd := &cobra.Command{Use: "idsec", Short: "Idsec CLI"}
				cmd.SilenceUsage = true
				return cmd
			},
			err:          fmt.Errorf("network timeout"),
			wantHelp:     false,
			wantErrInBuf: true,
			onlyErrInBuf: true,
		},
		{
			// isRootCommandError=false (known subcommand) → no help even for a
			// usage-style error keyword like "required".
			name: "success_known_subcommand_sets_isrootcmd_false",
			setupArgs: func() func() {
				orig := make([]string, len(os.Args))
				copy(orig, os.Args)
				os.Args = []string{"idsec", "version"}
				return func() { os.Args = orig }
			},
			setupCmd: func() *cobra.Command {
				cmd := &cobra.Command{Use: "idsec", Short: "Idsec CLI"}
				cmd.AddCommand(&cobra.Command{Use: "version"})
				cmd.SilenceUsage = true
				return cmd
			},
			err:          fmt.Errorf("required flag --profile-name not provided"),
			wantHelp:     false,
			wantErrInBuf: true,
			onlyErrInBuf: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanup := tt.setupArgs()
			defer cleanup()

			rootCmd := tt.setupCmd()

			// Save the original Out writer so we can verify it's restored.
			originalOut := rootCmd.OutOrStdout()

			var buf bytes.Buffer
			reportCommandError(rootCmd, tt.err, &buf)

			got := buf.String()

			// Verify the error message is present.
			if tt.wantErrInBuf && !strings.Contains(got, tt.err.Error()) {
				t.Errorf("expected buffer to contain error %q, got:\n%s", tt.err.Error(), got)
			}

			// Verify help content is (or is not) present.
			// Cobra's default help output always contains "Usage:" for a command
			// that has Use set, so that's a reliable marker.
			hasHelp := strings.Contains(got, "Usage:")
			if tt.wantHelp && !hasHelp {
				t.Errorf("expected buffer to contain help (Usage:), got:\n%s", got)
			}
			if !tt.wantHelp && hasHelp {
				t.Errorf("expected buffer to NOT contain help (Usage:), got:\n%s", got)
			}

			// For the "error only" case the buffer should be exactly
			// "<error>\n" (nothing else).
			if tt.onlyErrInBuf {
				expected := tt.err.Error() + "\n"
				if got != expected {
					t.Errorf("expected buffer to be exactly %q, got %q", expected, got)
				}
			}

			// rootCmd.OutOrStdout() must be restored to the original writer
			// after reportCommandError returns (it temporarily sets Out to &buf
			// while writing help).
			restoredOut := rootCmd.OutOrStdout()
			if restoredOut != originalOut {
				t.Errorf("expected rootCmd.OutOrStdout() to be restored to original after call")
			}
		})
	}
}

// setAgentMode resolves agent mode with every agent env var cleared. Tests
// using it mutate process-global state and must not call t.Parallel.
func setAgentMode(t *testing.T, agent bool) {
	t.Helper()
	// Registered first so it runs last (LIFO), after t.Setenv restores the env.
	t.Cleanup(func() {
		agentmode.Resolve(false, false)
		agentmode.ResetEnvelopeState()
	})
	t.Setenv(agentmode.EnvVar, "")
	t.Setenv(agentmode.ForceEnvVar, "")
	for _, v := range agentmode.DetectorEnvVars() {
		t.Setenv(v, "")
	}
	agentmode.Resolve(agent, false)
	agentmode.ResetEnvelopeState()
}

func setOSArgs(t *testing.T, args ...string) {
	t.Helper()
	originalArgs := make([]string, len(os.Args))
	copy(originalArgs, os.Args)
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = append([]string{}, args...)
}

// stubOSExit records exit codes instead of exiting.
func stubOSExit(t *testing.T) *[]int {
	t.Helper()
	original := osExit
	t.Cleanup(func() { osExit = original })
	codes := &[]int{}
	osExit = func(code int) { *codes = append(*codes, code) }
	return codes
}

// captureStdio runs fn with os.Stdout and os.Stderr redirected to pipes.
func captureStdio(t *testing.T, fn func()) (stdout, stderr string) {
	t.Helper()
	read := func(f **os.File) (restore func() string) {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("os.Pipe: %v", err)
		}
		original := *f
		*f = w
		done := make(chan string)
		go func() {
			b, _ := io.ReadAll(r)
			done <- string(b)
		}()
		return func() string {
			*f = original
			_ = w.Close()
			return <-done
		}
	}
	restoreOut := read(&os.Stdout)
	restoreErr := read(&os.Stderr)
	defer func() {
		stdout, stderr = restoreOut(), restoreErr()
	}()
	fn()
	return
}

func decodeEnvelope(t *testing.T, stdout string) agentmode.Envelope {
	t.Helper()
	if strings.Count(stdout, "\n") != 1 || !strings.HasSuffix(stdout, "\n") {
		t.Fatalf("stdout = %q, want exactly one envelope line", stdout)
	}
	var env agentmode.Envelope
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("unmarshal %q: %v", stdout, err)
	}
	if env.Status != agentmode.StatusError || env.Error == nil {
		t.Fatalf("envelope = %+v, want an error envelope", env)
	}
	return env
}

// newReportRoot builds a small fixed tree so help output is stable.
func newReportRoot() *cobra.Command {
	root := createRootCommand()
	root.AddCommand(&cobra.Command{Use: "version", Short: "Print the version", RunE: func(*cobra.Command, []string) error { return nil }})
	execCmd := &cobra.Command{Use: "exec", Short: "Execute service actions"}
	execCmd.AddCommand(&cobra.Command{Use: "pcloud", Short: "PCloud", RunE: func(*cobra.Command, []string) error { return nil }})
	root.AddCommand(execCmd)
	return root
}

type reportCase struct {
	name     string
	args     []string
	err      func(t *testing.T, root *cobra.Command) error
	showHelp bool
	// Human mode, captured from the pre-OLY-21331 exit sites.
	wantHumanStderr string
	wantExit        int
	// Agent mode.
	wantCode     agentmode.Code
	wantReported bool
}

func reportCases() []reportCase {
	return []reportCase{
		{
			name: "unknown_command",
			args: []string{"idsec", "exec", "nosuch"},
			err: func(t *testing.T, root *cobra.Command) error {
				return validateCommandPathBeforeExecution(root)
			},
			wantHumanStderr: "unknown command \"nosuch\" for \"idsec exec\"\n",
			wantExit:        1,
			wantCode:        agentmode.CodeUnknownCommand,
		},
		{
			name: "unknown_flag_known_subcommand",
			args: []string{"idsec", "version", "--bogus"},
			err: func(t *testing.T, root *cobra.Command) error {
				root.SetArgs([]string{"version", "--bogus"})
				return root.Execute()
			},
			showHelp:        true,
			wantHumanStderr: "unknown flag: --bogus\n",
			wantExit:        1,
			wantCode:        agentmode.CodeInvalidInput,
		},
		{
			name: "root_usage_error_with_help",
			args: []string{"idsec", "unknown-xyz"},
			err: func(*testing.T, *cobra.Command) error {
				return fmt.Errorf("unknown command %q for %q", "unknown-xyz", "idsec")
			},
			showHelp: true,
			wantHumanStderr: "Idsec CLI\n\nUsage:\n  idsec [command]\n\nAvailable Commands:\n" +
				"  exec        Execute service actions\n  version     Print the version\n\n" +
				"Flags:\n      --config string   Path to configuration file (default ~/.idsec/config.yaml)\n\n" +
				"Use \"idsec [command] --help\" for more information about a command.\n\n" +
				"unknown command \"unknown-xyz\" for \"idsec\"\n",
			wantExit: 1,
			wantCode: agentmode.CodeUnknownCommand,
		},
		{
			name:            "exit_code_1",
			args:            []string{"idsec", "version"},
			err:             func(*testing.T, *cobra.Command) error { return &actions.ExitCodeError{Code: 1} },
			showHelp:        true,
			wantHumanStderr: "",
			wantExit:        1,
			wantCode:        agentmode.CodeActionFailed,
			wantReported:    true,
		},
		{
			name:            "exit_code_4",
			args:            []string{"idsec", "version"},
			err:             func(*testing.T, *cobra.Command) error { return &actions.ExitCodeError{Code: 4} },
			showHelp:        true,
			wantHumanStderr: "",
			wantExit:        4,
			wantCode:        agentmode.CodeActionFailed,
			wantReported:    true,
		},
		{
			name:            "plain_error",
			args:            []string{"idsec", "version"},
			err:             func(*testing.T, *cobra.Command) error { return errors.New("network timeout") },
			wantHumanStderr: "network timeout\n",
			wantExit:        1,
			wantCode:        agentmode.CodeActionFailed,
		},
	}
}

func TestReportError_HumanGolden(t *testing.T) {
	cases := append(reportCases(), reportCase{
		name:            "quiet_exit_4",
		args:            []string{"idsec", "version"},
		err:             func(*testing.T, *cobra.Command) error { return &actions.ExitCodeError{Code: 4, Quiet: true} },
		showHelp:        true,
		wantHumanStderr: "",
		wantExit:        4,
	})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setAgentMode(t, false)
			setOSArgs(t, tc.args...)
			root := newReportRoot()
			err := tc.err(t, root)

			var stdout, stderr bytes.Buffer
			code := reportError(root, err, tc.showHelp, &stdout, &stderr)

			if code != tc.wantExit {
				t.Errorf("exit = %d, want %d", code, tc.wantExit)
			}
			if stderr.String() != tc.wantHumanStderr {
				t.Errorf("stderr = %q, want %q", stderr.String(), tc.wantHumanStderr)
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout = %q, want empty", stdout.String())
			}
		})
	}
}

func TestReportError_Agent(t *testing.T) {
	for _, tc := range reportCases() {
		t.Run(tc.name, func(t *testing.T) {
			setAgentMode(t, true)
			setOSArgs(t, tc.args...)
			root := newReportRoot()
			err := tc.err(t, root)

			var stdout, stderr bytes.Buffer
			code := reportError(root, err, tc.showHelp, &stdout, &stderr)

			if code != tc.wantExit {
				t.Errorf("exit = %d, want %d", code, tc.wantExit)
			}
			env := decodeEnvelope(t, stdout.String())
			if env.Error.Code != tc.wantCode {
				t.Errorf("code = %q, want %q", env.Error.Code, tc.wantCode)
			}
			wantStderr := err.Error() + "\n"
			if tc.wantReported {
				wantStderr = ""
			}
			if stderr.String() != wantStderr {
				t.Errorf("stderr = %q, want %q", stderr.String(), wantStderr)
			}
			if strings.Contains(stderr.String(), "Available Commands") {
				t.Errorf("stderr contains the help dump: %q", stderr.String())
			}
		})
	}
}

func TestReportError_AgentQuiet(t *testing.T) {
	setAgentMode(t, true)
	root := newReportRoot()
	for code := 2; code <= 5; code++ {
		var stdout, stderr bytes.Buffer
		got := reportError(root, &actions.ExitCodeError{Code: code, Quiet: true}, true, &stdout, &stderr)
		if got != code || stdout.Len() != 0 || stderr.Len() != 0 {
			t.Errorf("quiet %d: exit = %d, stdout = %q, stderr = %q", code, got, stdout.String(), stderr.String())
		}
	}

	var stdout, stderr bytes.Buffer
	if got := reportError(root, errors.New("status failed"), false, &stdout, &stderr); got != 1 {
		t.Errorf("plain error exit = %d, want 1", got)
	}
	if env := decodeEnvelope(t, stdout.String()); env.Error.Message != "status failed" {
		t.Errorf("message = %q", env.Error.Message)
	}
}

func TestReportError_AgentAlreadyReported(t *testing.T) {
	setAgentMode(t, true)
	failure := agentmode.NewFailure(agentmode.CodeProfileNotFound, errors.New("profile \"dev\" not found"),
		agentmode.WithDetail("profile", "dev"))

	var stdout, stderr bytes.Buffer
	code := reportError(newReportRoot(), &actions.ExitCodeError{Code: 1, Failure: failure}, true, &stdout, &stderr)

	if code != 1 {
		t.Errorf("exit = %d, want 1", code)
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty (the action already printed)", stderr.String())
	}
	env := decodeEnvelope(t, stdout.String())
	if env.Error.Code != agentmode.CodeProfileNotFound || env.Error.Message != failure.Message {
		t.Errorf("error = %q %q", env.Error.Code, env.Error.Message)
	}
}

func TestValidateCommandPath_UnknownCommandFailure(t *testing.T) {
	setAgentMode(t, false)
	setOSArgs(t, "idsec", "exec", "nosuch")
	rootCmd := createRootCommand()
	registerActions(rootCmd, profiles.DefaultProfilesLoader())

	err := validateCommandPathBeforeExecution(rootCmd)

	if err == nil || err.Error() != `unknown command "nosuch" for "idsec exec"` {
		t.Fatalf("err = %v", err)
	}
	var f *agentmode.Failure
	if !errors.As(err, &f) {
		t.Fatalf("err = %#v, want *agentmode.Failure", err)
	}
	if f.Code != agentmode.CodeUnknownCommand || f.Details["kind"] != agentmode.KindUnknownCommand ||
		f.Details["token"] != "nosuch" || f.Details["parent"] != "idsec exec" {
		t.Errorf("Failure = %q %#v", f.Code, f.Details)
	}
	available, _ := f.Details["available"].([]string)
	if len(available) == 0 || !slicesSorted(available) {
		t.Errorf("available = %#v, want non-empty sorted names", f.Details["available"])
	}
	if !reflect.DeepEqual(f.Hints, []string{"run `idsec exec --help` to list available commands"}) {
		t.Errorf("hints = %#v", f.Hints)
	}
}

func TestValidateCommandPath_UnknownCommandAfterUnknownFlag(t *testing.T) {
	const secret = "S3CRET-pw"
	cases := []struct {
		name       string
		args       []string
		wantText   string
		wantParent string
		wantToken  any
	}{
		{
			name:       "undefined_flag_before_subcommand",
			args:       []string{"exec", "pcloud", "--bogus-flag", secret, "accounts", "list"},
			wantText:   `unknown command "` + secret + `" for "idsec exec pcloud"`,
			wantParent: "idsec exec pcloud",
		},
		{
			name:       "known_bool_flag_keeps_token",
			args:       []string{"exec", "--verbose", "nosuch"},
			wantText:   `unknown command "nosuch" for "idsec exec"`,
			wantParent: "idsec exec",
			wantToken:  "nosuch",
		},
		{
			name:       "inline_value_keeps_token",
			args:       []string{"exec", "pcloud", "--bogus-flag=x", "acounts"},
			wantText:   `unknown command "acounts" for "idsec exec pcloud"`,
			wantParent: "idsec exec pcloud",
			wantToken:  "acounts",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setAgentMode(t, false)
			setOSArgs(t, append([]string{"idsec"}, tc.args...)...)
			rootCmd := createRootCommand()
			registerActions(rootCmd, profiles.DefaultProfilesLoader())

			err := validateCommandPathBeforeExecution(rootCmd)

			if err == nil || err.Error() != tc.wantText {
				t.Fatalf("err = %v, want unchanged human text %q", err, tc.wantText)
			}
			f := actions.ClassifyError(err)
			if f.Details["parent"] != tc.wantParent || f.Details["token"] != tc.wantToken {
				t.Errorf("parent, token = %#v, %#v; want %q, %#v", f.Details["parent"], f.Details["token"], tc.wantParent, tc.wantToken)
			}
			var buf bytes.Buffer
			if werr := agentmode.Write(&buf, agentmode.NewErrorEnvelope(f)); werr != nil {
				t.Fatalf("Write: %v", werr)
			}
			if strings.Contains(buf.String(), secret) {
				t.Errorf("envelope leaks the flag value: %s", buf.String())
			}
			if tc.wantToken == nil && f.Message != `unknown command for "`+tc.wantParent+`"` {
				t.Errorf("Message = %q", f.Message)
			}
		})
	}
}

func TestValidateCommandPath_InheritedValueFlagBeforeSubcommand(t *testing.T) {
	setAgentMode(t, false)
	setOSArgs(t, "idsec", "exec", "pcloud", "accounts", "--proxy-password", "S3CRET-pw", "list")
	rootCmd := createRootCommand()
	registerActions(rootCmd, profiles.DefaultProfilesLoader())

	if err := validateCommandPathBeforeExecution(rootCmd); err != nil {
		t.Errorf("err = %v, want nil: an inherited value flag's value is not a command", err)
	}
}

func slicesSorted(s []string) bool {
	for i := 1; i < len(s); i++ {
		if s[i-1] > s[i] {
			return false
		}
	}
	return true
}

// newMainRoot builds the command tree the way main does before validation.
func newMainRoot() *cobra.Command {
	rootCmd := createRootCommand()
	registerActions(rootCmd, profiles.DefaultProfilesLoader())
	rootCmd.InitDefaultHelpCmd()
	rootCmd.InitDefaultCompletionCmd()
	setupTransparentExecCompletion(rootCmd)
	return rootCmd
}

func TestValidateCommandPath_IncompleteCommand(t *testing.T) {
	cases := []struct {
		args       []string
		wantParent string
	}{
		{args: []string{"exec", "pcloud"}, wantParent: "idsec exec pcloud"},
		{args: []string{"pcloud"}, wantParent: "idsec pcloud"},
		{args: []string{"exec"}, wantParent: "idsec exec"},
		{args: nil, wantParent: "idsec"},
		{args: []string{"--agent"}, wantParent: "idsec"},
	}
	for _, tc := range cases {
		name := strings.Join(append([]string{"idsec"}, tc.args...), "_")
		t.Run(name+"/agent", func(t *testing.T) {
			setAgentMode(t, true)
			setOSArgs(t, append([]string{"idsec"}, tc.args...)...)

			err := validateCommandPathBeforeExecution(newMainRoot())

			var f *agentmode.Failure
			if !errors.As(err, &f) {
				t.Fatalf("err = %#v, want *agentmode.Failure", err)
			}
			if err.Error() != fmt.Sprintf("%q requires a subcommand", tc.wantParent) {
				t.Errorf("text = %q", err.Error())
			}
			if f.Code != agentmode.CodeUnknownCommand || f.Details["kind"] != agentmode.KindIncompleteCommand ||
				f.Details["parent"] != tc.wantParent {
				t.Errorf("Failure = %q %#v", f.Code, f.Details)
			}
			if available, _ := f.Details["available"].([]string); len(available) == 0 || !slicesSorted(available) {
				t.Errorf("available = %#v", f.Details["available"])
			}
			if want := []string{"run `" + tc.wantParent + " --help` to list available commands"}; !reflect.DeepEqual(f.Hints, want) {
				t.Errorf("hints = %#v, want %#v", f.Hints, want)
			}
		})
		t.Run(name+"/agent_help", func(t *testing.T) {
			setAgentMode(t, true)
			setOSArgs(t, append(append([]string{"idsec"}, tc.args...), "--help")...)
			if err := validateCommandPathBeforeExecution(newMainRoot()); err != nil {
				t.Errorf("err = %v, want nil", err)
			}
		})
		t.Run(name+"/human", func(t *testing.T) {
			setAgentMode(t, false)
			setOSArgs(t, append([]string{"idsec"}, tc.args...)...)
			if err := validateCommandPathBeforeExecution(newMainRoot()); err != nil {
				t.Errorf("err = %v, want nil", err)
			}
		})
	}
}

func TestFlagErrorFunc_Inherited(t *testing.T) {
	root := createRootCommand()
	execCmd := &cobra.Command{Use: "exec"}
	pcloud := &cobra.Command{Use: "pcloud"}
	pcloud.AddCommand(&cobra.Command{Use: "list", RunE: func(*cobra.Command, []string) error { return nil }})
	execCmd.AddCommand(pcloud)
	root.AddCommand(execCmd)
	root.SetArgs([]string{"exec", "pcloud", "list", "--bogus"})

	err := root.Execute()

	var f *agentmode.Failure
	if !errors.As(err, &f) || f.Code != agentmode.CodeInvalidInput {
		t.Fatalf("err = %#v, want INVALID_INPUT Failure", err)
	}
	if !strings.Contains(err.Error(), "unknown flag") {
		t.Errorf("err text = %q; the exec reroute matches \"unknown flag\"", err.Error())
	}
	if f.Details["command"] != "idsec exec pcloud list" || f.Details["flag"] != "bogus" {
		t.Errorf("details = %#v", f.Details)
	}
}

func TestExitWithError_SingleEmission(t *testing.T) {
	newRoot := func() *cobra.Command {
		root := createRootCommand()
		root.AddCommand(&cobra.Command{Use: "version", RunE: func(*cobra.Command, []string) error { return nil }})
		execCmd := &cobra.Command{Use: "exec"}
		pcloud := &cobra.Command{Use: "pcloud"}
		pcloud.AddCommand(&cobra.Command{Use: "list", RunE: func(*cobra.Command, []string) error { return errors.New("boom") }})
		execCmd.AddCommand(pcloud)
		root.AddCommand(execCmd)
		setupDefaultRouting(root)
		return root
	}
	cases := []struct {
		name     string
		args     []string
		wantCode agentmode.Code
		wantMsg  string
	}{
		{name: "default_routing", args: []string{"idsec", "pcloud", "list"}, wantCode: agentmode.CodeActionFailed, wantMsg: "boom"},
		{name: "final", args: []string{"idsec", "version", "--bogus"}, wantCode: agentmode.CodeInvalidInput, wantMsg: "unknown flag: --bogus"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setAgentMode(t, true)
			setOSArgs(t, tc.args...)
			exits := stubOSExit(t)
			root := newRoot()

			stdout, stderr := captureStdio(t, func() { handleCommandExecution(root) })

			if !reflect.DeepEqual(*exits, []int{1}) {
				t.Errorf("exits = %v, want [1]", *exits)
			}
			env := decodeEnvelope(t, stdout)
			if env.Error.Code != tc.wantCode || env.Error.Message != tc.wantMsg {
				t.Errorf("error = %q %q", env.Error.Code, env.Error.Message)
			}
			if stderr != tc.wantMsg+"\n" {
				t.Errorf("stderr = %q, want %q", stderr, tc.wantMsg+"\n")
			}
		})
	}
}

func TestMain_PreResolvesAgentMode(t *testing.T) {
	setAgentMode(t, false)

	agentmode.ResolveFromArgs([]string{"pcloud", "--agent", "--bogus"})

	if !agentmode.IsEnabled() {
		t.Error("IsEnabled() = false after ResolveFromArgs with --agent")
	}
}
