package actions

import (
	"reflect"
	"testing"

	"github.com/spf13/cobra"
	"github.com/cyberark/idsec-cli-golang/pkg/actions/testutils"
	"github.com/cyberark/idsec-sdk-golang/pkg/config"
)

func TestNewIdsecVersionAction(t *testing.T) {
	tests := []struct {
		name         string
		validateFunc func(t *testing.T, action *IdsecVersionAction)
	}{
		{
			name: "success_creates_version_action_with_embedded_base_action",
			validateFunc: func(t *testing.T, action *IdsecVersionAction) {
				if action == nil {
					t.Error("Expected action to be created, got nil")
					return
				}
				if action.IdsecBaseAction == nil {
					t.Error("Expected embedded IdsecBaseAction to be initialized")
				}
			},
		},
		{
			name: "success_embedded_base_action_has_logger",
			validateFunc: func(t *testing.T, action *IdsecVersionAction) {
				if action.IdsecBaseAction == nil {
					t.Error("Expected embedded IdsecBaseAction to be initialized")
					return
				}
				// Access logger through reflection since it's unexported
				actionValue := reflect.ValueOf(action.IdsecBaseAction).Elem()
				loggerField := actionValue.FieldByName("logger")
				if !loggerField.IsValid() {
					t.Error("Expected logger field to exist in embedded IdsecBaseAction")
					return
				}
				if loggerField.IsNil() {
					t.Error("Expected logger to be initialized")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			action := NewIdsecVersionAction()

			if tt.validateFunc != nil {
				tt.validateFunc(t, action)
			}
		})
	}
}

func TestIdsecVersionAction_DefineAction(t *testing.T) {
	tests := []struct {
		name         string
		validateFunc func(t *testing.T, rootCmd *cobra.Command, action *IdsecVersionAction)
	}{
		{
			name: "success_adds_version_command_to_parent",
			validateFunc: func(t *testing.T, rootCmd *cobra.Command, action *IdsecVersionAction) {
				versionCmd, _, err := rootCmd.Find([]string{"version"})
				if err != nil {
					t.Errorf("Expected to find version command, got error: %v", err)
					return
				}
				if versionCmd == nil {
					t.Error("Expected version command to be added")
					return
				}
				if versionCmd.Use != "version" {
					t.Errorf("Expected version command Use to be 'version', got '%s'", versionCmd.Use)
				}
				if versionCmd.Short != "Print the Idsec CLI version" {
					t.Errorf("Expected version command Short to be 'Print the Idsec CLI version', got '%s'", versionCmd.Short)
				}
			},
		},
		{
			name: "success_version_command_has_run_function",
			validateFunc: func(t *testing.T, rootCmd *cobra.Command, action *IdsecVersionAction) {
				versionCmd, _, err := rootCmd.Find([]string{"version"})
				if err != nil {
					t.Errorf("Expected to find version command, got error: %v", err)
					return
				}
				if versionCmd.Run == nil {
					t.Error("Expected version command to have Run function")
				}
			},
		},
		{
			name: "success_version_command_has_silent_flag_with_shorthand",
			validateFunc: func(t *testing.T, rootCmd *cobra.Command, action *IdsecVersionAction) {
				versionCmd, _, err := rootCmd.Find([]string{"version"})
				if err != nil {
					t.Errorf("Expected to find version command, got error: %v", err)
					return
				}
				flag := versionCmd.Flags().Lookup("silent")
				if flag == nil {
					t.Error("Expected version command to have 'silent' flag")
					return
				}
				if flag.Shorthand != "s" {
					t.Errorf("Expected 'silent' flag shorthand to be 's', got '%s'", flag.Shorthand)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			action := NewIdsecVersionAction()
			rootCmd := &cobra.Command{Use: "test"}

			action.DefineAction(rootCmd)

			if tt.validateFunc != nil {
				tt.validateFunc(t, rootCmd, action)
			}
		})
	}
}

func TestIdsecVersionAction_runVersionAction(t *testing.T) {
	tests := []struct {
		name            string
		silent          bool
		stubVersion     string
		stubBuildNumber string
		stubBuildDate   string
		stubGitCommit   string
		stubGitBranch   string
		expectedOutput  string
	}{
		{
			name:            "success_default_mode_prints_full_metadata_block",
			silent:          false,
			stubVersion:     "v1.2.3",
			stubBuildNumber: "42",
			stubBuildDate:   "2026-05-20T13:31:52Z",
			stubGitCommit:   "8e682dc6b01ac408b1e66f0162809bd877a496cc",
			stubGitBranch:   "main",
			expectedOutput: "Idsec v1.2.3\n" +
				"Build Number: 42\n" +
				"Build Date: 2026-05-20T13:31:52Z\n" +
				"Git Commit: 8e682dc6b01ac408b1e66f0162809bd877a496cc\n" +
				"Git Branch: main\n",
		},
		{
			name:            "success_silent_mode_strips_idsec_and_v_prefix",
			silent:          true,
			stubVersion:     "v1.2.3",
			stubBuildNumber: "42",
			stubBuildDate:   "2026-05-20T13:31:52Z",
			stubGitCommit:   "8e682dc6b01ac408b1e66f0162809bd877a496cc",
			stubGitBranch:   "main",
			expectedOutput:  "1.2.3\n",
		},
		{
			name:            "success_silent_mode_handles_version_without_v_prefix",
			silent:          true,
			stubVersion:     "0.4.0",
			stubBuildNumber: "1",
			stubBuildDate:   "2026-01-01T00:00:00Z",
			stubGitCommit:   "abc123",
			stubGitBranch:   "release",
			expectedOutput:  "0.4.0\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Not using t.Parallel() because we mutate the global SDK config state.

			originalVersion := config.IdsecVersion()
			originalBuildNumber := config.IdsecBuildNumber()
			originalBuildDate := config.IdsecBuildDate()
			originalGitCommit := config.IdsecGitCommit()
			originalGitBranch := config.IdsecGitBranch()
			config.SetIdsecVersion(tt.stubVersion)
			config.SetIdsecBuildNumber(tt.stubBuildNumber)
			config.SetIdsecBuildDate(tt.stubBuildDate)
			config.SetIdsecGitCommit(tt.stubGitCommit)
			config.SetIdsecGitBranch(tt.stubGitBranch)
			defer func() {
				config.SetIdsecVersion(originalVersion)
				config.SetIdsecBuildNumber(originalBuildNumber)
				config.SetIdsecBuildDate(originalBuildDate)
				config.SetIdsecGitCommit(originalGitCommit)
				config.SetIdsecGitBranch(originalGitBranch)
			}()

			action := NewIdsecVersionAction()
			rootCmd := &cobra.Command{Use: "test"}
			action.DefineAction(rootCmd)

			versionCmd, _, err := rootCmd.Find([]string{"version"})
			if err != nil {
				t.Fatalf("Expected to find version command, got error: %v", err)
			}

			if tt.silent {
				if err := versionCmd.Flags().Set("silent", "true"); err != nil {
					t.Fatalf("Failed to set silent flag: %v", err)
				}
			}

			output := testutils.CaptureOutput(func() {
				action.runVersionAction(versionCmd, nil)
			})

			if output != tt.expectedOutput {
				t.Errorf("Expected output to be %q, got %q", tt.expectedOutput, output)
			}
		})
	}
}

func TestIdsecVersionAction_StructFields(t *testing.T) {
	tests := []struct {
		name         string
		validateFunc func(t *testing.T, action *IdsecVersionAction)
	}{
		{
			name: "success_struct_embeds_idsecbaseaction",
			validateFunc: func(t *testing.T, action *IdsecVersionAction) {
				actionValue := reflect.ValueOf(action).Elem()
				actionType := actionValue.Type()

				// Check that it embeds IdsecBaseAction
				found := false
				for i := 0; i < actionType.NumField(); i++ {
					field := actionType.Field(i)
					if field.Type.String() == "*actions.IdsecBaseAction" && field.Anonymous {
						found = true
						break
					}
				}
				if !found {
					t.Error("Expected IdsecVersionAction to embed *IdsecBaseAction")
				}
			},
		},
		{
			name: "success_implements_idsecaction_interface",
			validateFunc: func(t *testing.T, action *IdsecVersionAction) {
				// Verify it implements IdsecAction interface by checking method exists
				actionValue := reflect.ValueOf(action)
				actionType := actionValue.Type()

				method, exists := actionType.MethodByName("DefineAction")
				if !exists {
					t.Error("Expected DefineAction method to exist")
					return
				}

				// Check method signature: func(cmd *cobra.Command)
				if method.Type.NumIn() != 2 { // receiver + parameter
					t.Errorf("DefineAction should have 1 parameter, got %d", method.Type.NumIn()-1)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			action := NewIdsecVersionAction()

			if tt.validateFunc != nil {
				tt.validateFunc(t, action)
			}
		})
	}
}

func TestIdsecVersionAction_IntegrationWithIdsecAction(t *testing.T) {
	tests := []struct {
		name         string
		validateFunc func(t *testing.T, action *IdsecVersionAction)
	}{
		{
			name: "success_can_be_used_as_idsecaction_interface",
			validateFunc: func(t *testing.T, action *IdsecVersionAction) {
				// This should compile if IdsecVersionAction implements IdsecAction
				var idsecAction IdsecAction = action

				// Test that we can call the interface method
				rootCmd := &cobra.Command{Use: "test"}
				idsecAction.DefineAction(rootCmd)

				// Verify the command was added
				versionCmd, _, err := rootCmd.Find([]string{"version"})
				if err != nil {
					t.Errorf("Expected to find version command after DefineAction call, got error: %v", err)
				}
				if versionCmd == nil {
					t.Error("Expected version command to be added through interface call")
				}
			},
		},
		{
			name: "success_inherits_common_action_methods",
			validateFunc: func(t *testing.T, action *IdsecVersionAction) {
				// Verify that methods from IdsecBaseAction are accessible
				cmd := &cobra.Command{}

				// This should not panic and should add common flags
				action.CommonActionsConfiguration(cmd)

				// Check that common flags were added
				if flag := cmd.PersistentFlags().Lookup("verbose"); flag == nil {
					t.Error("Expected to inherit CommonActionsConfiguration from IdsecBaseAction")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			action := NewIdsecVersionAction()

			if tt.validateFunc != nil {
				tt.validateFunc(t, action)
			}
		})
	}
}
