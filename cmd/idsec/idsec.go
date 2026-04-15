// Package main provides the entry point for the Idsec CLI application.
//
// The Idsec CLI is a command-line interface that provides access to various
// Idsec services and functionality including profile management, authentication,
// configuration, caching, and service execution.
//
// The application uses the Cobra library for command-line interface management
// and supports multiple subcommands for different operations. Build information
// including version, build number, build date, and git commit are embedded
// at compile time through build variables.
//
// Example usage:
//
//	idsec --version
//	idsec profiles list
//	idsec login
//	idsec configure
package main

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/cyberark/idsec-sdk-golang/pkg/config"

	"github.com/cyberark/idsec-cli-golang/pkg/actions"
	_ "github.com/cyberark/idsec-cli-golang/pkg/registry"
	k8sactions "github.com/cyberark/idsec-cli-golang/pkg/services/sca/k8s/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/profiles"
)

// main is the entry point for the Idsec CLI application.
//
// This function initializes the Cobra root command with version information,
// sets up the application version in the common package, creates a profiles
// loader, and registers all available actions (profiles, cache, configure,
// login, and service execution) with the root command.
//
// The function handles command execution and exits with code 1 if an error
// occurs during command execution. The version template is customized to
// display build information in a specific format.
//
// Build variables (GitCommit, BuildDate, Version, BuildNumber) are expected
// to be set at compile time using ldflags but will default to "N/A" if not
// provided.
//
// Available commands after initialization:
//   - profiles: Manage user profiles
//   - cache: Manage application cache
//   - configure: Configure the CLI
//   - login: Authenticate with services
//   - exec: Execute service actions
//
// The function will call os.Exit(1) if command execution fails.
func main() {
	defer actions.RecoverFromPanic()

	config.SetIdsecToolInUse(config.IdsecToolCLI)
	profilesLoader := profiles.DefaultProfilesLoader()

	rootCmd := createRootCommand()
	registerActions(rootCmd, profilesLoader)
	setupCustomHelp(rootCmd)
	setupDefaultRouting(rootCmd)
	handleCommandExecution(rootCmd)
}

// createRootCommand creates and configures the root Cobra command with version information.
func createRootCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		Use: "idsec",
		Version: fmt.Sprintf(
			"Version: %s\nBuild Number: %s\nBuild Date: %s\nGit Commit: %s\nGit Branch: %s",
			config.IdsecVersion(),
			config.IdsecBuildNumber(),
			config.IdsecBuildDate(),
			config.IdsecGitCommit(),
			config.IdsecGitBranch(),
		),
		Short: "Idsec CLI",
		Args:  cobra.ArbitraryArgs,
	}
	rootCmd.SetVersionTemplate("{{.Version}}\n")
	// Silence usage so we can show our custom help with services in error handler
	rootCmd.SilenceUsage = true
	// Silence errors so Cobra doesn't print them before our error handler can reroute
	rootCmd.SilenceErrors = true
	return rootCmd
}

// registerActions creates and registers all available actions with the root command.
func registerActions(rootCmd *cobra.Command, profilesLoader *profiles.ProfileLoader) {
	idsecActions := []actions.IdsecAction{
		actions.NewIdsecProfilesAction(profilesLoader),
		actions.NewIdsecCacheAction(),
		actions.NewIdsecConfigureAction(profilesLoader),
		actions.NewIdsecLoginAction(profilesLoader),
		actions.NewIdsecServiceExecAction(profilesLoader),
		actions.NewIdsecUpgradeAction(),
		k8sactions.NewIdsecKubectlLoginAction(profilesLoader),
		k8sactions.NewIdsecGenerateKubeconfigAction(profilesLoader),
	}

	for _, action := range idsecActions {
		action.DefineAction(rootCmd)
	}
}

// setupCustomHelp extends the help function to include available services from exec command.
func setupCustomHelp(rootCmd *cobra.Command) {
	originalHelpFunc := rootCmd.HelpFunc()
	rootCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		// Call the original help function
		originalHelpFunc(cmd, args)

		// Only append available services information for the root command, not for subcommands
		// Check if this is the root command by checking if it has no parent or is the root itself
		if cmd.Parent() == nil || cmd == rootCmd {
			execCmd, _, err := cmd.Find([]string{"exec"})
			if err == nil && execCmd != nil {
				if execCmd.HasAvailableLocalFlags() {
					fmt.Println("\nGlobal Flags:")
					fmt.Print(execCmd.LocalFlags().FlagUsages())
				}

				if len(execCmd.Commands()) > 0 {
					fmt.Println("\nAvailable services (use 'idsec <service>' or 'idsec exec <service>'):")
					for _, serviceCmd := range execCmd.Commands() {
						description := serviceCmd.Short
						if description == "" {
							description = serviceCmd.Long
						}
						fmt.Printf("  %-15s %s\n", serviceCmd.Name(), description)
					}
				}
			}
		}
	})
}

// isKnownSubcommand checks if the given argument matches a known subcommand or its alias.
func isKnownSubcommand(cmd *cobra.Command, arg string) bool {
	for _, subCmd := range cmd.Commands() {
		if subCmd.Name() == arg || slices.Contains(subCmd.Aliases, arg) {
			return true
		}
	}
	return false
}

// routeToExec modifies os.Args to prepend "exec" and re-executes the command.
func routeToExec(cmd *cobra.Command) error {
	// Save original args
	originalArgs := make([]string, len(os.Args))
	copy(originalArgs, os.Args)

	// Create new args with "exec" inserted after the program name
	// os.Args[0] is the program name, os.Args[1:] are the remaining args
	newArgs := append([]string{os.Args[0], "exec"}, os.Args[1:]...)
	os.Args = newArgs

	// Temporarily clear the Run function to prevent infinite recursion
	// when we re-execute rootCmd
	originalRun := cmd.Run
	cmd.Run = nil

	// Re-execute rootCmd - this time it will find "exec" as a subcommand
	// and route to it with the remaining arguments
	err := cmd.Execute()

	// Restore original Run function and args (though we're about to exit)
	cmd.Run = originalRun
	os.Args = originalArgs

	return err
}

// setupDefaultRouting sets up the Run function to handle default routing to exec command.
func setupDefaultRouting(rootCmd *cobra.Command) {
	rootCmd.Run = func(cmd *cobra.Command, args []string) {
		// If no arguments provided, show help
		if len(args) == 0 {
			_ = cmd.Help()
			return
		}

		// Check if the first argument matches a known subcommand
		firstArg := args[0]
		if !isKnownSubcommand(cmd, firstArg) {
			// If NOT a known subcommand, route to exec
			// (If it was a known subcommand, Cobra would have matched it and we wouldn't be here)
			if err := routeToExec(cmd); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		}
	}
}

// isRootCommandError checks if the error is related to the root command (not a subcommand).
func isRootCommandError(rootCmd *cobra.Command) bool {
	if len(os.Args) <= 1 {
		return true
	}

	firstArg := os.Args[1]
	return !isKnownSubcommand(rootCmd, firstArg)
}

// shouldShowHelpForError checks if help should be shown for the given error.
func shouldShowHelpForError(errStr string) bool {
	errLower := strings.ToLower(errStr)
	return strings.Contains(errLower, "unknown command") ||
		strings.Contains(errLower, "unknown flag") ||
		strings.Contains(errLower, "required") ||
		strings.Contains(errLower, "invalid") ||
		strings.Contains(errLower, "usage")
}

// handleCommandExecution executes the root command and handles errors, including routing unknown commands to exec.
func handleCommandExecution(rootCmd *cobra.Command) {
	if err := rootCmd.Execute(); err != nil {
		errStr := err.Error()

		// Check if this is an "unknown command" or "unknown flag" error that should be routed to exec
		if len(os.Args) > 1 {
			firstArg := os.Args[1]
			if !isKnownSubcommand(rootCmd, firstArg) && (strings.Contains(errStr, "unknown command") || strings.Contains(errStr, "unknown flag")) {
				// Modify os.Args to prepend "exec"
				newArgs := append([]string{os.Args[0], "exec"}, os.Args[1:]...)
				os.Args = newArgs

				// Clear Run function to prevent recursion
				rootCmd.Run = nil

				// Re-execute with exec prepended
				if retryErr := rootCmd.Execute(); retryErr != nil {
					fmt.Println(retryErr)
					os.Exit(1)
				}
				return
			}
		}

		// Show help for root command usage errors to include available services
		// This helps users see available services when they make a mistake
		if isRootCommandError(rootCmd) && shouldShowHelpForError(errStr) {
			// Show our custom help with services section
			_ = rootCmd.Help()
			fmt.Println()
		}
		fmt.Println(err)
		os.Exit(1)
	}
}
