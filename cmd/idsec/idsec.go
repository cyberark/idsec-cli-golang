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
//	idsec version
//	idsec profiles list
//	idsec login
//	idsec configure
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/cyberark/idsec-sdk-golang/pkg/config"

	"github.com/cyberark/idsec-cli-golang/pkg/actions"
	"github.com/cyberark/idsec-cli-golang/pkg/agentmode"
	cliconfig "github.com/cyberark/idsec-cli-golang/pkg/config"
	_ "github.com/cyberark/idsec-cli-golang/pkg/registry"
	k8sactions "github.com/cyberark/idsec-cli-golang/pkg/services/sca/k8s/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/profiles"
)

// main is the entry point for the Idsec CLI application.
//
// This function initializes the Cobra root command,
// creates a profiles
// loader, and registers all available actions (version, profiles, cache, configure,
// login, and service execution) with the root command.
//
// The function handles command execution and exits with code 1 if an error
// occurs during command execution.
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
//   - version: Print the Idsec CLI version
//
// The function will call os.Exit(1) if command execution fails.
func main() {
	defer actions.RecoverFromPanic()

	configPath := cliconfig.ResolveConfigFilePath(cliconfig.ExtractConfigFlag())
	cliconfig.LoadConfigFile(configPath)
	// Before registerActions: registration can panic, and that report must
	// already know whether agent mode is on.
	agentmode.ResolveFromArgs(os.Args[1:])

	config.SetIdsecToolInUse(config.IdsecToolCLI)
	profilesLoader := profiles.DefaultProfilesLoader()

	rootCmd := createRootCommand()
	registerActions(rootCmd, profilesLoader)
	setupCustomHelp(rootCmd)
	// Force Cobra to register its built-in "help" and "completion" subcommands
	// before validateCommandPathBeforeExecution runs. Without this, those
	// commands aren't in cmd.Commands() yet and get mistakenly routed to exec.
	rootCmd.InitDefaultHelpCmd()
	rootCmd.InitDefaultCompletionCmd()
	// Register transparent exec aliases on the root so that tab-completion
	// works for the "idsec <service> ..." shorthand in addition to the
	// explicit "idsec exec <service> ..." form.
	setupTransparentExecCompletion(rootCmd)
	setupDefaultRouting(rootCmd)
	rerouteHelpToExecIfNeeded(rootCmd)
	handleCommandExecution(rootCmd)
}

// createRootCommand creates and configures the root Cobra command.
func createRootCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "idsec",
		Short: "Idsec CLI",
		Args:  cobra.ArbitraryArgs,
	}
	rootCmd.PersistentFlags().String("config", "", "Path to configuration file (default ~/.idsec/config.yaml)")
	// Silence usage so we can show our custom help with services in error handler
	rootCmd.SilenceUsage = true
	// Silence errors so Cobra doesn't print them before our error handler can reroute
	rootCmd.SilenceErrors = true
	rootCmd.SetFlagErrorFunc(actions.FlagError)
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
		actions.NewIdsecStatusAction(profilesLoader),
		actions.NewIdsecQueryAction(),
		actions.NewIdsecUpgradeAction(),
		k8sactions.NewIdsecKubectlLoginAction(profilesLoader),
		k8sactions.NewIdsecGenerateKubeconfigAction(profilesLoader),
		actions.NewIdsecVersionAction(),
	}

	for _, action := range idsecActions {
		action.DefineAction(rootCmd)
	}
}

// setupCustomHelp extends the root help to show exec's global flags (profile-name,
// output-path, etc.) which are persistent on the exec command rather than on root.
// The available-services list is no longer printed here because
// setupTransparentExecCompletion registers each service as a root-level command
// in its own labelled group, so Cobra's built-in help already shows them.
func setupCustomHelp(rootCmd *cobra.Command) {
	originalHelpFunc := rootCmd.HelpFunc()
	rootCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		// Call the original help function
		originalHelpFunc(cmd, args)

		// Only append exec global flags for the root command, not for subcommands.
		if cmd.Parent() == nil || cmd == rootCmd {
			execCmd, _, err := cmd.Find([]string{"exec"})
			if err == nil && execCmd != nil && execCmd.HasAvailableLocalFlags() {
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), "\nGlobal Flags:")
				_, _ = fmt.Fprint(cmd.OutOrStdout(), execCmd.LocalFlags().FlagUsages())
			}
		}
	})
}

// execServiceGroupID is the Cobra group ID used to label transparent exec aliases in help.
const execServiceGroupID = "services"

// setupTransparentExecCompletion mirrors every service command that lives under
// "exec" as a top-level root command so that tab-completion works for the
// shorthand "idsec <service> ..." form in addition to "idsec exec <service> ...".
//
// Each mirrored command:
//   - Is non-hidden so Cobra includes it in shell completions.
//   - Belongs to the "services" group so it appears under its own labelled
//     section in `idsec help` rather than mixed into "Available Commands".
//   - Carries the same flags as the exec counterpart (leaf nodes only) so that
//     flag-level completion (e.g. --profile-name) also works.
//   - Has a RunE that re-inserts "exec" into os.Args and re-runs the root
//     command, preserving the full exec execution path (auth, retries, etc.).
func setupTransparentExecCompletion(rootCmd *cobra.Command) {
	execCmd := findSubcommand(rootCmd, "exec")
	if execCmd == nil {
		return
	}
	rootCmd.AddGroup(&cobra.Group{
		ID:    execServiceGroupID,
		Title: "Available Services (use 'idsec <service>' or 'idsec exec <service>'):",
	})
	for _, svcCmd := range execCmd.Commands() {
		alias := buildExecAlias(svcCmd, rootCmd)
		alias.GroupID = execServiceGroupID
		rootCmd.AddCommand(alias)
	}
}

// buildExecAlias recursively clones a command subtree from exec for use as a
// transparent root-level alias. Leaf commands get a RunE that routes execution
// back through exec so the full exec lifecycle (auth, profile, retries) runs.
//
// Schema flags are copied from the exec counterpart so that flag-level
// tab-completion (e.g. --safe-name, --description) works on the shorthand form.
// FParseErrWhitelist.UnknownFlags=true lets Cobra silently ignore exec's
// persistent flags (--profile-name, --dry-run, etc.) that are not registered
// on the phantom command — they are forwarded correctly through os.Args anyway.
func buildExecAlias(src *cobra.Command, rootCmd *cobra.Command) *cobra.Command {
	dst := &cobra.Command{
		Use:     src.Use,
		Aliases: src.Aliases,
		Short:   src.Short,
		Long:    src.Long,
	}

	if !src.HasSubCommands() {
		// Leaf: copy schema flags so Cobra can offer them in tab-completion.
		dst.Flags().AddFlagSet(src.Flags())
		// Silently ignore exec persistent flags (profile-name, dry-run, …)
		// that aren't registered here; they are passed through via os.Args.
		dst.FParseErrWhitelist = cobra.FParseErrWhitelist{UnknownFlags: true}

		capturedRoot := rootCmd
		dst.RunE = func(_ *cobra.Command, _ []string) error {
			// Re-insert "exec" after the program name so the real exec command
			// tree handles authentication, profile loading and retry logic.
			original := make([]string, len(os.Args))
			copy(original, os.Args)
			defer func() { os.Args = original }()

			os.Args = append([]string{os.Args[0], "exec"}, os.Args[1:]...)
			// Temporarily clear root's Run so that it doesn't trigger the
			// default-routing fallback and cause infinite recursion.
			savedRun := capturedRoot.Run
			capturedRoot.Run = nil
			err := capturedRoot.Execute()
			capturedRoot.Run = savedRun
			return err
		}
	}

	for _, child := range src.Commands() {
		dst.AddCommand(buildExecAlias(child, rootCmd))
	}
	return dst
}

// isKnownSubcommand checks if the given argument matches a known subcommand or its alias.
// Args with a "__" prefix are always treated as known because they are Cobra's internal
// commands (e.g. __complete, __completeNoDesc) that are registered lazily inside Execute().
func isKnownSubcommand(cmd *cobra.Command, arg string) bool {
	if strings.HasPrefix(arg, "__") {
		return true
	}
	return findSubcommand(cmd, arg) != nil
}

// hasHelpFlag returns true when args include any help flag form.
func hasHelpFlag(args []string) bool {
	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			return true
		}
		if strings.HasPrefix(arg, "--help=") {
			value := strings.TrimPrefix(arg, "--help=")
			if enabled, err := strconv.ParseBool(value); err == nil && enabled {
				return true
			}
		}
	}
	return false
}

// firstPositionalArg returns the first non-flag arg while skipping values consumed
// by root-level flags that can appear before a command path.
func firstPositionalArg(args []string) string {
	skipNextValue := false
	for _, arg := range args {
		if skipNextValue {
			skipNextValue = false
			continue
		}

		// "--" means the rest are positional arguments.
		if arg == "--" {
			return ""
		}

		if strings.HasPrefix(arg, "-") {
			if arg == "--config" {
				skipNextValue = true
			}
			continue
		}

		return arg
	}

	return ""
}

// rerouteHelpToExecIfNeeded makes "idsec <service> ... --help" behave like
// "idsec exec <service> ... --help" by prepending "exec" before command execution.
func rerouteHelpToExecIfNeeded(rootCmd *cobra.Command) {
	if len(os.Args) <= 1 || !hasHelpFlag(os.Args[1:]) {
		return
	}

	serviceOrCmd := firstPositionalArg(os.Args[1:])
	if serviceOrCmd == "" || isKnownSubcommand(rootCmd, serviceOrCmd) {
		return
	}

	os.Args = append([]string{os.Args[0], "exec"}, os.Args[1:]...)
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
				exitWithError(cmd, err, false)
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

func findSubcommand(cmd *cobra.Command, name string) *cobra.Command {
	for _, subCmd := range cmd.Commands() {
		if subCmd.Name() == name || slices.Contains(subCmd.Aliases, name) {
			return subCmd
		}
	}
	return nil
}

func parseFlagToken(flagToken string) (string, bool) {
	trimmed := strings.TrimLeft(flagToken, "-")
	if trimmed == "" {
		return "", false
	}
	if idx := strings.Index(trimmed, "="); idx >= 0 {
		return trimmed[:idx], true
	}
	return trimmed, false
}

func commandAcceptsFlagValue(cmd *cobra.Command, flagName string) bool {
	flag := cmd.Flags().Lookup(flagName)
	if flag == nil {
		flag = cmd.InheritedFlags().Lookup(flagName)
	}
	if flag == nil {
		return false
	}
	return flag.Value.Type() != "bool"
}

// findUnknownCommandInArgs walks argv tokens and returns the first unmatched
// positional token (or "") plus the last matched command. afterUnknownFlag
// reports that the token directly follows a flag the matched command doesn't
// define, so it may be that flag's value rather than a mistyped command.
func findUnknownCommandInArgs(rootCmd *cobra.Command, argv []string) (token string, last *cobra.Command, afterUnknownFlag bool) {
	current := rootCmd
	for i := 0; i < len(argv); i++ {
		token := argv[i]
		if token == "--" {
			break
		}

		if strings.HasPrefix(token, "-") {
			flagName, hasInlineValue := parseFlagToken(token)
			afterUnknownFlag = flagName != "" && !hasInlineValue && !commandDefinesFlag(current, flagName)
			if flagName != "" && !hasInlineValue && commandAcceptsFlagValue(current, flagName) && i+1 < len(argv) {
				i++
			}
			continue
		}

		next := findSubcommand(current, token)
		if next == nil {
			return token, current, afterUnknownFlag
		}
		afterUnknownFlag = false
		current = next
		// Leaf commands (no subcommands) handle all remaining tokens themselves
		// as flags and positional args. Stop traversal here to avoid
		// mis-classifying flag values (e.g. "--profile-name dudu") as unknown
		// subcommands when the flag is not registered on the phantom command.
		if !current.HasSubCommands() {
			break
		}
	}
	return "", current, false
}

// commandDefinesFlag reports whether cmd defines flagName, locally or inherited.
func commandDefinesFlag(cmd *cobra.Command, flagName string) bool {
	return cmd.Flags().Lookup(flagName) != nil || cmd.InheritedFlags().Lookup(flagName) != nil
}

func validateCommandPathBeforeExecution(rootCmd *cobra.Command) error {
	var argv []string
	if len(os.Args) > 1 {
		argv = os.Args[1:]
	}
	firstArg := firstPositionalArg(argv)
	if firstArg == "" {
		if agentmode.IsEnabled() && !hasHelpFlag(argv) && !hasUndefinedFlag(rootCmd, argv) {
			return actions.IncompleteCommandFailure(rootCmd)
		}
		return nil
	}

	// Cobra's internal shell-completion commands (e.g. __complete, __completeNoDesc)
	// are registered lazily inside Execute(), so they are never present in
	// cmd.Commands() at this point. Skip pre-validation for them entirely.
	if strings.HasPrefix(firstArg, "__") {
		return nil
	}

	// Shorthand service routing ("idsec <service> ...") should validate the path
	// under exec before command execution, otherwise Cobra may print exec help.
	validationArgs := argv
	if !isKnownSubcommand(rootCmd, firstArg) {
		validationArgs = append([]string{"exec"}, argv...)
	}

	unknownToken, last, mayBeFlagValue := findUnknownCommandInArgs(rootCmd, validationArgs)
	if unknownToken != "" {
		return actions.UnknownCommandFailure(unknownToken, last, mayBeFlagValue)
	}
	// Human mode keeps Cobra's help-and-exit-0 for group commands.
	if agentmode.IsEnabled() && last.HasSubCommands() && !last.Runnable() && !hasHelpFlag(argv) &&
		!hasUndefinedFlag(last, validationArgs) {
		return actions.IncompleteCommandFailure(last)
	}
	return nil
}

// hasUndefinedFlag reports whether argv holds a flag that cmd doesn't define,
// so that Cobra's flag error is reported instead of an incomplete command.
// --agent and --no-agent are resolved from argv before Cobra runs.
func hasUndefinedFlag(cmd *cobra.Command, argv []string) bool {
	for i := 0; i < len(argv); i++ {
		token := argv[i]
		if token == "--" {
			return false
		}
		if !strings.HasPrefix(token, "-") || token == "-" {
			continue
		}
		name, hasInlineValue := parseFlagToken(token)
		if name == "agent" || name == "no-agent" {
			continue
		}
		flag := lookupDefinedFlag(cmd, token, name)
		if flag == nil {
			return true
		}
		inlineValue := hasInlineValue || (!strings.HasPrefix(token, "--") && len(name) > 1)
		if !inlineValue && flag.NoOptDefVal == "" {
			i++
		}
	}
	return false
}

// lookupDefinedFlag finds the flag token names among cmd's local, own
// persistent and inherited flags. Before Execute, Cobra hasn't merged a
// command's own persistent flags into Flags(). For a single-dash token only
// its first letter names a (shorthand) flag.
func lookupDefinedFlag(cmd *cobra.Command, token, name string) *pflag.Flag {
	if name == "" {
		return nil
	}
	for _, fs := range []*pflag.FlagSet{cmd.Flags(), cmd.PersistentFlags(), cmd.InheritedFlags()} {
		var flag *pflag.Flag
		if strings.HasPrefix(token, "--") {
			flag = fs.Lookup(name)
		} else {
			flag = fs.ShorthandLookup(name[:1])
		}
		if flag != nil {
			return flag
		}
	}
	return nil
}

var osExit = os.Exit

// exitWithError reports err exactly once and terminates the process.
// showHelp preserves today's root-help dump for human mode at the final site only.
func exitWithError(rootCmd *cobra.Command, err error, showHelp bool) {
	osExit(reportError(rootCmd, err, showHelp, os.Stdout, os.Stderr))
}

// reportError writes err's report and returns the process exit code. An
// *actions.ExitCodeError was already reported by the action that returned it.
func reportError(rootCmd *cobra.Command, err error, showHelp bool, stdout, stderr io.Writer) int {
	code := 1
	var exitErr *actions.ExitCodeError
	reported := errors.As(err, &exitErr)
	if reported {
		code = exitErr.Code
		if exitErr.Quiet {
			return code
		}
	}
	if agentmode.IsEnabled() {
		if !reported {
			_, _ = fmt.Fprintln(stderr, err)
		}
		actions.WriteErrorEnvelope(stdout, err)
		return code
	}
	if reported {
		return code
	}
	if showHelp {
		reportCommandError(rootCmd, err, stderr)
	} else {
		_, _ = fmt.Fprintln(stderr, err)
	}
	return code
}

// handleCommandExecution executes the root command and handles errors, including routing unknown commands to exec.
func handleCommandExecution(rootCmd *cobra.Command) {
	if validationErr := validateCommandPathBeforeExecution(rootCmd); validationErr != nil {
		exitWithError(rootCmd, validationErr, false)
		return
	}

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
					exitWithError(rootCmd, retryErr, false)
				}
				return
			}
		}

		exitWithError(rootCmd, err, true)
	}
}

// reportCommandError writes err to w. For root command usage errors it first
// writes the root help (which lists the available services) and a blank line,
// so the help and the error it explains always share a stream.
func reportCommandError(rootCmd *cobra.Command, err error, w io.Writer) {
	if isRootCommandError(rootCmd) && shouldShowHelpForError(err.Error()) {
		originalOut := rootCmd.OutOrStdout()
		rootCmd.SetOut(w)
		_ = rootCmd.Help()
		rootCmd.SetOut(originalOut)
		_, _ = fmt.Fprintln(w)
	}
	_, _ = fmt.Fprintln(w, err)
}
