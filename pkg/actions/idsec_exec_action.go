// Package actions provides base implementation for CLI exec actions in the IDSEC SDK.
//
// This package contains the core functionality for defining and executing CLI commands
// that integrate with various authentication providers and profiles.
package actions

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/cyberark/idsec-cli-golang/internal/featureadoption"
	"github.com/cyberark/idsec-cli-golang/pkg/agentmode"
	"github.com/cyberark/idsec-cli-golang/pkg/common/args"
	"github.com/cyberark/idsec-sdk-golang/pkg/config"

	"github.com/cyberark/idsec-cli-golang/pkg/cli"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authcommon "github.com/cyberark/idsec-sdk-golang/pkg/auth/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/models"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/profiles"
)

// IdsecExecAction defines the interface for executing CLI actions in the IDSEC SDK.
//
// Implementations of this interface provide the actual command definition and execution logic
// for specific IDSEC SDK operations. The interface enables pluggable action implementations
// while maintaining consistent command structure and behavior.
type IdsecExecAction interface {
	// DefineExecAction configures the specific exec command structure and flags.
	//
	// This method is called during command initialization to set up the CLI command
	// structure, including any subcommands, flags, and help text specific to the action.
	//
	// Parameters:
	//   - cmd: The parent cobra command to which the exec action will be added
	//
	// Returns an error if the command definition fails.
	DefineExecAction(cmd *cobra.Command) error

	// RunExecAction executes the specific action logic with an authenticated API client.
	//
	// This method is called after authentication and profile loading are complete.
	// It receives a fully configured CLI API client and should implement the actual
	// business logic for the specific action.
	//
	// Parameters:
	//   - api: Authenticated IDSEC CLI API client
	//   - cmd: The root command being executed
	//   - execCmd: The specific exec command being run
	//   - args: Command line arguments passed to the action
	//
	// Returns an error if the action execution fails.
	RunExecAction(api *cli.IdsecCLIAPI, cmd *cobra.Command, execCmd *cobra.Command, args []string) error
}

// IdsecBaseExecAction provides a base implementation for IDSEC CLI exec actions.
//
// This struct serves as a foundation for implementing specific exec actions by combining
// the common IDSEC action functionality with exec-specific behavior. It handles profile
// loading, authentication, and action execution orchestration.
//
// The struct embeds IdsecBaseAction to inherit common CLI functionality and adds
// exec-specific capabilities like profile management and action delegation.
type IdsecBaseExecAction struct {
	*IdsecBaseAction
	profilesLoader *profiles.ProfileLoader
	execAction     *IdsecExecAction
	logger         *common.IdsecLogger
	cliContextTags map[string]string
}

// NewIdsecBaseExecAction creates a new instance of IdsecBaseExecAction with the specified configuration.
//
// NewIdsecBaseExecAction initializes a base exec action with the provided action implementation,
// name for logging, and profile loader. The returned instance can be used to define
// and execute CLI commands that require profile-based authentication. The constructor
// sets up logging with the specified name and configures all necessary dependencies
// for command execution.
//
// Parameters:
//   - execAction: Implementation of the specific exec action behavior
//   - name: Identifier used for logging and error reporting
//   - profilesLoader: Service for loading and managing authentication profiles
//
// Returns a configured IdsecBaseExecAction ready for command definition and execution.
//
// Example:
//
//	action := NewIdsecBaseExecAction(
//	    &myExecAction,
//	    "my-action",
//	    profileLoader,
//	)
//	action.DefineAction(rootCmd)
func NewIdsecBaseExecAction(execAction *IdsecExecAction, name string, profilesLoader *profiles.ProfileLoader) *IdsecBaseExecAction {
	return &IdsecBaseExecAction{
		IdsecBaseAction: NewIdsecBaseAction(),
		profilesLoader:  profilesLoader,
		execAction:      execAction,
		logger:          common.GetLogger(name, common.Unknown),
	}
}

// DefineAction defines the CLI `exec` command structure and configuration.
//
// DefineAction creates and configures the `exec` subcommand with all necessary flags
// and execution behavior. It sets up the command hierarchy, adds persistent flags
// for profile management and execution control, and delegates specific action
// definition to the embedded exec action implementation.
//
// The method configures the following persistent flags:
//   - profile-name: Specifies which authentication profile to use
//   - output-path: Optional file path for writing command output
//   - request-file: Optional file containing action parameters
//   - retry-count: Number of retry attempts for failed executions
//   - refresh-auth: Forces authentication token refresh
//   - page-size: Items per page for interactive paging, pausing between pages (0 = disabled)
//   - dry-run: Print the resolved action plan as JSON without authenticating or executing
//
// Parameters:
//   - cmd: The parent cobra command to which the exec command will be added
//
// The method panics if the embedded exec action fails to define its specific behavior.
//
// Example:
//
//	baseAction := NewIdsecBaseExecAction(&myAction, "test", loader)
//	baseAction.DefineAction(rootCmd)
func (a *IdsecBaseExecAction) DefineAction(cmd *cobra.Command) {
	execCmd := &cobra.Command{
		Use:   "exec",
		Short: "Exec an action",
	}
	execCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		a.CommonActionsExecution(cmd, args, true)
	}
	a.CommonActionsConfiguration(execCmd)

	execCmd.PersistentFlags().String("profile-name", profiles.DefaultProfileName(), "Profile name to load")
	execCmd.PersistentFlags().String("output-path", "", "Output file to write data to")
	execCmd.PersistentFlags().String("request-file", "", "Request file containing the parameters for the exec action")
	execCmd.PersistentFlags().Int("retry-count", 1, "Retry count for execution")
	execCmd.PersistentFlags().Bool("refresh-auth", true, "If a cache exists, will also try to refresh it")
	execCmd.PersistentFlags().Int("page-size", 0, "Show N items per page in interactive output, pausing between pages (0 = disabled)")
	execCmd.PersistentFlags().String("format", "auto", "Output format: auto (service-defined formatter when available, otherwise JSON) or json (always JSON)")
	execCmd.PersistentFlags().Bool("dry-run", false, "Print the action, operation, resolved arguments, and secret fields as JSON without authenticating or executing")
	execCmd.PersistentFlags().String("query", "", "jq expression applied to the JSON output (e.g. '.name', '.[] | select(.active)')")
	registerQueryVarFlags(execCmd.PersistentFlags())
	err := (*a.execAction).DefineExecAction(execCmd)
	if err != nil {
		args.PrintFailure(fmt.Sprintf("Error defining exec action %v", err))
		panic(err)
	}
	cmd.AddCommand(execCmd)
}

// runExecAction executes the configured action with profile-based authentication.
//
// runExecAction orchestrates the complete execution flow including profile loading,
// authentication validation, API client creation, and action execution with retry logic.
// The method performs the following steps:
//  1. Locates the exec command in the command hierarchy
//  2. Loads the specified authentication profile
//  3. Validates and loads available authenticators
//  4. Creates an authenticated CLI API client
//  5. Executes the action with configured retry logic
//
// The method handles authentication token expiration and provides user feedback
// for authentication status. If not all authenticators are available, it warns
// the user that some functionality may be disabled.
//
// Parameters:
//   - cmd: The root command being executed
//   - execArgs: Command line arguments passed to the exec action
//
// The method prints failure messages and returns ErrActionFailed if any critical
// step fails, including profile loading, authentication, API client creation, or
// the action itself (after retries). It returns nil on success.
func (a *IdsecBaseExecAction) runExecAction(cmd *cobra.Command, execArgs []string) error {
	a.CommonActionsExecution(cmd, execArgs, false)
	var execCmd *cobra.Command
	currentCmd := cmd
	for currentCmd != nil {
		if currentCmd.Use == "exec" {
			execCmd = currentCmd
			break
		}
		currentCmd = currentCmd.Parent()
	}
	if execCmd == nil {
		return reportFailure(agentmode.CodeInternalError, "Failed to find exec command", nil)
	}
	profileName, _ := execCmd.Flags().GetString("profile-name")
	deducedProfileName := profiles.DeduceProfileName(profileName)
	profile, err := (*a.profilesLoader).LoadProfile(deducedProfileName)
	if err != nil {
		return reportFailure(agentmode.CodeConfigError, profileRequiredMessage, err,
			agentmode.WithDetail("profile", deducedProfileName),
			agentmode.WithDetail("source", "profile"),
			agentmode.WithHint(hintProfileUnreadable))
	}
	if profile == nil {
		return reportFailure(agentmode.CodeProfileNotFound, profileRequiredMessage, nil,
			agentmode.WithDetail("profile", deducedProfileName),
			agentmode.WithHint(hintProfilesList),
			agentmode.WithHint(hintProfileCreate))
	}

	var authenticators []auth.IdsecAuth
	authStates := map[string]string{}
	for authenticatorName := range profile.AuthProfiles {
		authenticator := auth.SupportedAuthenticators[authenticatorName]
		refreshAuth, _ := cmd.Flags().GetBool("refresh-auth")
		token, err := loadAuthentication(authenticator, profile, refreshAuth)
		if err != nil || token == nil {
			authStates[authenticatorName] = authenticatorState(err)
			continue
		}
		if time.Now().After(time.Time(token.ExpiresIn)) {
			authStates[authenticatorName] = authStateTokenExpired
			continue
		}
		authenticators = append(authenticators, authenticator)
	}

	if len(authenticators) == 0 {
		return reportFailure(agentmode.CodeNotAuthenticated, notAuthenticatedMessage, nil,
			notAuthenticatedOptions(deducedProfileName, authStates)...)
	}
	if len(authenticators) != len(profile.AuthProfiles) {
		if config.IsInteractive() {
			args.PrintColoredStderr(partialAuthMessage, color.New())
		} else if agentmode.IsEnabled() {
			agentmode.AddWarning(partialAuthMessage)
		}
	}

	// Create the CLI API with the authenticators
	api, err := newCLIAPI(authenticators, profile)
	if err != nil {
		return reportFailure(classifiedOr(err, agentmode.CodeInternalError), fmt.Sprintf("Failed to create CLI API: %s", err), err)
	}
	reportStatus := "success"
	reportMessage := ""
	fasTags := buildCLIContextTags(cmd, execCmd)
	a.cliContextTags = fasTags
	a.cliContextTags[featureadoption.TagKeyCLIAgent] = claValue()
	defer featureadoption.ReportOperationDefer(cmd.Context(), &api.IdsecAPI, a.logger, &reportStatus, &reportMessage, fasTags)()

	// Run the actual exec fitting action with the api
	// Run it with retries as per defined by user
	retryCount, _ := execCmd.Flags().GetInt("retry-count")
	err = common.RetryCall(func() error {
		return (*a.execAction).RunExecAction(api, cmd, execCmd, execArgs)
	}, retryCount, 1, nil, 1, 0, func(err error, delay int) {
		args.PrintColoredStderr(fmt.Sprintf("Retrying in %d seconds", delay), color.New(color.FgRed))
	})

	if err != nil {
		reportStatus = "failure"
		reportMessage = err.Error()
		return reportFailure(classifiedOr(err, agentmode.CodeActionFailed), fmt.Sprintf("Failed to execute action: %s", err), err,
			agentmode.WithDetail("command", cmd.CommandPath()))
	}
	return nil
}

const (
	profileRequiredMessage  = "Please configure a profile before trying to execute actions"
	notAuthenticatedMessage = "Failed to load authenticators, tokens are either expired or authenticators are not logged in, please login first"
	partialAuthMessage      = "Not all authenticators are logged in, some of the functionality will be disabled"
)

// details.authenticators states that are not authcommon.Classify reasons.
const (
	authStateNotAuthenticated = "NOT_AUTHENTICATED"
	authStateTokenExpired     = "TOKEN_EXPIRED"
)

var (
	loadAuthentication = func(authenticator auth.IdsecAuth, profile *models.IdsecProfile, refreshAuth bool) (*authmodels.IdsecToken, error) {
		return authenticator.LoadAuthentication(profile, refreshAuth)
	}
	newCLIAPI = cli.NewIdsecCLIAPI
)

// authenticatorState is the details.authenticators state for an authenticator
// that has no usable token.
func authenticatorState(loadErr error) string {
	if reason, ok := authcommon.Classify(loadErr); ok {
		return string(reason)
	}
	return authStateNotAuthenticated
}

// notAuthenticatedOptions builds the NOT_AUTHENTICATED details and hints. When
// every authenticator failed with the same Classify reason, that reason's hint
// comes first. states keys are supported-authenticator keys.
func notAuthenticatedOptions(profileName string, states map[string]string) []agentmode.FailureOption {
	opts := []agentmode.FailureOption{
		agentmode.WithDetail("profile", profileName),
		agentmode.WithDetail("authenticators", states),
	}
	names := make([]string, 0, len(states))
	shared := ""
	for name, state := range states {
		names = append(names, name)
		if len(names) == 1 {
			shared = state
		} else if state != shared {
			shared = ""
		}
	}
	if shared != "" {
		opts = append(opts, withDefaultHints(agentmode.Code(shared)))
	}
	sort.Strings(names)
	for _, name := range names {
		opts = append(opts, agentmode.WithHint(loginHint(name)))
	}
	return opts
}

// buildCLIContextTags extracts CLI context and returns compact FAS tags:
//   - cls: CLI service (e.g. pcloud)
//   - clo: operation (leaf command, e.g. create)
//   - clv: CLI version
//   - clr: resource path between service and operation, joined by '-'
//     (e.g. safes, accounts-members)
//
// The function walks from the leaf command upward, stopping before the stopCmd
// or the root. It also skips the "exec" and root ("idsec") segments so the
// result is stable regardless of whether the user typed "exec" explicitly.
func buildCLIContextTags(cmd *cobra.Command, stopCmd *cobra.Command) map[string]string {
	skip := map[string]bool{"exec": true, "idsec": true}
	var parts []string
	for c := cmd; c != nil && c != stopCmd; c = c.Parent() {
		if !skip[c.Name()] {
			parts = append([]string{c.Name()}, parts...)
		}
	}

	tags := map[string]string{
		featureadoption.TagKeyCLIVersion: cliVersion(),
	}
	if len(parts) > 0 {
		tags[featureadoption.TagKeyCLIService] = parts[0]
		tags[featureadoption.TagKeyCLIOperation] = parts[len(parts)-1]
	}
	if len(parts) > 2 {
		tags[featureadoption.TagKeyCLIResource] = strings.Join(parts[1:len(parts)-1], "-")
	}
	return tags
}

// cliVersion returns the release version for FAS tag clv (config.IdsecVersion() / ldflags).
// Local `go build` without ldflags may show the SDK default (e.g. 0.0.0).
func cliVersion() string {
	return string(config.IdsecVersion())
}

// claValue returns the cla tag value for the current invocation.
// It mirrors the logic in internal/featureadoption.buildTags so that the
// X-Cybr-Telemetry header and the FAS report always carry the same value.
func claValue() string {
	if agentmode.IsEnabled() {
		if slug := agentmode.DetectedAgent(); slug != "" {
			return slug
		}
		return featureadoption.AgentUnknownSlug
	}
	return featureadoption.AgentHumanSlug
}

// cliContextFullName maps a FAS short tag key to its descriptive long name for
// use as the human-readable field name in the X-Cybr-Telemetry extra context.
func cliContextFullName(shortKey string) string {
	switch shortKey {
	case featureadoption.TagKeyCLIService:
		return "cli_service"
	case featureadoption.TagKeyCLIOperation:
		return "cli_operation"
	case featureadoption.TagKeyCLIResource:
		return "cli_resource"
	case featureadoption.TagKeyCLIVersion:
		return "cli_version"
	case featureadoption.TagKeyCLIAgent:
		return "cli_agent"
	default:
		return "cli_" + shortKey
	}
}
