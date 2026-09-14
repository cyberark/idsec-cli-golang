package actions

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/cyberark/idsec-cli-golang/pkg/common/args"
	"github.com/cyberark/idsec-cli-golang/pkg/credentials"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authcommon "github.com/cyberark/idsec-sdk-golang/pkg/auth/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth/identity"
	"github.com/cyberark/idsec-sdk-golang/pkg/config"
	"github.com/cyberark/idsec-sdk-golang/pkg/models"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/profiles"
)

// Login failure reasons emitted on the machine-readable reason line. The
// deterministic pre-flight reasons are recognized entirely CLI-side; auth-time
// reasons come from authcommon.Classify (MFA_REQUIRED, ENDPOINT_UNREACHABLE,
// KEYRING_FAILURE, CERTIFICATE_ERROR), and anything unrecognized is AUTH_FAILED.
// CONFIG_ERROR covers a malformed environment or credentials file, i.e. a
// problem with the inputs rather than with the credentials themselves.
const (
	loginReasonProfileNotFound  = "PROFILE_NOT_FOUND"
	loginReasonUsernameRequired = "USERNAME_REQUIRED"
	loginReasonSecretRequired   = "SECRET_REQUIRED"
	loginReasonConfigError      = "CONFIG_ERROR"
	loginReasonAuthFailed       = "AUTH_FAILED"
)

// loginFailure prints a stable, greppable machine-readable reason line to
// stderr and returns ErrActionFailed so the process exits non-zero. The line
// format is:
//
//	idsec: login failed reason=<REASON>[ authenticator=<name>][ key=value ...]
//
// Fields are always appended after reason= so that the existing
// ${REASON_LINE#*reason=} shell parse keeps working. Consumers match on this
// line instead of parsing human error prose (which silently rots when a
// message is reworded). The human-readable failure has already been printed
// via args.PrintFailure before this is called.
func loginFailure(reason, authenticator string, extra ...string) error {
	line := "idsec: login failed reason=" + reason
	if authenticator != "" {
		line += " authenticator=" + authenticator
	}
	for _, kv := range extra {
		line += " " + kv
	}
	fmt.Fprintln(os.Stderr, line)
	return ErrActionFailed
}

// IdsecLoginAction is a struct that implements the IdsecAction interface for login action.
//
// IdsecLoginAction provides authentication functionality for the Idsec SDK CLI.
// It handles user authentication across multiple authentication methods and
// manages token storage and retrieval. The action supports interactive and
// non-interactive modes, shared secrets between authenticators, token refresh,
// and forced re-authentication.
//
// Key features:
//   - Multi-authenticator support (e.g., ISP, identity providers)
//   - Interactive credential prompting with shared secrets
//   - Token caching and refresh capabilities
//   - Force login and token display options
//   - Profile-based configuration management
type IdsecLoginAction struct {
	*IdsecBaseAction
	profilesLoader *profiles.ProfileLoader
}

// NewIdsecLoginAction creates a new instance of IdsecLoginAction.
//
// NewIdsecLoginAction initializes a new IdsecLoginAction with the provided profile
// loader for managing authentication profiles. The action inherits common
// functionality from IdsecBaseAction and configures profile-specific behavior.
//
// Parameters:
//   - profilesLoader: A ProfileLoader interface for loading and managing authentication profiles
//
// Returns a new IdsecLoginAction instance ready for CLI integration.
//
// Example:
//
//	loader := profiles.DefaultProfilesLoader()
//	action := NewIdsecLoginAction(loader)
//	action.DefineAction(rootCmd)
func NewIdsecLoginAction(profilesLoader *profiles.ProfileLoader) *IdsecLoginAction {
	return &IdsecLoginAction{
		IdsecBaseAction: NewIdsecBaseAction(),
		profilesLoader:  profilesLoader,
	}
}

// DefineAction defines the CLI `login` action, and adds the login function.
//
// DefineAction configures the login command with all necessary flags and
// behavior for authentication operations. The command supports various
// authentication options including profile selection, forced login,
// shared secrets management, token display, and refresh capabilities.
//
// Command flags added:
//   - profile-name: Specifies which profile to use for authentication
//   - force: Forces login even if valid tokens exist
//   - no-shared-secrets: Disables credential sharing between authenticators
//   - show-tokens: Displays authentication tokens in output
//   - refresh-auth: Attempts to refresh existing tokens from cache
//   - [authenticator]-username: Username for specific authenticators
//   - [authenticator]-secret: Secret/password for specific authenticators
//
// Parameters:
//   - cmd: The parent cobra command to attach the login command to
//
// The login command will be added as a subcommand with all configured flags
// and will execute the authentication workflow when invoked.
//
// Example:
//
//	action := NewIdsecLoginAction(loader)
//	action.DefineAction(rootCmd)
//	// Now 'idsec login' command is available
func (a *IdsecLoginAction) DefineAction(cmd *cobra.Command) {
	loginCmd := &cobra.Command{
		Use:   "login",
		Short: "Login to the system",
		RunE:  a.runLoginAction,
	}
	loginCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		a.CommonActionsExecution(cmd, args, true)
	}
	a.CommonActionsConfiguration(loginCmd)

	loginCmd.Flags().String("profile-name", profiles.DefaultProfileName(), "Profile name to load")
	loginCmd.Flags().Bool("force", false, "Whether to force login even though token has not expired yet")
	loginCmd.Flags().Bool("no-shared-secrets", false, "Do not share secrets between different authenticators with the same username")
	loginCmd.Flags().Bool("show-tokens", false, "Print out tokens as well if not silent")
	loginCmd.Flags().Bool("refresh-auth", false, "If a cache exists, will also try to refresh it")
	loginCmd.Flags().String("credentials-file", "", "Path to an .idsecrc credentials file (INI). Overrides auto-discovery and IDSEC_CREDENTIALS_FILE")
	loginCmd.Flags().Bool("no-credentials-file", false, "Do not auto-discover an .idsecrc credentials file; only an explicit --credentials-file or IDSEC_CREDENTIALS_FILE is used")
	loginCmd.Flags().String("query", "", "jq expression to apply to the JSON token output (implies --show-tokens)")
	registerQueryVarFlags(loginCmd.Flags())

	for _, authenticator := range auth.SupportedAuthenticatorsList {
		loginCmd.Flags().String(fmt.Sprintf("%s-username", authenticator.AuthenticatorName()), "", fmt.Sprintf("Username to authenticate with to %s", authenticator.AuthenticatorHumanReadableName()))
		loginCmd.Flags().String(fmt.Sprintf("%s-secret", authenticator.AuthenticatorName()), "", fmt.Sprintf("Secret to authenticate with to %s", authenticator.AuthenticatorHumanReadableName()))
	}

	cmd.AddCommand(loginCmd)
}

// runLoginAction executes the authentication workflow for the login command.
//
// runLoginAction handles the complete authentication process including profile
// loading, credential gathering, authentication execution, and token management.
// It supports multiple authenticators simultaneously and manages shared secrets
// between compatible authentication methods.
//
// The function performs the following operations:
//  1. Loads the specified authentication profile
//  2. Iterates through configured authenticators
//  3. Checks existing authentication status and handles refresh/force options
//  4. Gathers credentials interactively or from command flags
//  5. Executes authentication for each configured authenticator
//  6. Manages shared secrets between compatible authenticators
//  7. Displays authentication results and tokens (if requested)
//
// Parameters:
//   - cmd: The cobra command containing parsed flags and configuration
//   - loginArgs: Command line arguments (currently unused)
//
// The function handles various authentication scenarios:
//   - Skip authentication if already authenticated (unless force=true)
//   - Refresh tokens if requested and possible
//   - Interactive credential prompting in interactive mode
//   - Shared secret reuse for compatible authentication methods
//   - Special handling for identity authentication without passwords
//   - Error handling and user feedback for failed authentication attempts
//
// Example:
//   Command: idsec login --profile-name prod --force --show-tokens
//   Result: Authenticates to all configured authenticators and displays tokens

func (a *IdsecLoginAction) runLoginAction(cmd *cobra.Command, loginArgs []string) error {
	a.CommonActionsExecution(cmd, loginArgs, false)

	profileName, _ := cmd.Flags().GetString("profile-name")
	profile, err := a.loadProfileWithConfigureFlow(profileName, cmd)
	if err != nil {
		args.PrintFailure(fmt.Sprintf("Failed to load or configure profile: %v", err))
		return loginFailure(loginReasonProfileNotFound, "")
	}

	credentialsFileFlag, _ := cmd.Flags().GetString("credentials-file")
	noCredentialsFile, _ := cmd.Flags().GetBool("no-credentials-file")
	credentialsFile, err := credentials.Load(credentialsFileFlag, noCredentialsFile)
	if err != nil {
		args.PrintFailure(fmt.Sprintf("Failed to load credentials file: %v", err))
		return loginFailure(loginReasonConfigError, "")
	}

	sharedSecretsMap := make(map[authmodels.IdsecAuthMethod][][2]string)
	tokensMap := make(map[string]*authmodels.IdsecToken)

	for authenticatorName, authProfile := range profile.AuthProfiles {
		authenticator := auth.SupportedAuthenticators[authenticatorName]
		force, _ := cmd.Flags().GetBool("force")
		refreshAuth, _ := cmd.Flags().GetBool("refresh-auth")
		if !force {
			if authenticator.IsAuthenticated(profile) {
				if refreshAuth {
					_, err := authenticator.LoadAuthentication(profile, true)
					if err == nil {
						args.PrintSuccess(fmt.Sprintf("%s Authentication Refreshed", authenticator.AuthenticatorHumanReadableName()))
						continue
					}
					a.logger.Info("%s Failed to refresh token, performing normal login [%s]", authenticator.AuthenticatorHumanReadableName(), err.Error())
				} else {
					args.PrintSuccess(fmt.Sprintf("%s Already Authenticated", authenticator.AuthenticatorHumanReadableName()))
					continue
				}
			}
		}
		flagSecret, _ := cmd.Flags().GetString(fmt.Sprintf("%s-secret", authenticatorName))
		flagUser, _ := cmd.Flags().GetString(fmt.Sprintf("%s-username", authenticatorName))
		envUser := credentials.EnvUsername(authenticatorName)
		envSecret, err := credentials.EnvSecret(authenticatorName)
		if err != nil {
			args.PrintFailure(fmt.Sprintf("Failed to resolve %s secret: %v", authenticatorName, err))
			return loginFailure(loginReasonConfigError, authenticatorName)
		}
		rcUser := credentialsFile.Username(profile.ProfileName, authenticatorName)
		rcSecret := credentialsFile.Secret(profile.ProfileName, authenticatorName)

		// Secret precedence for both modes: flag > env var > .idsecrc file.
		resolvedSecret, secretSource := firstNonEmptyWithSource(
			credSource{flagSecret, credSourceFlag},
			credSource{envSecret, credSourceEnv},
			credSource{rcSecret, credSourceFile},
		)
		secret := &authmodels.IdsecSecret{Secret: resolvedSecret}

		if config.IsInteractive() && slices.Contains(authmodels.IdsecAuthMethodsRequireCredentials, authProfile.AuthMethod) {
			// Username default shown in the prompt: flag > env var > .idsecrc file > profile.
			usernameDefault := firstNonEmpty(flagUser, envUser, rcUser, authProfile.Username)
			authProfile.Username, err = args.GetArg(
				cmd,
				fmt.Sprintf("%s-username", authenticatorName),
				fmt.Sprintf("%s Username", authenticator.AuthenticatorHumanReadableName()),
				usernameDefault,
				false,
				true,
				false,
			)
			if err != nil {
				args.PrintFailure(fmt.Sprintf("Failed to get %s username: %s", authenticatorName, err))
				return loginFailure(loginReasonAuthFailed, authenticatorName)
			}
			if slices.Contains(authmodels.IdsecAuthMethodSharableCredentials, authProfile.AuthMethod) && len(sharedSecretsMap[authProfile.AuthMethod]) > 0 && !viper.GetBool("no-shared-secrets") {
				for _, s := range sharedSecretsMap[authProfile.AuthMethod] {
					if s[0] == authProfile.Username {
						secret = &authmodels.IdsecSecret{Secret: s[1]}
						break
					}
				}
			} else {
				if authenticatorName == "isp" &&
					authProfile.AuthMethod == authmodels.Identity &&
					resolvedSecret == "" &&
					!identity.IsPasswordRequired(authProfile.Username,
						authProfile.AuthMethodSettings.(*authmodels.IdentityIdsecAuthMethodSettings).IdentityURL,
						authProfile.AuthMethodSettings.(*authmodels.IdentityIdsecAuthMethodSettings).IdentityTenantSubdomain) {
					secret = &authmodels.IdsecSecret{Secret: ""}
				} else {
					secretPrompt := fmt.Sprintf("%s Secret", authenticator.AuthenticatorHumanReadableName())
					if resolvedSecret != "" {
						secretPrompt = annotateSecretPrompt(secretPrompt, secretSource, authenticatorName, credentialsFile)
					}
					secretStr, err := args.GetArg(
						cmd,
						fmt.Sprintf("%s-secret", authenticatorName),
						secretPrompt,
						resolvedSecret,
						true,
						true,
						false,
					)
					if err != nil {
						args.PrintFailure(fmt.Sprintf("Failed to get %s secret: %s", authenticatorName, err))
						return loginFailure(loginReasonAuthFailed, authenticatorName)
					}
					secret = &authmodels.IdsecSecret{Secret: secretStr}
				}
			}
		} else if !config.IsInteractive() && slices.Contains(authmodels.IdsecAuthMethodsRequireCredentials, authProfile.AuthMethod) {
			// Silent username precedence: flag > env var > .idsecrc file > profile.
			effectiveUser := firstNonEmpty(flagUser, envUser, rcUser, authProfile.Username)
			if effectiveUser == "" {
				args.PrintFailure(fmt.Sprintf(
					"A username is required to authenticate to %s when running silently. Provide --%s-username, set the %s environment variable, or add %s_username to an .idsecrc file",
					authenticator.AuthenticatorHumanReadableName(),
					authenticatorName,
					credentials.EnvUsernameVar(authenticatorName),
					authenticatorName,
				))
				return loginFailure(loginReasonUsernameRequired, authenticatorName, rcAvailable(credentialsFile)...)
			}
			authProfile.Username = effectiveUser
			if secret.Secret == "" {
				args.PrintFailure(fmt.Sprintf(
					"A secret is required to authenticate to %s when running silently. Provide --%s-secret, set the %s or %s environment variable, or add %s_secret to an .idsecrc file",
					authenticator.AuthenticatorHumanReadableName(),
					authenticatorName,
					credentials.EnvSecretVar(authenticatorName),
					credentials.EnvSecretFileVar(authenticatorName),
					authenticatorName,
				))
				return loginFailure(loginReasonSecretRequired, authenticatorName, rcAvailable(credentialsFile)...)
			}
		}

		// Reaching here means we need to authenticate for sure, as we either are forced to or not authenticated yet
		token, err := authenticator.Authenticate(profile, nil, secret, true, false)
		if err != nil {
			args.PrintFailure(fmt.Sprintf("Failed to authenticate with %s: %s", authenticator.AuthenticatorHumanReadableName(), err))
			reason := loginReasonAuthFailed
			if classified, ok := authcommon.Classify(err); ok {
				reason = string(classified)
			}
			return loginFailure(reason, authenticatorName)
		}

		noSharedSecrets, _ := cmd.Flags().GetBool("no-shared-secrets")
		if !noSharedSecrets && slices.Contains(authmodels.IdsecAuthMethodSharableCredentials, authProfile.AuthMethod) {
			sharedSecretsMap[authProfile.AuthMethod] = append(sharedSecretsMap[authProfile.AuthMethod], [2]string{authProfile.Username, secret.Secret})
		}
		tokensMap[authenticator.AuthenticatorHumanReadableName()] = token
	}
	showTokens, _ := cmd.Flags().GetBool("show-tokens")
	query, _ := cmd.Flags().GetString("query")
	// --query implies --show-tokens so the expression can reach all fields.
	if query != "" {
		showTokens = true
	}

	// Build a per-authenticator map regardless of output mode so --query and
	// normal printing share the same preparation logic.
	allTokens := make(map[string]interface{}, len(tokensMap))
	for k, v := range tokensMap {
		if v.Metadata != nil {
			delete(v.Metadata, "cookies")
		}
		tokenMap := make(map[string]interface{})
		data, _ := json.Marshal(v)
		_ = json.Unmarshal(data, &tokenMap)
		if !showTokens {
			delete(tokenMap, "token")
			delete(tokenMap, "refresh_token")
		}
		allTokens[k] = tokenMap
	}

	if query != "" {
		raw, _ := cmd.Flags().GetBool("raw")
		vars, err := queryVarsFromFlags(cmd.Flags())
		if err != nil {
			return err
		}
		return applyGojqQuery(allTokens, query, raw, vars...)
	}

	if !showTokens && len(tokensMap) > 0 {
		args.PrintSuccess("Login tokens are hidden")
	}
	for k, tokenMap := range allTokens {
		jsonData, _ := json.MarshalIndent(tokenMap, "", "  ")
		args.PrintSuccess(fmt.Sprintf("%s Token\n%s", k, jsonData))
	}
	return nil
}

// rcAvailable returns the extra reason-line fields describing the credentials
// file that was in play, so a script that hits USERNAME_REQUIRED or
// SECRET_REQUIRED can tell "no .idsecrc was found" apart from "an .idsecrc was
// loaded but has no entry for this profile/authenticator". Nothing is added when
// no file was loaded.
func rcAvailable(credentialsFile *credentials.IdsecRCFile) []string {
	if path := credentialsFile.Path(); path != "" {
		return []string{"rc_available=" + path}
	}
	return nil
}

// credSourceKind identifies where a resolved credential value came from.
type credSourceKind int

const (
	credSourceNone credSourceKind = iota
	credSourceFlag
	credSourceEnv
	credSourceFile
)

// credSource pairs a candidate credential value with its source.
type credSource struct {
	value string
	kind  credSourceKind
}

// firstNonEmptyWithSource returns the first non-empty value among the given
// sources, together with the source it came from.
func firstNonEmptyWithSource(sources ...credSource) (string, credSourceKind) {
	for _, s := range sources {
		if s.value != "" {
			return s.value, s.kind
		}
	}
	return "", credSourceNone
}

// firstNonEmpty returns the first non-empty string among the given values.
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// annotateSecretPrompt appends a note to the secret prompt indicating that a
// value was pre-loaded from an environment variable or the credentials file, so
// the user can press Enter to use it or type a new value to override it. The
// secret value itself is never included.
func annotateSecretPrompt(prompt string, source credSourceKind, authName string, credentialsFile *credentials.IdsecRCFile) string {
	switch source {
	case credSourceEnv:
		return fmt.Sprintf("%s (loaded from %s; press Enter to use)", prompt, credentials.EnvSecretSourceVar(authName))
	case credSourceFile:
		return fmt.Sprintf("%s (loaded from %s; press Enter to use)", prompt, credentialsFile.Path())
	default:
		return prompt
	}
}

// loadProfileWithConfigureFlow loads a profile by name, automatically triggering configure flow if no profile exists.
//
// loadProfileWithConfigureFlow attempts to load the specified profile and, if no valid profile
// is found, automatically starts the configuration flow to help users set up a profile.
// This provides a seamless user experience for login commands by eliminating the need to
// manually run configure commands when profiles are missing.
//
// Parameters:
//   - profileName: The name of the profile to load (will be processed through DeduceProfileName)
//   - cmd: The cobra command context for configuration
//
// Returns the loaded profile and any error that occurred during loading or configuration.
//
// Example usage:
//
//	profile, err := a.loadProfileWithConfigureFlow("production", cmd)
//	if err != nil {
//	    return fmt.Errorf("failed to load or configure profile: %v", err)
//	}
func (a *IdsecLoginAction) loadProfileWithConfigureFlow(profileName string, cmd *cobra.Command) (*models.IdsecProfile, error) {
	profile, err := (*a.profilesLoader).LoadProfile(profiles.DeduceProfileName(profileName))
	if err != nil || profile == nil {
		// Only start configure flow in interactive mode
		if config.IsInteractive() {
			args.PrintWarning("No profile found. Starting configuration flow...")

			// Run configure and use the returned profile directly
			configureAction := NewIdsecConfigureAction(a.profilesLoader)
			profile = configureAction.runConfigureAction(cmd, []string{})
			if profile == nil {
				return nil, fmt.Errorf("failed to load profile after configuration")
			}
		} else {
			// In non-interactive mode, just return an error
			return nil, fmt.Errorf("no profile found. Please run 'idsec configure' to set up a profile before using login")
		}
	}
	return profile, nil
}
