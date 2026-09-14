package actions

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/spf13/cobra"
	commonargs "github.com/cyberark/idsec-cli-golang/pkg/common/args"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/models"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/profiles"
)

// status --quiet exit codes. 0 = authenticated; the non-zero codes let scripts
// branch on state without parsing JSON. Exit code 1 is deliberately left
// reserved for generic/unexpected errors, so it is not reused here.
const (
	exitStatusProfileMissing   = 2
	exitStatusNoAuthenticators = 3
	exitStatusNotAuthenticated = 4
	exitStatusTokenExpired     = 5
)

// cachedTokenLoader is implemented by SDK authenticators (via IdsecAuthBase) and
// exposes the raw cached token, including expired ones — which the IdsecAuth
// interface itself does not. status uses it under --quiet to tell an expired
// cached token (exit 5) apart from no cached token at all (exit 4).
type cachedTokenLoader interface {
	LoadCachedToken(profile *models.IdsecProfile) (*authmodels.IdsecToken, error)
}

// cachedTokenPresent reports whether a raw cached token exists for the
// authenticator (regardless of expiry). It is only consulted for authenticators
// that are not currently authenticated, where a present-but-unusable token
// means "expired" and an absent token means "never authenticated".
func cachedTokenPresent(authenticator auth.IdsecAuth, profile *models.IdsecProfile) bool {
	loader, ok := authenticator.(cachedTokenLoader)
	if !ok {
		return false
	}
	token, err := loader.LoadCachedToken(profile)
	return err == nil && token != nil
}

// statusQuietExitCode maps an aggregate profile state to a --quiet exit code.
// Tie-break priority across authenticators is: no-authenticators >
// any-authenticator-has-no-token > any-expired.
func statusQuietExitCode(authenticated, noAuthenticators, hasNoToken, hasExpired bool) int {
	switch {
	case authenticated:
		return 0
	case noAuthenticators:
		return exitStatusNoAuthenticators
	case hasNoToken:
		return exitStatusNotAuthenticated
	case hasExpired:
		return exitStatusTokenExpired
	default:
		return exitStatusNotAuthenticated
	}
}

// IdsecStatusAction is a struct that implements the IdsecAction interface for reporting authentication status.
//
// IdsecStatusAction inspects a profile and reports, per configured authenticator,
// whether the profile is currently authenticated, the authenticated username and
// endpoint, when the cached token expires, and how much time is left before it
// expires. It embeds IdsecBaseAction for common CLI functionality and uses a
// ProfileLoader to resolve and load the profile to inspect.
//
// The status is derived purely from local state (the profile configuration and
// the cached token in the keyring). It never triggers an interactive login or a
// network request, making it safe to run in scripts and CI.
type IdsecStatusAction struct {
	// IdsecBaseAction provides common action functionality
	*IdsecBaseAction
	// profilesLoader handles loading of profile configurations
	profilesLoader *profiles.ProfileLoader
}

// NewIdsecStatusAction creates a new instance of IdsecStatusAction.
//
// NewIdsecStatusAction initializes a new IdsecStatusAction with the provided
// profile loader for resolving and loading profiles, and an embedded
// IdsecBaseAction for common CLI functionality.
//
// Parameters:
//   - profilesLoader: A pointer to a ProfileLoader for loading profiles
//
// Returns a new IdsecStatusAction instance ready for CLI integration.
//
// Example:
//
//	loader := profiles.DefaultProfilesLoader()
//	action := NewIdsecStatusAction(loader)
//	action.DefineAction(rootCmd)
func NewIdsecStatusAction(profilesLoader *profiles.ProfileLoader) *IdsecStatusAction {
	return &IdsecStatusAction{
		IdsecBaseAction: NewIdsecBaseAction(),
		profilesLoader:  profilesLoader,
	}
}

// authenticatorStatus is the machine-readable status of a single authenticator.
type authenticatorStatus struct {
	Authenticator string `json:"authenticator"`
	Name          string `json:"name"`
	Username      string `json:"username,omitempty"`
	AuthMethod    string `json:"auth_method,omitempty"`
	Authenticated bool   `json:"authenticated"`
	Endpoint      string `json:"endpoint,omitempty"`
	ExpiresAt     string `json:"expires_at,omitempty"`
	TimeLeft      string `json:"time_left,omitempty"`
	Expired       bool   `json:"expired,omitempty"`
}

// profileStatus is the machine-readable status of a profile as a whole.
type profileStatus struct {
	Profile        string                `json:"profile"`
	Exists         bool                  `json:"exists"`
	Authenticated  bool                  `json:"authenticated"`
	Authenticators []authenticatorStatus `json:"authenticators"`
}

// DefineAction defines the CLI `status` action, and adds the status function.
//
// DefineAction configures the status command with the flags needed to select a
// profile and choose the output format, then attaches it to the parent command.
//
// Command flags added:
//   - profile-name: Profile to inspect (defaults to the current profile)
//   - json: Output the status as JSON instead of a human-readable summary
//
// Parameters:
//   - cmd: The parent cobra command to attach the status command to
//
// Example:
//
//	action := NewIdsecStatusAction(loader)
//	action.DefineAction(rootCmd)
//	// Now 'idsec status' command is available
func (a *IdsecStatusAction) DefineAction(cmd *cobra.Command) {
	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show the authentication status of a profile",
		RunE:  a.runStatusAction,
	}
	statusCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		a.CommonActionsExecution(cmd, args, true)
	}
	a.CommonActionsConfiguration(statusCmd)

	statusCmd.Flags().String("profile-name", profiles.DefaultProfileName(), "Profile name to show status for, if not given, uses the current one")
	statusCmd.Flags().Bool("json", false, "Output the status as JSON")
	statusCmd.Flags().Bool("quiet", false, "Suppress output and exit non-zero when the profile is not authenticated (useful in scripts without a JSON parser)")
	statusCmd.Flags().String("query", "", "jq expression to apply to the JSON status output")
	registerQueryVarFlags(statusCmd.Flags())

	cmd.AddCommand(statusCmd)
}

// runStatusAction executes the status workflow for the status command.
//
// runStatusAction loads the requested (or current) profile and, for every
// configured authenticator, reports whether it is authenticated and, when it is,
// the cached token's username, endpoint, expiry time, and remaining time before
// expiry. The information is read from local state only (profile file + keyring
// cache); no login or network request is performed.
//
// Parameters:
//   - cmd: The cobra command containing parsed flags and configuration
//   - statusArgs: Command line arguments (not currently used)
func (a *IdsecStatusAction) runStatusAction(cmd *cobra.Command, _ []string) error {
	profileName, _ := cmd.Flags().GetString("profile-name")
	if profileName == "" {
		profileName = profiles.DefaultProfileName()
	}
	profileName = profiles.DeduceProfileName(profileName)

	asJSON, _ := cmd.Flags().GetBool("json")
	quiet, _ := cmd.Flags().GetBool("quiet")
	query, _ := cmd.Flags().GetString("query")
	rawOutput, _ := cmd.Flags().GetBool("raw")

	var queryVars []queryVar
	if query != "" {
		var vErr error
		if queryVars, vErr = queryVarsFromFlags(cmd.Flags()); vErr != nil {
			return vErr
		}
	}

	profile, err := (*a.profilesLoader).LoadProfile(profileName)
	if err != nil || profile == nil {
		// The profile does not exist (exists=false), which is distinct from a
		// profile that exists but has no authenticators.
		missing := profileStatus{Profile: profileName, Exists: false, Authenticated: false, Authenticators: []authenticatorStatus{}}
		if query != "" {
			return applyGojqQuery(missing, query, rawOutput, queryVars...)
		}
		if quiet {
			return &ExitCodeError{Code: exitStatusProfileMissing}
		}
		if asJSON {
			data, _ := json.MarshalIndent(missing, "", "  ")
			commonargs.PrintNormal(string(data))
			return nil
		}
		commonargs.PrintWarning(fmt.Sprintf("No profile was found for the name %s. Run `idsec configure` to set one up.", profileName))
		return nil
	}

	status := profileStatus{
		Profile:        profile.ProfileName,
		Exists:         true,
		Authenticated:  len(profile.AuthProfiles) > 0,
		Authenticators: []authenticatorStatus{},
	}

	// Sort authenticator names for stable output ordering.
	authNames := make([]string, 0, len(profile.AuthProfiles))
	for name := range profile.AuthProfiles {
		authNames = append(authNames, name)
	}
	sort.Strings(authNames)

	// Track, across not-authenticated authenticators, whether any has no cached
	// token at all vs. a cached-but-expired token, so --quiet can pick the right
	// exit code without parsing the JSON output.
	hasNoToken := false
	hasExpired := false

	for _, authenticatorName := range authNames {
		authProfile := profile.AuthProfiles[authenticatorName]
		authenticator, ok := auth.SupportedAuthenticators[authenticatorName]
		if !ok {
			// Unknown authenticator in the profile, surface it but treat as not authenticated.
			status.Authenticated = false
			hasNoToken = true
			status.Authenticators = append(status.Authenticators, authenticatorStatus{
				Authenticator: authenticatorName,
				Name:          authenticatorName,
				Username:      authProfile.Username,
				AuthMethod:    string(authProfile.AuthMethod),
				Authenticated: false,
			})
			continue
		}

		entry := authenticatorStatus{
			Authenticator: authenticatorName,
			Name:          authenticator.AuthenticatorHumanReadableName(),
			Username:      authProfile.Username,
			AuthMethod:    string(authProfile.AuthMethod),
			Authenticated: authenticator.IsAuthenticated(profile),
		}

		if entry.Authenticated {
			if token, loadErr := authenticator.LoadAuthentication(profile, false); loadErr == nil && token != nil {
				if token.Username != "" {
					entry.Username = token.Username
				}
				entry.Endpoint = token.Endpoint
				expiry := time.Time(token.ExpiresIn)
				if !expiry.IsZero() {
					timeLeft := time.Until(expiry)
					entry.ExpiresAt = expiry.Format(time.RFC3339)
					entry.Expired = timeLeft <= 0
					entry.TimeLeft = formatTimeLeft(timeLeft)
				}
			}
		} else {
			status.Authenticated = false
			// Only pay for the extra keyring read when --quiet needs to
			// distinguish expired from never-authenticated.
			if quiet && cachedTokenPresent(authenticator, profile) {
				hasExpired = true
			} else {
				hasNoToken = true
			}
		}

		status.Authenticators = append(status.Authenticators, entry)
	}

	if query != "" {
		return applyGojqQuery(status, query, rawOutput, queryVars...)
	}

	if quiet {
		code := statusQuietExitCode(status.Authenticated, len(status.Authenticators) == 0, hasNoToken, hasExpired)
		if code == 0 {
			return nil
		}
		return &ExitCodeError{Code: code}
	}

	if asJSON {
		data, _ := json.MarshalIndent(status, "", "  ")
		commonargs.PrintNormal(string(data))
	} else {
		a.printHumanReadable(status)
	}
	return nil
}

// printHumanReadable renders the profile status as a colored, human-friendly summary.
func (a *IdsecStatusAction) printHumanReadable(status profileStatus) {
	commonargs.PrintNormalBright(fmt.Sprintf("Profile: %s", status.Profile))

	if len(status.Authenticators) == 0 {
		commonargs.PrintWarning("No authenticators are configured for this profile.")
		return
	}

	for _, entry := range status.Authenticators {
		if !entry.Authenticated {
			commonargs.PrintWarning(fmt.Sprintf("%s: Not Authenticated (run `idsec login`)", entry.Name))
			continue
		}
		if entry.Expired {
			commonargs.PrintWarning(fmt.Sprintf("%s: Token Expired (run `idsec login`)", entry.Name))
			continue
		}

		line := fmt.Sprintf("%s: Authenticated", entry.Name)
		if entry.Username != "" {
			line += fmt.Sprintf(" as %s", entry.Username)
		}
		commonargs.PrintSuccess(line)
		if entry.Endpoint != "" {
			commonargs.PrintNormal(fmt.Sprintf("  Endpoint: %s", entry.Endpoint))
		}
		if entry.ExpiresAt != "" {
			commonargs.PrintNormal(fmt.Sprintf("  Expires:  %s (%s left)", entry.ExpiresAt, entry.TimeLeft))
		}
	}
}

// formatTimeLeft renders a duration until token expiry as a compact, human-readable string.
// Non-positive durations are reported as "expired".
func formatTimeLeft(d time.Duration) string {
	if d <= 0 {
		return "expired"
	}
	d = d.Round(time.Second)
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60
	if hours > 0 {
		return fmt.Sprintf("%dh%dm%ds", hours, minutes, seconds)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm%ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}
