package actions

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	editor "github.com/confluentinc/go-editor"
	"github.com/spf13/cobra"
	"github.com/cyberark/idsec-cli-golang/pkg/agentmode"
	commonargs "github.com/cyberark/idsec-cli-golang/pkg/common/args"
	"github.com/cyberark/idsec-sdk-golang/pkg/config"
	"github.com/cyberark/idsec-sdk-golang/pkg/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/profiles"
)

// newProfileEditor creates the editor used by profiles edit. It is a var so
// tests can stub the editor launch.
var newProfileEditor = editor.NewEditor

// IdsecProfilesAction is a struct that implements the IdsecAction interface for managing CLI profiles.
//
// IdsecProfilesAction provides functionality for managing multiple CLI configuration profiles
// including listing, showing, deleting, clearing, cloning, adding, and editing profiles.
// It handles profile operations through a ProfileLoader and provides both interactive
// and non-interactive modes for various operations.
//
// The action supports comprehensive profile management operations:
//   - List profiles with optional filtering by name pattern or auth type
//   - Show detailed profile information
//   - Delete specific profiles with confirmation prompts
//   - Clear all profiles with confirmation
//   - Clone profiles with automatic or custom naming
//   - Add profiles from file paths
//   - Edit profiles interactively using an external editor
type IdsecProfilesAction struct {
	// IdsecBaseAction provides common action functionality
	*IdsecBaseAction
	// profilesLoader handles loading and saving of profile configurations
	profilesLoader *profiles.ProfileLoader
}

// NewIdsecProfilesAction creates a new instance of IdsecProfilesAction.
//
// NewIdsecProfilesAction initializes a new IdsecProfilesAction with the provided
// profile loader and an embedded IdsecBaseAction for common CLI functionality.
// The profile loader is used for all profile operations including loading,
// saving, deleting, and managing profile configurations.
//
// Parameters:
//   - profilesLoader: A pointer to a ProfileLoader for handling profile operations
//
// Returns a new IdsecProfilesAction instance ready for defining profile management commands.
//
// Example:
//
//	loader := profiles.NewProfileLoader()
//	profilesAction := NewIdsecProfilesAction(loader)
//	profilesAction.DefineAction(rootCmd)
func NewIdsecProfilesAction(profilesLoader *profiles.ProfileLoader) *IdsecProfilesAction {
	return &IdsecProfilesAction{
		IdsecBaseAction: NewIdsecBaseAction(),
		profilesLoader:  profilesLoader,
	}
}

// DefineAction defines the CLI profiles action and adds profile management commands.
//
// DefineAction creates a "profiles" command that provides comprehensive profile management
// functionality. The command includes multiple subcommands for different profile operations,
// each with their own flags and functionality.
//
// The function creates the following subcommands:
//   - list: Lists all profiles with optional filtering by name pattern or auth type
//   - show: Shows detailed information for a specific profile
//   - delete: Deletes a specific profile with confirmation
//   - clear: Clears all profiles with confirmation
//   - clone: Clones an existing profile with optional renaming
//   - add: Adds a profile from a file path
//   - edit: Opens a profile for interactive editing
//
// Parameters:
//   - cmd: The parent cobra command to which the profiles command will be added
//
// Each subcommand includes appropriate flags for configuration and supports both
// interactive and non-interactive modes where applicable.
//
// Example:
//
//	profilesAction := NewIdsecProfilesAction(loader)
//	profilesAction.DefineAction(rootCmd)
//	// This adds: myapp profiles [list|show|delete|clear|clone|add|edit] [flags]
func (a *IdsecProfilesAction) DefineAction(cmd *cobra.Command) {
	profileCmd := &cobra.Command{
		Use:   "profiles",
		Short: "Manage profiles",
	}
	profileCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		a.CommonActionsExecution(cmd, args, true)
	}
	a.CommonActionsConfiguration(profileCmd)

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List all profiles",
		RunE:  a.runListAction,
	}
	listCmd.Flags().StringP("name", "", "", "Profile name to filter with by wildcard")
	listCmd.Flags().StringP("auth-profile", "", "", "Filter profiles by auth types")
	listCmd.Flags().BoolP("all", "", false, "Whether to show all profiles data as well and not only their names")
	listCmd.Flags().String("query", "", "jq expression to apply to the JSON output")
	registerQueryVarFlags(listCmd.Flags())

	showCmd := &cobra.Command{
		Use:   "show",
		Short: "Show a profile",
		RunE:  a.runShowAction,
	}
	showCmd.Flags().StringP("profile-name", "", "", "Profile name to show, if not given, shows the current one")

	deleteCmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete a specific profile",
		RunE:  a.runDeleteAction,
	}
	deleteCmd.Flags().StringP("profile-name", "", "", "Profile name to delete")
	deleteCmd.Flags().BoolP("yes", "", false, "Whether to approve deletion non interactively")

	clearCmd := &cobra.Command{
		Use:   "clear",
		Short: "Clear all profiles",
		RunE:  a.runClearAction,
	}
	clearCmd.Flags().BoolP("yes", "", false, "Whether to approve clear non interactively")

	cloneCmd := &cobra.Command{
		Use:   "clone",
		Short: "Clone a profile",
		RunE:  a.runCloneAction,
	}
	cloneCmd.Flags().StringP("profile-name", "", "", "Profile name to clone")
	cloneCmd.Flags().StringP("new-profile-name", "", "", "New cloned profile name, if not given, will add _clone as part of the name")
	cloneCmd.Flags().BoolP("yes", "", false, "Whether to override existing profile if exists")

	addCmd := &cobra.Command{
		Use:   "add",
		Short: "Add a profile from a given path",
		RunE:  a.runAddAction,
	}
	addCmd.Flags().StringP("profile-path", "", "", "Profile file path to be added")
	addCmd.Flags().BoolP("yes", "", false, "Whether to overwrite an existing profile non-interactively")

	editCmd := &cobra.Command{
		Use:   "edit",
		Short: "Edit a profile interactively",
		RunE:  a.runEditAction,
	}
	editCmd.Flags().StringP("profile-name", "", "", "Profile name to edit, if not given, edits the current one")

	profileCmd.AddCommand(listCmd, showCmd, deleteCmd, clearCmd, cloneCmd, addCmd, editCmd)
	cmd.AddCommand(profileCmd)
}

// loadExistingProfile loads profileName and reports a failure when it is
// missing or can't be read, so callers can return the error directly. The
// loader returns (nil, nil) for a missing profile and an error only when the
// profile exists but can't be read, parsed or validated. The name and the
// error (which can embed the file path) are quoted so a newline in the name
// can't forge an "idsec: " machine-readable line.
func (a *IdsecProfilesAction) loadExistingProfile(profileName string) (*models.IdsecProfile, error) {
	profile, err := (*a.profilesLoader).LoadProfile(profileName)
	if err != nil {
		return nil, reportFailure(agentmode.CodeConfigError, fmt.Sprintf("Failed to load profile %q: %q", profileName, err.Error()), err,
			agentmode.WithDetail("source", "profile"), agentmode.WithDetail("profile", profileName),
			agentmode.WithHint(hintProfileUnreadable))
	}
	if profile == nil {
		return nil, reportFailure(agentmode.CodeProfileNotFound, fmt.Sprintf("No profile was found for the name %q", profileName), nil,
			agentmode.WithDetail("profile", profileName),
			agentmode.WithHint(hintProfilesList), agentmode.WithHint(hintProfileCreate))
	}
	return profile, nil
}

// profileFileFailure reports an unusable `profiles add --profile-path` file.
func profileFileFailure(msg, path string) error {
	return reportFailure(agentmode.CodeConfigError, msg, nil,
		agentmode.WithDetail("source", "profile_file"), agentmode.WithDetail("path", path))
}

// runListAction handles the profiles list command execution.
//
// runListAction loads all available profiles and displays them based on the provided
// filtering criteria and output format options. It supports filtering by name pattern
// using regex matching and by authentication profile type.
//
// The function performs the following operations:
//  1. Loads all profiles using the profile loader
//  2. Applies name-based filtering using regex pattern matching
//  3. Applies auth-profile filtering by checking profile auth configurations
//  4. Outputs either profile names only or full profile data based on --all flag
//
// Parameters:
//   - cmd: The cobra command containing flag values for filtering and output options
//   - args: Command line arguments (not currently used)
//
// Supported flags:
//   - name: Regex pattern to filter profile names
//   - auth-profile: Filter profiles by specific auth type
//   - all: Show full profile data instead of just names
//
// A failure to load the profiles is reported as an error (non-zero exit),
// distinct from the "no profiles configured" case. Output is always a valid
// JSON array — an empty result set marshals to [] (never null), so JSON
// consumers of --all or the default name listing never break.
func (a *IdsecProfilesAction) runListAction(cmd *cobra.Command, args []string) error {
	// Start by loading all the profiles. An error here (for example an
	// unreadable or corrupt profiles directory) is a genuine failure and must
	// not be conflated with "you have no profiles".
	loadedProfiles, err := (*a.profilesLoader).LoadAllProfiles()
	if err != nil {
		return reportFailure(agentmode.CodeConfigError, fmt.Sprintf("Failed to load profiles: %v", err), err,
			agentmode.WithDetail("source", "profiles_folder"),
			agentmode.WithHint(hintProfilesFolderUnreadable))
	}
	// Guarantee a non-nil slice so a genuinely empty result marshals to [].
	if loadedProfiles == nil {
		loadedProfiles = []*models.IdsecProfile{}
	}

	// Filter profiles
	name, _ := cmd.Flags().GetString("name")
	if name != "" {
		filtered := []*models.IdsecProfile{}
		for _, p := range loadedProfiles {
			if matched, err := regexp.MatchString(name, p.ProfileName); err == nil && matched {
				filtered = append(filtered, p)
			}
		}
		loadedProfiles = filtered
	}

	authProfile, _ := cmd.Flags().GetString("auth-profile")
	if authProfile != "" {
		filtered := []*models.IdsecProfile{}
		for _, p := range loadedProfiles {
			if _, ok := p.AuthProfiles[authProfile]; ok {
				filtered = append(filtered, p)
			}
		}
		loadedProfiles = filtered
	}

	// Build the output value based on --all.
	showAll, _ := cmd.Flags().GetBool("all")
	var output any
	if showAll {
		output = loadedProfiles
	} else {
		names := make([]string, 0, len(loadedProfiles))
		for _, p := range loadedProfiles {
			names = append(names, p.ProfileName)
		}
		output = names
	}

	query, _ := cmd.Flags().GetString("query")
	if query != "" {
		raw, _ := cmd.Flags().GetBool("raw")
		vars, err := queryVarsFromFlags(cmd.Flags())
		if err != nil {
			return err
		}
		return applyGojqQuery(output, query, raw, vars...)
	}

	data, _ := json.MarshalIndent(output, "", "  ")
	commonargs.PrintSuccess(string(data))
	return nil
}

// runShowAction handles the profiles show command execution.
//
// runShowAction displays detailed information for a specific profile. If no profile
// name is provided, it uses the default profile name deduction logic to determine
// which profile to show.
//
// Parameters:
//   - cmd: The cobra command containing the profile-name flag
//   - args: Command line arguments (not currently used)
//
// Supported flags:
//   - profile-name: Name of the profile to show (optional, defaults to current profile)
//
// The function outputs the profile data in JSON format. If the profile is not
// found or can't be read, it prints a failure and exits non-zero.
func (a *IdsecProfilesAction) runShowAction(cmd *cobra.Command, args []string) error {
	profileName, _ := cmd.Flags().GetString("profile-name")
	if profileName == "" {
		profileName = profiles.DeduceProfileName("")
	}

	profile, err := a.loadExistingProfile(profileName)
	if err != nil {
		return err
	}

	data, _ := json.MarshalIndent(profile, "", "  ")
	commonargs.PrintSuccess(string(data))
	return nil
}

// runDeleteAction handles the profiles delete command execution.
//
// runDeleteAction deletes a specific profile after loading it and optionally
// prompting for user confirmation. The function includes safety checks to
// ensure the profile exists before attempting deletion.
//
// Parameters:
//   - cmd: The cobra command containing the profile-name and yes flags
//   - args: Command line arguments (not currently used)
//
// Supported flags:
//   - profile-name: Name of the profile to delete (required)
//   - yes: Skip confirmation prompt for non-interactive deletion
//
// The function fails with a non-zero exit if --profile-name is empty or the
// profile is not found or can't be read, and uses interactive confirmation
// unless the --yes flag is provided.
func (a *IdsecProfilesAction) runDeleteAction(cmd *cobra.Command, args []string) error {
	profileName, _ := cmd.Flags().GetString("profile-name")
	if profileName == "" {
		return missingFlagFailure("--profile-name is required", "profile-name")
	}
	if _, err := a.loadExistingProfile(profileName); err != nil {
		return err
	}

	ok, err := commonargs.GetConfirmation(cmd, "yes",
		fmt.Sprintf("Are you sure you want to delete profile %s?", profileName))
	if err != nil {
		return missingInputFailure(fmt.Sprintf("Refusing to delete profile %s without confirmation", profileName), err)
	}
	if !ok {
		return nil
	}

	if err := (*a.profilesLoader).DeleteProfile(profileName); err != nil {
		commonargs.PrintFailure(fmt.Sprintf("Failed to delete profile: %v", err))
		return ErrActionFailed
	}
	return nil
}

// runClearAction handles the profiles clear command execution.
//
// runClearAction clears all profiles after optionally prompting for user
// confirmation. This is a destructive operation that removes all stored
// profile configurations.
//
// Parameters:
//   - cmd: The cobra command containing the yes flag
//   - args: Command line arguments (not currently used)
//
// Supported flags:
//   - yes: Skip confirmation prompt for non-interactive clearing
//
// The function uses interactive confirmation unless the --yes flag is provided
// to prevent accidental deletion of all profiles.
func (a *IdsecProfilesAction) runClearAction(cmd *cobra.Command, args []string) error {
	ok, err := commonargs.GetConfirmation(cmd, "yes", "Are you sure you want to clear all profiles?")
	if err != nil {
		return missingInputFailure("Refusing to clear all profiles without confirmation", err)
	}
	if !ok {
		return nil
	}

	if err := (*a.profilesLoader).ClearAllProfiles(); err != nil {
		commonargs.PrintFailure(fmt.Sprintf("Failed to clear profiles: %v", err))
		return ErrActionFailed
	}
	return nil
}

// runCloneAction handles the profiles clone command execution.
//
// runCloneAction creates a copy of an existing profile with a new name. If no
// new name is provided, it automatically appends "_clone" to the original name.
// The function includes logic to handle name conflicts with existing profiles.
//
// Parameters:
//   - cmd: The cobra command containing profile-name, new-profile-name, and yes flags
//   - args: Command line arguments (not currently used)
//
// Supported flags:
//   - profile-name: Name of the profile to clone (required)
//   - new-profile-name: Name for the cloned profile (optional, defaults to original_clone)
//   - yes: Skip confirmation prompt when overwriting existing profiles
//
// The function prompts for confirmation if the target profile name already exists
// unless the --yes flag is provided.
func (a *IdsecProfilesAction) runCloneAction(cmd *cobra.Command, args []string) error {
	profileName, _ := cmd.Flags().GetString("profile-name")
	if profileName == "" {
		return missingFlagFailure("--profile-name is required", "profile-name")
	}
	profile, err := a.loadExistingProfile(profileName)
	if err != nil {
		return err
	}

	newProfileName, _ := cmd.Flags().GetString("new-profile-name")
	if newProfileName == "" {
		newProfileName = profileName + "_clone"
	}

	clonedProfile := profile
	clonedProfile.ProfileName = newProfileName

	if (*a.profilesLoader).ProfileExists(newProfileName) {
		ok, err := commonargs.GetConfirmation(cmd, "yes",
			fmt.Sprintf("Profile %s already exists, do you want to override it?", newProfileName))
		if err != nil {
			return missingInputFailure(fmt.Sprintf("Refusing to overwrite profile %s without confirmation", newProfileName), err)
		}
		if !ok {
			return nil
		}
	}

	if err := (*a.profilesLoader).SaveProfile(clonedProfile); err != nil {
		commonargs.PrintFailure(fmt.Sprintf("Failed to save cloned profile: %v", err))
		return ErrActionFailed
	}
	return nil
}

// runAddAction handles the profiles add command execution.
//
// runAddAction adds a profile from a specified file path by reading and parsing
// the JSON profile data. The function includes validation to ensure the file
// exists and contains valid profile data.
//
// Parameters:
//   - cmd: The cobra command containing the profile-path and yes flags
//   - args: Command line arguments (not currently used)
//
// Supported flags:
//   - profile-path: File system path to the profile JSON file (required)
//   - yes: Skip the confirmation prompt when overwriting an existing profile
//
// The function validates file existence, reads the file content, unmarshals
// the JSON data into a profile structure, checks that profile_name is a single
// path element and that the profile passes Validate, and saves it using the
// profile loader.
// If a profile with the same name already exists, it asks for confirmation
// before overwriting unless --yes is provided; in non-interactive (agent) mode
// without --yes it refuses and emits a machine-readable missing_required_input
// line on stderr. It prints appropriate warnings and failures for various
// error conditions.
func (a *IdsecProfilesAction) runAddAction(cmd *cobra.Command, args []string) error {
	profilePath, _ := cmd.Flags().GetString("profile-path")
	if profilePath == "" {
		return missingFlagFailure("--profile-path is required", "profile-path")
	}
	fi, err := os.Stat(profilePath)
	if os.IsNotExist(err) {
		return profileFileFailure(fmt.Sprintf("Profile path [%s] does not exist, aborting", profilePath), profilePath)
	}
	// os.Stat follows symlinks, so this also rejects links to devices or FIFOs,
	// which would make ReadFile read forever or block.
	if err != nil || !fi.Mode().IsRegular() {
		return profileFileFailure(fmt.Sprintf("Profile path [%s] is not a regular file, aborting", profilePath), profilePath)
	}
	data, err := os.ReadFile(profilePath) // #nosec G304
	if err != nil {
		return profileFileFailure(fmt.Sprintf("Profile path [%s] failed to be read, aborting", profilePath), profilePath)
	}
	var profile *models.IdsecProfile
	if err = json.Unmarshal(data, &profile); err != nil || profile == nil {
		return profileFileFailure(fmt.Sprintf("Profile path [%s] failed to be parsed, aborting", profilePath), profilePath)
	}
	// The name becomes a file name inside the profiles folder, so it must be a
	// single path element: an empty name resolves to the folder itself and
	// separators or ".." would write outside it. Control characters are refused
	// because the name ends up in messages (including OS errors that embed the
	// path) where a newline could forge an "idsec: " machine-readable line.
	name := profile.ProfileName
	if name == "" || name == "." || name == ".." || name != filepath.Base(name) ||
		strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return profileFileFailure(fmt.Sprintf("Profile path [%s] has invalid profile_name %q: must be a non-empty name without path separators", profilePath, name), profilePath)
	}
	if err = profile.Validate(); err != nil {
		return profileFileFailure(fmt.Sprintf("Profile path [%s] contains an invalid profile: %q", profilePath, err.Error()), profilePath)
	}
	if (*a.profilesLoader).ProfileExists(profile.ProfileName) {
		ok, err := commonargs.GetConfirmation(cmd, "yes",
			fmt.Sprintf("Profile %q already exists. Do you want to overwrite it?", profile.ProfileName))
		if err != nil {
			return missingInputFailure(fmt.Sprintf("Refusing to overwrite profile %q without confirmation", profile.ProfileName), err)
		}
		if !ok {
			return nil
		}
	}
	if err = (*a.profilesLoader).SaveProfile(profile); err != nil {
		commonargs.PrintFailure(fmt.Sprintf("Failed to save profile: %q", err.Error()))
		return ErrActionFailed
	}
	commonargs.PrintSuccess(fmt.Sprintf("Profile %q added successfully", profile.ProfileName))
	return nil
}

// runEditAction handles the profiles edit command execution.
//
// runEditAction opens a profile for interactive editing using an external editor.
// The profile data is marshaled to JSON, opened in a temporary file for editing,
// and then parsed back and saved after the user completes editing.
//
// Parameters:
//   - cmd: The cobra command containing the profile-name flag
//   - args: Command line arguments (not currently used)
//
// Supported flags:
//   - profile-name: Name of the profile to edit (optional, defaults to current profile)
//
// The function creates a temporary JSON file, launches the configured editor,
// waits for the user to complete editing, parses the modified content, and
// saves the updated profile. It includes cleanup logic to remove temporary files
// and comprehensive error handling for various failure scenarios.
func (a *IdsecProfilesAction) runEditAction(cmd *cobra.Command, args []string) error {
	if !config.IsInteractive() {
		return interactiveRequiredFailure("profiles edit requires an interactive terminal; use `idsec profiles add --profile-path <file>` or `idsec configure` flags instead",
			agentmode.WithDetail("command", cmd.CommandPath()), agentmode.WithHint(hintProfilesEditAlternative))
	}

	profileName, _ := cmd.Flags().GetString("profile-name")
	if profileName == "" {
		profileName = profiles.DeduceProfileName("")
	}

	profile, err := a.loadExistingProfile(profileName)
	if err != nil {
		return err
	}
	edit := newProfileEditor()
	data, err := json.Marshal(profile)
	if err != nil {
		commonargs.PrintFailure(fmt.Sprintf("Failed to marshal profile: %s", err))
		return ErrActionFailed
	}
	edited, path, err := edit.LaunchTempFile(fmt.Sprintf("%s-temp.json", profile.ProfileName), bytes.NewBufferString(string(data)))
	defer func(name string) {
		if removeErr := os.Remove(name); removeErr != nil {
			commonargs.PrintWarning(fmt.Sprintf("Failed to remove temp file: %s", removeErr))
		}
	}(path)
	if err != nil {
		commonargs.PrintFailure(fmt.Sprintf("Failed to launch editor: %s", err))
		return ErrActionFailed
	}
	if err = json.Unmarshal(edited, &profile); err != nil {
		commonargs.PrintFailure(fmt.Sprintf("Failed to unmarshal edited profile: %s", err))
		return ErrActionFailed
	}
	if err = (*a.profilesLoader).SaveProfile(profile); err != nil {
		commonargs.PrintFailure(fmt.Sprintf("Failed to save edited profile: %s", err))
		return ErrActionFailed
	}
	return nil
}
