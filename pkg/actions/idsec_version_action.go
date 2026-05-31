package actions

import (
	"fmt"
	"os"
	"strings"

	"github.com/blang/semver"
	"github.com/spf13/cobra"
	"github.com/cyberark/idsec-cli-golang/pkg/common"
	commonargs "github.com/cyberark/idsec-cli-golang/pkg/common/args"
	"github.com/cyberark/idsec-sdk-golang/pkg/config"
)

// getUpgradeHint returns the latest available version when the running
// binary is out of date, and nil otherwise (up-to-date, suppressed via
// IDSEC_SUPPRESS_UPGRADE_CHECK, or any IsLatestVersion error including
// the bounded timeout).
//
// Declared as a var so tests can swap in a deterministic stub.
var getUpgradeHint = func() *semver.Version {
	if os.Getenv(suppressUpgradeCheckEnvVar) != "" {
		return nil
	}
	isLatest, latest, err := common.IsLatestVersion()
	if err != nil || isLatest {
		return nil
	}
	return latest
}

// IdsecVersionAction is a struct that implements the IdsecAction interface for printing the CLI version.
//
// IdsecVersionAction provides functionality for printing the build version and
// associated metadata (build number, build date, git commit and git branch)
// embedded into the Idsec CLI binary. It embeds IdsecBaseAction to inherit
// common CLI functionality and adds a single "version" command that reports
// the build information populated at compile time.
type IdsecVersionAction struct {
	// IdsecBaseAction provides common action functionality
	*IdsecBaseAction
}

// NewIdsecVersionAction creates a new instance of IdsecVersionAction.
//
// NewIdsecVersionAction initializes a new IdsecVersionAction with an embedded
// IdsecBaseAction, providing all the common CLI functionality along with
// version-specific operations. The returned instance is ready to be used for
// defining the version command.
//
// Returns a new IdsecVersionAction instance with initialized base action functionality.
//
// Example:
//
//	versionAction := NewIdsecVersionAction()
//	versionAction.DefineAction(rootCmd)
func NewIdsecVersionAction() *IdsecVersionAction {
	return &IdsecVersionAction{
		IdsecBaseAction: NewIdsecBaseAction(),
	}
}

// DefineAction defines the version command and its configuration.
//
// DefineAction creates and configures the "version" command with a single
// boolean flag controlling output formatting and attaches it to the parent
// command.
//
// Parameters:
//   - cmd: The parent cobra.Command to which the version command will be added
//
// The method configures the following flags:
//   - --silent / -s: Boolean flag to print only the raw semantic version
//     string (e.g. "0.3.1"), without the "Idsec " or leading "v" prefix
//
// Example:
//
//	rootCmd := &cobra.Command{Use: "idsec"}
//	versionAction := NewIdsecVersionAction()
//	versionAction.DefineAction(rootCmd)
func (a *IdsecVersionAction) DefineAction(cmd *cobra.Command) {
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print the Idsec CLI version",
		Run:   a.runVersionAction,
	}
	versionCmd.Flags().BoolP("silent", "s", false, "Print only the raw semantic version, without the 'Idsec ' or leading 'v' prefix")
	cmd.AddCommand(versionCmd)
}

// runVersionAction prints the embedded build metadata of the Idsec CLI.
//
// runVersionAction reads the --silent flag and prints the version string
// sourced from the SDK build-time configuration. In the default mode the
// output is a multi-line block of the form:
//
//	Idsec <version>
//	Build Number: <build-number>
//	Build Date: <build-date>
//	Git Commit: <git-commit>
//	Git Branch: <git-branch>
//
// (e.g. first line "Idsec v0.3.1"). When the binary is older than the latest
// published GitHub release, a yellow upgrade hint is appended below the
// metadata block, matching the wording used by the other CLI commands. The
// check is run on every invocation (no 12h disk cache, unlike the incidental
// nag in `idsec login`/etc.) and bounded by IsLatestVersion's internal
// timeout, so `idsec version` always reflects the current state and never
// hangs. The hint is suppressed on any check failure or when
// IDSEC_SUPPRESS_UPGRADE_CHECK is set, so offline or restricted environments
// see no extra noise. When --silent is set, only the bare version string is
// printed with the leading "v" prefix stripped (e.g. "0.3.1") and the
// upgrade hint is skipped, keeping output stable for shell scripting.
//
// Parameters:
//   - cmd: The cobra command containing the parsed flags
//   - args: Command line arguments (not currently used)
func (a *IdsecVersionAction) runVersionAction(cmd *cobra.Command, args []string) {
	silent, _ := cmd.Flags().GetBool("silent")
	if silent {
		fmt.Println(strings.TrimPrefix(config.IdsecVersion(), "v"))
		return
	}
	fmt.Printf(
		"Idsec %s\nBuild Number: %s\nBuild Date: %s\nGit Commit: %s\nGit Branch: %s\n",
		config.IdsecVersion(),
		config.IdsecBuildNumber(),
		config.IdsecBuildDate(),
		config.IdsecGitCommit(),
		config.IdsecGitBranch(),
	)
	if latest := getUpgradeHint(); latest != nil {
		commonargs.PrintWarning(fmt.Sprintf(
			"\nA newer version of idsec is available. Run `idsec upgrade` to upgrade to version %s.",
			latest.String(),
		))
	}
}
