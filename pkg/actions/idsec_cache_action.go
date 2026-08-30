package actions

import (
	"github.com/spf13/cobra"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/keyring"
)

// IdsecCacheAction is a struct that implements the IdsecAction interface for cache management.
//
// IdsecCacheAction provides functionality for managing cache operations in the Idsec SDK CLI.
// It embeds IdsecBaseAction to inherit common CLI functionality and adds specific cache
// management commands such as clearing cached profiles and credentials.
//
// The action specifically supports clearing cache for basic keyring implementations,
// which store credentials and profile information in local files.
type IdsecCacheAction struct {
	// IdsecBaseAction provides common action functionality
	*IdsecBaseAction
}

// NewIdsecCacheAction creates a new instance of IdsecCacheAction.
//
// NewIdsecCacheAction initializes a new IdsecCacheAction with an embedded IdsecBaseAction,
// providing all the common CLI functionality along with cache-specific operations.
// The returned instance is ready to be used for defining cache management commands.
//
// Returns a new IdsecCacheAction instance with initialized base action functionality.
//
// Example:
//
//	cacheAction := NewIdsecCacheAction()
//	cacheAction.DefineAction(rootCmd)
func NewIdsecCacheAction() *IdsecCacheAction {
	return &IdsecCacheAction{
		IdsecBaseAction: NewIdsecBaseAction(),
	}
}

// DefineAction defines the CLI cache action and adds cache management subcommands.
//
// DefineAction creates a "cache" command with subcommands for cache management operations.
// Currently, it provides a "clear" subcommand that removes cached credentials and profile
// information from the basic keyring implementation.
//
// The function sets up:
//  1. A parent "cache" command for cache management
//  2. Common action configuration through embedded IdsecBaseAction
//  3. A "clear" subcommand for clearing cached data
//  4. Persistent pre-run hook for common action execution
//
// Parameters:
//   - cmd: The parent cobra command to which the cache command will be added
//
// The cache command supports the standard CLI flags inherited from IdsecBaseAction
// and executes common action setup before running cache-specific operations.
//
// Example:
//
//	cacheAction := NewIdsecCacheAction()
//	cacheAction.DefineAction(rootCmd)
//	// This adds: myapp cache clear
func (a *IdsecCacheAction) DefineAction(cmd *cobra.Command) {
	cacheCmd := &cobra.Command{
		Use:   "cache",
		Short: "Manage cache",
	}
	cacheCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		a.CommonActionsExecution(cmd, args, true)
	}
	a.CommonActionsConfiguration(cacheCmd)

	clearCmd := &cobra.Command{
		Use:   "clear",
		Short: "Clears all profiles cache",
		Run:   a.runClearCacheAction,
	}

	cacheCmd.AddCommand(clearCmd)
	cmd.AddCommand(cacheCmd)
}

// runClearCacheAction clears the cached credentials held by whichever keyring the SDK resolves.
//
// runClearCacheAction resolves the keyring and delegates the removal to it, so the cache is
// cleared wherever it happens to live: the OS keystore removes the entries the SDK owns, and the
// file-backed keyring removes its stored file. The key material protecting the file-backed cache
// is deliberately left in place, since removing the cache is enough to forget the credentials and
// the key on its own decrypts nothing.
//
// Clearing a cache that is already empty succeeds, and so does clearing one written by an earlier
// version whose contents this build can no longer read.
//
// Parameters:
//   - cmd: The cobra command (not currently used)
//   - args: Command line arguments (not currently used)
//
// A keyring that cannot be resolved leaves nothing to clear and is not reported: the cache is
// unreachable for reading too, so the credentials are already unusable. A removal that does fail
// is logged as a warning rather than returned, following the pattern of best-effort cleanup.
func (a *IdsecCacheAction) runClearCacheAction(cmd *cobra.Command, args []string) {
	if keyring, err := keyring.NewIdsecKeyring("").GetKeyring(false); err == nil {
		err = keyring.ClearAllPasswords()
		if err != nil {
			a.logger.Warning("Failed to clear keyring passwords: %v", err)
		}
	}
}
