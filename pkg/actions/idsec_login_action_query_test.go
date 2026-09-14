package actions

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/cyberark/idsec-cli-golang/pkg/actions/testutils"
)

// TestIdsecLoginAction_DefineAction_QueryFlags verifies the login command
// exposes --query for querying the token output; raw output reuses the common
// --raw flag.
func TestIdsecLoginAction_DefineAction_QueryFlags(t *testing.T) {
	t.Parallel()

	action := NewIdsecLoginAction(testutils.NewMockProfileLoader().AsProfileLoader())
	rootCmd := &cobra.Command{Use: "idsec"}
	action.DefineAction(rootCmd)

	loginCmd, _, err := rootCmd.Find([]string{"login"})
	if err != nil {
		t.Fatalf("expected to find login command, got error: %v", err)
	}
	if loginCmd.Flags().Lookup("query") == nil {
		t.Error("expected flag 'query' to be defined on the login command")
	}
	// raw is the common persistent flag from CommonActionsConfiguration.
	if loginCmd.PersistentFlags().Lookup("raw") == nil {
		t.Error("expected common '--raw' flag to be available on the login command")
	}
}
