package actions

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	sdkactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/groupaccess/actions"
)

func boolPtr(b bool) *bool { return &b }

// CLIAction defines the group-access subcommand for the SCA CLI.
// It maps to: idsec exec sca group-access <action> [flags]
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "group-access",
		Enabled:           boolPtr(false),
		ActionDescription: "List and elevate Microsoft Entra ID groups that the authenticated user is eligible to request just-in-time membership for via Secure Cloud Access.",
		ActionVersion:     1,
		Schemas:           sdkactions.ActionToSchemaMap,
	},
}
