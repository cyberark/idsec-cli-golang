package actions

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	sdkactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/entragroups/actions"
)

func boolPtr(b bool) *bool { return &b }

// CLIAction defines the entragroups subcommand for the SCA CLI.
// It maps to: idsec exec sca entragroups <action> [flags]
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "entragroups",
		Enabled:           boolPtr(false),
		ActionDescription: "List and elevate Microsoft Entra ID groups that the authenticated user is eligible to request just-in-time membership for via Secure Cloud Access.",
		ActionVersion:     1,
		Schemas:           sdkactions.ActionToSchemaMap,
	},
}
