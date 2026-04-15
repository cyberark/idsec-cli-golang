package actions

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	sdkactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/cloudconsole/actions"
)

// CLIAction defines the cloud-console subcommand for the SCA CLI.
// It maps to: idsec exec sca cloud-console <action> [flags]
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "cloud-console",
		ActionDescription: "List cloud console targets (AWS, Azure, GCP accounts) that the authenticated user is eligible to access via Secure Cloud Access.",
		ActionVersion:     1,
		Schemas:           sdkactions.ActionToSchemaMap,
	},
}
