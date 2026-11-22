package actions

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	sdkactions "github.com/cyberark/idsec-sdk-golang/pkg/services/ars/requests/actions"
)

// CLIAction is a struct that defines the ARS requests action for the Idsec service CLI.
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "requests",
		ActionDescription: "Access requests management. Submit, list, get, cancel and finalize access requests, calculate their statistics, and list the request forms describing the details to provide when requesting access.",
		ActionVersion:     1,
		Schemas:           sdkactions.ActionToSchemaMap,
	},
}
