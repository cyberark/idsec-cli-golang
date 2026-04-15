package actions

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	sdkactions "github.com/cyberark/idsec-sdk-golang/pkg/services/cmgr/poolidentifiers/actions"
)

// CLIAction is a struct that defines the pool-identifiers action for the Idsec CMGR service CLI.
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "pool-identifiers",
		ActionDescription: "CMGR Pool Identifiers Management. Pool identifiers are used to identify pools in a simplified manner.",
		ActionVersion:     1,
		Schemas:           sdkactions.ActionToSchemaMap,
	},
}
