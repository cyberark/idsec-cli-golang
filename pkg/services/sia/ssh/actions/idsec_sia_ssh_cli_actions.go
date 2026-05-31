package actions

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	sdkactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/ssh/actions"
)

// CLIAction is a struct that defines the SIA SSH action for the Idsec service for the CLI.
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "ssh",
		ActionDescription: "SIA SSH actions.",
		ActionVersion:     1,
		Schemas:           sdkactions.ActionToSchemaMap,
	},
}
