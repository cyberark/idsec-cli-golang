package actions

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	sdkactions "github.com/cyberark/idsec-sdk-golang/pkg/services/access/assets/actions"
)

// CLIAction is a struct that defines the access assets action for the Idsec service CLI.
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "assets",
		ActionDescription: "Access Space Assets Management. List assets accessible via the Access Space, and retrieve their credentials on demand.",
		ActionVersion:     1,
		Schemas:           sdkactions.ActionToSchemaMap,
	},
}
