package actions

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	sdkactions "github.com/cyberark/idsec-sdk-golang/pkg/services/cmgr/poolcomponents/actions"
)

// CLIAction is a struct that defines the pool-components action for the Idsec CMGR service CLI.
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "pool-components",
		ActionDescription: "CMGR Pool Components Management. Pool components represent connectors associated with pools.",
		ActionVersion:     1,
		Schemas:           sdkactions.ActionToSchemaMap,
	},
}
