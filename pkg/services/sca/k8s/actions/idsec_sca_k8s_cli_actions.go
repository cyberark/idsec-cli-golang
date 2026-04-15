package actions

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	sdkactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s/actions"
)

func boolPtr(b bool) *bool { return &b }

// CLIAction is a struct that defines the SCA k8s action for the Idsec service CLI.
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "k8s",
		Enabled:           boolPtr(false),
		ActionDescription: "Access kubernetes clusters and its components",
		ActionVersion:     1,
		Schemas:           sdkactions.ActionToSchemaMap,
	},
}
