package actions

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	sdkactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/secretsdb/actions"
)

// CLIAction is a struct that defines the SIA Secrets DB action for the Idsec service for the CLI.
// Note: This resource uses the legacy secrets API. For strong accounts, use the db-strong-accounts resource instead.
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
	IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
		ActionName:        "secrets-db",
		ActionDescription: "SIA Secrets database actions.",
		ActionVersion:     1,
		Schemas:           sdkactions.ActionToSchemaMap,
	},
}
