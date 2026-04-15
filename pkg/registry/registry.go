package registry

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
)

var cliActionRegistry []*actions.IdsecServiceCLIActionDefinition

// RegisterCLIAction adds a top-level CLI action definition to the registry.
func RegisterCLIAction(action *actions.IdsecServiceCLIActionDefinition) {
	cliActionRegistry = append(cliActionRegistry, action)
}

// TopLevelCLIActions returns all registered top-level CLI action definitions.
func TopLevelCLIActions() []*actions.IdsecServiceCLIActionDefinition {
	return cliActionRegistry
}
