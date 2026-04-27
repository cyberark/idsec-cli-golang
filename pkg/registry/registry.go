package registry

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
)

// releasedFeaturesOnly controls whether disabled CLI actions are filtered out
// at registration / wiring time. It mirrors the SDK-side flag of the same
// name and is set via ldflags, e.g.:
//
//	-ldflags "-X github.com/cyberark/idsec-cli-golang/pkg/registry.releasedFeaturesOnly=true"
//
// When inactive (the default), every action is registered regardless of its
// Enabled value so developer builds still expose unreleased commands.
var releasedFeaturesOnly = "false"

// IsReleasedFeaturesOnly returns true when disabled-action filtering is active.
func IsReleasedFeaturesOnly() bool {
	return releasedFeaturesOnly == "true"
}

var cliActionRegistry []*actions.IdsecServiceCLIActionDefinition

// RegisterCLIAction adds a top-level CLI action definition to the registry.
//
// When IsReleasedFeaturesOnly() is true, the top-level action is skipped if it
// is disabled, and any disabled descendants are pruned recursively from its
// Subactions tree before it is stored.
func RegisterCLIAction(action *actions.IdsecServiceCLIActionDefinition) {
	if action == nil {
		return
	}
	if IsReleasedFeaturesOnly() {
		if !action.IsEnabled() {
			return
		}
		action.Subactions = filterEnabledSubactions(action.Subactions)
	}
	cliActionRegistry = append(cliActionRegistry, action)
}

// TopLevelCLIActions returns all registered top-level CLI action definitions.
func TopLevelCLIActions() []*actions.IdsecServiceCLIActionDefinition {
	return cliActionRegistry
}

// filterEnabledSubactions returns a new slice containing only enabled
// subactions, with the same filter applied recursively to their own subactions.
func filterEnabledSubactions(subactions []*actions.IdsecServiceCLIActionDefinition) []*actions.IdsecServiceCLIActionDefinition {
	if len(subactions) == 0 {
		return subactions
	}
	filtered := make([]*actions.IdsecServiceCLIActionDefinition, 0, len(subactions))
	for _, sub := range subactions {
		if sub == nil || !sub.IsEnabled() {
			continue
		}
		sub.Subactions = filterEnabledSubactions(sub.Subactions)
		filtered = append(filtered, sub)
	}
	return filtered
}
