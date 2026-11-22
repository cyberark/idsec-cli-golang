package actions

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	requestsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/ars/requests/models"
)

func TestARSRequestsCLIAction_Config(t *testing.T) {
	t.Parallel()

	require.NotNil(t, CLIAction)
	assert.Equal(t, "requests", CLIAction.ActionName)
	assert.NotEmpty(t, CLIAction.ActionDescription)
	assert.Equal(t, int64(1), CLIAction.ActionVersion)
}

func TestARSRequestsCLIAction_Schemas(t *testing.T) {
	t.Parallel()

	tests := map[string]interface{}{
		"submit":             &requestsmodels.IdsecARSSubmitAccessRequest{},
		"cancel":             &requestsmodels.IdsecARSCancelAccessRequest{},
		"finalize":           &requestsmodels.IdsecARSFinalizeAccessRequest{},
		"list":               nil,
		"list-by":            &requestsmodels.IdsecARSFilter{},
		"get":                &requestsmodels.IdsecARSGetAccessRequest{},
		"stats":              nil,
		"list-request-forms": &requestsmodels.IdsecARSListAccessRequestForms{},
	}
	require.Len(t, CLIAction.Schemas, len(tests))
	for action, expected := range tests {
		t.Run(action, func(t *testing.T) {
			t.Parallel()
			schema, ok := CLIAction.Schemas[action]
			require.True(t, ok, "expected action %q to be present in Schemas", action)
			if expected == nil {
				assert.Nil(t, schema)
				return
			}
			assert.IsType(t, expected, schema)
		})
	}
}
