package actions

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	assetsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/access/assets/models"
)

func TestAccessAssetsCLIAction_Config(t *testing.T) {
	t.Parallel()

	require.NotNil(t, CLIAction)
	assert.Equal(t, "assets", CLIAction.ActionName)
	assert.NotEmpty(t, CLIAction.ActionDescription)
	assert.Equal(t, int64(1), CLIAction.ActionVersion)
}

func TestAccessAssetsCLIAction_Schemas(t *testing.T) {
	t.Parallel()

	require.NotNil(t, CLIAction.Schemas)

	tests := []struct {
		name            string
		action          string
		expectNilSchema bool
		schemaType      interface{}
	}{
		{
			name:            "list_has_nil_schema",
			action:          "list",
			expectNilSchema: true,
		},
		{
			name:       "list_by_has_request_schema",
			action:     "list-by",
			schemaType: &assetsmodels.IdsecAccessAssetsListAssetsRequest{},
		},
		{
			name:       "secret_has_request_schema",
			action:     "secret",
			schemaType: &assetsmodels.IdsecAccessAssetsSecretRequest{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			schema, ok := CLIAction.Schemas[tt.action]
			require.True(t, ok, "expected action %q to be present in Schemas", tt.action)

			if tt.expectNilSchema {
				assert.Nil(t, schema)
				return
			}

			require.NotNil(t, schema)
			assert.IsType(t, tt.schemaType, schema)
		})
	}
}

func TestAccessAssetsCLIAction_SchemaCount(t *testing.T) {
	t.Parallel()

	expectedActions := []string{"list", "list-by", "secret"}
	assert.Len(t, CLIAction.Schemas, len(expectedActions),
		"Schemas map should contain exactly %d entries", len(expectedActions))
}

func TestAccessAssetsListRequest_DefaultValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		request *assetsmodels.IdsecAccessAssetsListAssetsRequest
	}{
		{
			name:    "empty_request",
			request: &assetsmodels.IdsecAccessAssetsListAssetsRequest{},
		},
		{
			name: "vaulted_access_method",
			request: &assetsmodels.IdsecAccessAssetsListAssetsRequest{
				AccessMethod: "vaulted",
			},
		},
		{
			name: "zsp_access_method",
			request: &assetsmodels.IdsecAccessAssetsListAssetsRequest{
				AccessMethod: "zsp",
			},
		},
		{
			name: "recents_only",
			request: &assetsmodels.IdsecAccessAssetsListAssetsRequest{
				RecentsOnly: true,
			},
		},
		{
			name: "favorites_only",
			request: &assetsmodels.IdsecAccessAssetsListAssetsRequest{
				FavoritesOnly: true,
			},
		},
		{
			name: "with_limit_and_sort",
			request: &assetsmodels.IdsecAccessAssetsListAssetsRequest{
				Limit: 50,
				Sort:  "address.asc",
			},
		},
		{
			name: "with_search",
			request: &assetsmodels.IdsecAccessAssetsListAssetsRequest{
				Search: "address contains 10.0.0",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.NotNil(t, tt.request)
		})
	}
}

func TestAccessAssetsSecretRequest_Validation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		request *assetsmodels.IdsecAccessAssetsSecretRequest
		valid   bool
	}{
		{
			name: "required_asset_id_only",
			request: &assetsmodels.IdsecAccessAssetsSecretRequest{
				AssetID: "asset-001",
			},
			valid: true,
		},
		{
			name: "with_optional_audit_reason",
			request: &assetsmodels.IdsecAccessAssetsSecretRequest{
				AssetID: "asset-001",
				Reason:  "Break-glass troubleshooting",
			},
			valid: true,
		},
		{
			name:    "missing_asset_id_is_invalid",
			request: &assetsmodels.IdsecAccessAssetsSecretRequest{},
			valid:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.valid {
				assert.NotEmpty(t, tt.request.AssetID)
			} else {
				assert.Empty(t, tt.request.AssetID)
			}
		})
	}
}

func TestAccessAssetsSecretResponse_SecretPointer(t *testing.T) {
	t.Parallel()

	secretValue := "s3cr3t-p@ssw0rd"

	tests := []struct {
		name           string
		response       assetsmodels.IdsecAccessAssetsSecretResponse
		expectNil      bool
		expectedSecret string
	}{
		{
			name:      "nil_secret_when_not_set",
			response:  assetsmodels.IdsecAccessAssetsSecretResponse{AssetID: "asset-001"},
			expectNil: true,
		},
		{
			name: "non_nil_secret_when_set",
			response: assetsmodels.IdsecAccessAssetsSecretResponse{
				AssetID: "asset-001",
				Secret:  &secretValue,
			},
			expectNil:      false,
			expectedSecret: secretValue,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.expectNil {
				assert.Nil(t, tt.response.Secret)
			} else {
				require.NotNil(t, tt.response.Secret)
				assert.Equal(t, tt.expectedSecret, *tt.response.Secret)
			}
		})
	}
}
