package actions

var (
	configurationAuthenticatorIgnoredDefinitionKeys = map[string][]string{
		"isp": {"identity-application", "identity-tenant-url"},
	}

	configurationAuthenticatorIgnoredInteractiveKeys = map[string][]string{
		"isp": {
			"identity-application",
			"identity-application-id",
			"identity-tenant-url",
			"identity-mfa-interactive",
		},
	}

	configurationAllowedEmptyValues = map[string][]string{
		"isp": {
			"identity-url",
			"identity-tenant-subdomain",
			"identity-mfa-method",
		},
	}

	configurationDefaultInteractiveValues = map[string]map[string]interface{}{
		"isp": {
			"identity-mfa-interactive": true,
		},
	}
)
