package registry

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"

	cmgrnetworksactions "github.com/cyberark/idsec-cli-golang/pkg/services/cmgr/networks/actions"
	cmgrpoolcomponentsactions "github.com/cyberark/idsec-cli-golang/pkg/services/cmgr/poolcomponents/actions"
	cmgrpoolidentifiersactions "github.com/cyberark/idsec-cli-golang/pkg/services/cmgr/poolidentifiers/actions"
	cmgrpoolsactions "github.com/cyberark/idsec-cli-golang/pkg/services/cmgr/pools/actions"

	identityauthprofilesactions "github.com/cyberark/idsec-cli-golang/pkg/services/identity/authprofiles/actions"
	identitydirectoriesactions "github.com/cyberark/idsec-cli-golang/pkg/services/identity/directories/actions"
	identitypoliciesactions "github.com/cyberark/idsec-cli-golang/pkg/services/identity/policies/actions"
	identityrolesactions "github.com/cyberark/idsec-cli-golang/pkg/services/identity/roles/actions"
	identityusersactions "github.com/cyberark/idsec-cli-golang/pkg/services/identity/users/actions"

	pcloudaccountsactions "github.com/cyberark/idsec-cli-golang/pkg/services/pcloud/accounts/actions"
	pcloudapplicationsactions "github.com/cyberark/idsec-cli-golang/pkg/services/pcloud/applications/actions"
	pcloudplatformsactions "github.com/cyberark/idsec-cli-golang/pkg/services/pcloud/platforms/actions"
	pcloudsafesactions "github.com/cyberark/idsec-cli-golang/pkg/services/pcloud/safes/actions"
	pcloudtargetplatformsactions "github.com/cyberark/idsec-cli-golang/pkg/services/pcloud/targetplatforms/actions"

	policycloudaccessactions "github.com/cyberark/idsec-cli-golang/pkg/services/policy/cloudaccess/actions"
	policydbactions "github.com/cyberark/idsec-cli-golang/pkg/services/policy/db/actions"
	policygroupaccessactions "github.com/cyberark/idsec-cli-golang/pkg/services/policy/groupaccess/actions"
	policyvmactions "github.com/cyberark/idsec-cli-golang/pkg/services/policy/vm/actions"

	sechubconfigurationsactions "github.com/cyberark/idsec-cli-golang/pkg/services/sechub/configurations/actions"
	sechubfiltersactions "github.com/cyberark/idsec-cli-golang/pkg/services/sechub/filters/actions"
	sechubscansactions "github.com/cyberark/idsec-cli-golang/pkg/services/sechub/scans/actions"
	sechubsecretsactions "github.com/cyberark/idsec-cli-golang/pkg/services/sechub/secrets/actions"
	sechubsecretstoresactions "github.com/cyberark/idsec-cli-golang/pkg/services/sechub/secretstores/actions"
	sechubserviceinfoactions "github.com/cyberark/idsec-cli-golang/pkg/services/sechub/serviceinfo/actions"
	sechubsyncpoliciesactions "github.com/cyberark/idsec-cli-golang/pkg/services/sechub/syncpolicies/actions"

	siaaccessactions "github.com/cyberark/idsec-cli-golang/pkg/services/sia/access/actions"
	siacertificatesactions "github.com/cyberark/idsec-cli-golang/pkg/services/sia/certificates/actions"
	siadbactions "github.com/cyberark/idsec-cli-golang/pkg/services/sia/db/actions"
	siadbstrongaccountsactions "github.com/cyberark/idsec-cli-golang/pkg/services/sia/dbstrongaccounts/actions"
	siak8sactions "github.com/cyberark/idsec-cli-golang/pkg/services/sia/k8s/actions"
	siasecretsdbactions "github.com/cyberark/idsec-cli-golang/pkg/services/sia/secretsdb/actions"
	siasecretsvmactions "github.com/cyberark/idsec-cli-golang/pkg/services/sia/secretsvm/actions"
	siasettingsactions "github.com/cyberark/idsec-cli-golang/pkg/services/sia/settings/actions"
	siashortenedconnectionstringactions "github.com/cyberark/idsec-cli-golang/pkg/services/sia/shortenedconnectionstring/actions"
	siasshcaactions "github.com/cyberark/idsec-cli-golang/pkg/services/sia/sshca/actions"
	siassoactions "github.com/cyberark/idsec-cli-golang/pkg/services/sia/sso/actions"
	siaworkspacesdbactions "github.com/cyberark/idsec-cli-golang/pkg/services/sia/workspacesdb/actions"
	siaworkspacestargetsetsactions "github.com/cyberark/idsec-cli-golang/pkg/services/sia/workspacestargetsets/actions"

	scacloudaccessactions "github.com/cyberark/idsec-cli-golang/pkg/services/sca/cloudaccess/actions"
	scagroupaccessactions "github.com/cyberark/idsec-cli-golang/pkg/services/sca/groupaccess/actions"
	scak8sactions "github.com/cyberark/idsec-cli-golang/pkg/services/sca/k8s/actions"

	smsessionactivitiesactions "github.com/cyberark/idsec-cli-golang/pkg/services/sm/sessionactivities/actions"
	smsessionsactions "github.com/cyberark/idsec-cli-golang/pkg/services/sm/sessions/actions"

	policysdkactions "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/actions"
	scasdkactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/actions"
)

func init() {
	RegisterCLIAction(&actions.IdsecServiceCLIActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "sia",
			ActionDescription: "Secure infrastructure access provides a seamless, agentless SaaS solution for session management, ideal for securing privileged access to targets spread across hybrid and cloud environments. Session management with SIA allows access with Zero Standing Privileges (ZSP) or vaulted credentials",
			ActionVersion:     1,
		},
		ActionAliases: []string{"dpa"},
		Subactions: []*actions.IdsecServiceCLIActionDefinition{
			siassoactions.CLIAction,
			siak8sactions.CLIAction,
			siaworkspacesdbactions.CLIAction,
			siaworkspacestargetsetsactions.CLIAction,
			siasecretsdbactions.CLIAction,
			siasecretsvmactions.CLIAction,
			siadbstrongaccountsactions.CLIAction,
			siaaccessactions.CLIAction,
			siasshcaactions.CLIAction,
			siadbactions.CLIAction,
			siashortenedconnectionstringactions.CLIAction,
			siasettingsactions.CLIAction,
			siacertificatesactions.CLIAction,
		},
	})

	RegisterCLIAction(&actions.IdsecServiceCLIActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "cmgr",
			ActionDescription: "The Connector Management service mediates Identity Security Platform Shared Services (ISPSS) and is used by IT administrators to manage CyberArk components, communication tunnels, networks, and connector pools.",
			ActionVersion:     1,
		},
		ActionAliases: []string{"connectormanager", "cm"},
		Subactions: []*actions.IdsecServiceCLIActionDefinition{
			cmgrnetworksactions.CLIAction,
			cmgrpoolsactions.CLIAction,
			cmgrpoolidentifiersactions.CLIAction,
			cmgrpoolcomponentsactions.CLIAction,
		},
	})

	RegisterCLIAction(&actions.IdsecServiceCLIActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "pcloud",
			ActionDescription: "CyberArk Privilege Cloud is a SaaS solution that enables organizations to securely store, rotate and isolate credentials (for both human and non-human users), monitor sessions, and deliver scalable risk reduction to the business.",
			ActionVersion:     1,
		},
		ActionAliases: []string{"privilegecloud", "pc"},
		Subactions: []*actions.IdsecServiceCLIActionDefinition{
			pcloudaccountsactions.CLIAction,
			pcloudsafesactions.CLIAction,
			pcloudplatformsactions.CLIAction,
			pcloudtargetplatformsactions.CLIAction,
			pcloudapplicationsactions.CLIAction,
		},
	})

	RegisterCLIAction(&actions.IdsecServiceCLIActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "identity",
			ActionDescription: "Identity provides a single centralized interface for provisioning users and setting up the authentication for users of the Shared Services platform.",
			ActionVersion:     1,
		},
		ActionAliases: []string{"idaptive", "id"},
		Subactions: []*actions.IdsecServiceCLIActionDefinition{
			identitydirectoriesactions.CLIAction,
			identityrolesactions.CLIAction,
			identityusersactions.CLIAction,
			identityauthprofilesactions.CLIAction,
			identitypoliciesactions.CLIAction,
		},
	})

	RegisterCLIAction(&actions.IdsecServiceCLIActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "policy",
			ActionDescription: "Access policies define when specified users may access particular assets and for how long. You may use access policies for cloud workspaces, Azure groups, virtual machines, and databases.",
			ActionVersion:     1,
			Schemas:           policysdkactions.ActionToSchemaMap,
		},
		ActionAliases: []string{"accesspolicies", "acp"},
		Subactions: []*actions.IdsecServiceCLIActionDefinition{
			policycloudaccessactions.CLIAction,
			policygroupaccessactions.CLIAction,
			policyvmactions.CLIAction,
			policydbactions.CLIAction,
		},
	})

	RegisterCLIAction(&actions.IdsecServiceCLIActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "sechub",
			ActionDescription: "Secrets Hub is a CyberArk SaaS solution that simplifies managing and consuming secrets in the Cloud Service Providers' native secret managers.",
			ActionVersion:     1,
		},
		ActionAliases: []string{"secretshub", "sh"},
		Subactions: []*actions.IdsecServiceCLIActionDefinition{
			sechubconfigurationsactions.CLIAction,
			sechubfiltersactions.CLIAction,
			sechubscansactions.CLIAction,
			sechubsecretsactions.CLIAction,
			sechubsecretstoresactions.CLIAction,
			sechubserviceinfoactions.CLIAction,
			sechubsyncpoliciesactions.CLIAction,
		},
	})

	RegisterCLIAction(&actions.IdsecServiceCLIActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "sca",
			ActionDescription: "Secure Cloud Access (SCA) operations. List the cloud targets you are eligible to access.",
			ActionVersion:     1,
			Schemas:           scasdkactions.ActionToSchemaMap,
		},
		ActionAliases: []string{"accesssca", "asca"},
		Subactions: []*actions.IdsecServiceCLIActionDefinition{
			scacloudaccessactions.CLIAction,
			scagroupaccessactions.CLIAction,
			scak8sactions.CLIAction,
		},
	})

	RegisterCLIAction(&actions.IdsecServiceCLIActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "sm",
			ActionDescription: "The CyberArk Audit space centralizes session monitoring across all CyberArk services on the Shared Services platform to provide a comprehensive display of all sessions as a unified view. This enables enhanced auditing as well as incident-response investigation.",
			ActionVersion:     1,
		},
		ActionAliases: []string{"sessionmonitoring"},
		Subactions: []*actions.IdsecServiceCLIActionDefinition{
			smsessionsactions.CLIAction,
			smsessionactivitiesactions.CLIAction,
		},
	})
}
