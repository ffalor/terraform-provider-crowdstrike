package acctest

import (
	"os"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

const (
	ProviderConfig = `
provider "crowdstrike" {}
`
	CharSetNum = "0123456789"

	// FalconClientIDEnvVar is the environment variable for the Falcon Client ID
	FalconClientIDEnvVar = "FALCON_CLIENT_ID"
	// FalconClientSecretEnvVar is the environment variable for the Falcon Client Secret
	FalconClientSecretEnvVar = "FALCON_CLIENT_SECRET"
	// HostGroupIDEnvVar is the environment variable for the Host Group ID
	HostGroupIDEnvVar = "HOST_GROUP_ID"
	// IOARuleGroupIDEnvVar is the environment variable for the IOA Rule Group ID
	IOARuleGroupIDEnvVar = "IOA_RULE_GROUP_ID"
)

// ProtoV6ProviderFactories are used to instantiate a provider during
// acceptance testing. The factory function will be invoked for every Terraform
// CLI command executed to create a provider server to which the CLI can
// reattach.
var ProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"crowdstrike": providerserver.NewProtocol6WithError(provider.New("test")()),
}

func PreCheck(t *testing.T, additionalVars ...string) {
	requiredEnvVars := []string{
		FalconClientIDEnvVar,
		FalconClientSecretEnvVar,
	}
	requiredEnvVars = append(requiredEnvVars, additionalVars...)

	for _, envVar := range requiredEnvVars {
		if v := os.Getenv(envVar); v == "" {
			t.Fatalf("%s must be set for acceptance tests", envVar)
		}
	}
}
