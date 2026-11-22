package featureadoption

import (
	"os"
	"testing"

	"github.com/cyberark/idsec-cli-golang/pkg/agentmode"
)

func TestMain(m *testing.M) {
	_ = os.Unsetenv(agentmode.EnvVar)
	_ = os.Unsetenv(agentmode.ForceEnvVar)
	for _, v := range agentmode.DetectorEnvVars() {
		_ = os.Unsetenv(v)
	}
	os.Exit(m.Run())
}
