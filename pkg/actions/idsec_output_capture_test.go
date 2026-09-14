package actions

import (
	"github.com/cyberark/idsec-cli-golang/pkg/actions/testutils"
	"github.com/cyberark/idsec-sdk-golang/pkg/config"
)

// withCapturedOutput enables plain (non-colored) output, captures stdout while fn runs,
// and restores the previous config afterwards. It is intentionally not run in parallel
// because it mutates global config and os.Stdout.
func withCapturedOutput(fn func()) string {
	config.AllowOutput()
	config.DisableColor()
	defer func() {
		config.DisallowOutput()
		config.EnableColor()
	}()
	return testutils.CaptureOutput(fn)
}
