package actions

// Kubectl-login CLI logging. See SDK idsec_sca_k8s_kubectl_login_diagnostics.go.
// Call sites: kubectlLoginVerbose/Info/Warning/Error.

import (
	"os"
	"strings"
	"time"

	"github.com/cyberark/idsec-sdk-golang/pkg/config"
	k8sservice "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s"
)

const idsecVerboseEnvVar = "IDSEC_VERBOSE"

func kubectlLoginDiagnosticsEnabled() bool {
	switch strings.TrimSpace(strings.ToLower(os.Getenv(idsecVerboseEnvVar))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func kubectlLoginLog(level k8sservice.KubectlLoginLogLevel, format string, args ...any) {
	switch level {
	case k8sservice.KubectlLoginLogLevelWarning, k8sservice.KubectlLoginLogLevelError:
		k8sservice.KubectlLoginLogLine(os.Stderr, level, format, args...)
	default:
		if !kubectlLoginDiagnosticsEnabled() {
			return
		}
		k8sservice.KubectlLoginLog(level, format, args...)
	}
}

func kubectlLoginVerbose(format string, args ...any) {
	kubectlLoginLog(k8sservice.KubectlLoginLogLevelDebug, format, args...)
}

func kubectlLoginInfo(format string, args ...any) {
	kubectlLoginLog(k8sservice.KubectlLoginLogLevelInfo, format, args...)
}

func kubectlLoginWarning(format string, args ...any) {
	kubectlLoginLog(k8sservice.KubectlLoginLogLevelWarning, format, args...)
}

func kubectlLoginError(format string, args ...any) {
	kubectlLoginLog(k8sservice.KubectlLoginLogLevelError, format, args...)
}

func kubectlLoginVerboseDuration(phase string, startedAt time.Time) {
	kubectlLoginLog(
		k8sservice.KubectlLoginLogLevelDebug,
		"%s completed in %s",
		phase,
		time.Since(startedAt).Round(time.Millisecond),
	)
}

func kubectlLoginVerboseExecCredentialTTL(
	flow string,
	candidates []ttlCandidate,
	effective time.Time,
	picked string,
	computeErr error,
) {
	format := func(t time.Time) string {
		if t.IsZero() {
			return "-"
		}
		return t.UTC().Format(time.RFC3339)
	}

	kubectlLoginVerbose("%s effective TTL candidates:", flow)
	for _, c := range candidates {
		if c.when.IsZero() {
			reason := c.skipReason
			if reason == "" {
				reason = "empty expiration"
			}
			kubectlLoginVerbose("  %s: skipped (%s)", c.name, reason)
			continue
		}
		source := "raw"
		if c.alreadyBuffered {
			source = "already-buffered"
		}
		kubectlLoginVerbose("  %s: raw=%s effective=%s source=%s skew=%s",
			c.name, format(c.when), format(c.effective()), source, c.skew)
	}
	if computeErr != nil {
		kubectlLoginVerbose("%s effective TTL: computation failed (%v)", flow, computeErr)
		return
	}
	if effective.IsZero() {
		kubectlLoginVerbose("%s effective TTL: no usable candidates", flow)
		return
	}
	kubectlLoginVerbose("%s effective TTL: selected=%s expirationTimestamp=%s",
		flow, picked, format(effective))
}

func exitErr(msg string) {
	kubectlLoginError("%s", msg)
	if !kubectlLoginDiagnosticsEnabled() {
		kubectlLoginWarning("hint: re-run with IDSEC_VERBOSE=true set for step-by-step diagnostics")
	}
	os.Exit(1)
}

// setupKubectlLoginLogging silences SDK stdout (CRITICAL) and seeds KUBELOGIN from LOG_LEVEL when unset.
func setupKubectlLoginLogging() func() {
	originalLogLevel, logLevelEnvSet := os.LookupEnv(config.IdsecLogLevelEnvVar)
	originalKubectlLevel, kubectlLevelEnvSet := os.LookupEnv(k8sservice.KubectlLoginLogLevelEnvVar)
	inheritedKubectlLevel := !kubectlLevelEnvSet && logLevelEnvSet

	if inheritedKubectlLevel {
		_ = os.Setenv(k8sservice.KubectlLoginLogLevelEnvVar, originalLogLevel)
	}
	_ = os.Setenv(config.IdsecLogLevelEnvVar, "CRITICAL")

	return func() {
		if logLevelEnvSet {
			_ = os.Setenv(config.IdsecLogLevelEnvVar, originalLogLevel)
		} else {
			_ = os.Unsetenv(config.IdsecLogLevelEnvVar)
		}
		if inheritedKubectlLevel {
			_ = os.Unsetenv(k8sservice.KubectlLoginLogLevelEnvVar)
		} else if kubectlLevelEnvSet {
			_ = os.Setenv(k8sservice.KubectlLoginLogLevelEnvVar, originalKubectlLevel)
		}
	}
}
