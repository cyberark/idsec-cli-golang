// Package agentmode resolves whether the idsec CLI is being driven by an
// autonomous agent and holds that state for the lifetime of the process.
//
// agentmode is a leaf package: it imports only the standard library so that
// pkg/actions, pkg/common/args and cmd/idsec can all depend on it.
package agentmode

import (
	"os"
	"strings"
)

// EnvVar forces agent mode on or off from the environment (or config.yaml).
// Accepted values: 1/true/yes/on (on) and 0/false/no/off (off).
const EnvVar = "IDSEC_AGENT_MODE"

// ForceEnvVar hard-forces agent mode ON from the environment (or config.yaml).
// It is a pup-compatible alias that overrides EnvVar but is still overridden
// by the --no-agent flag. Any truthy value (1/true/yes/on) activates it;
// falsy values (0/false/no/off) are treated as "not set" (force never forces OFF).
const ForceEnvVar = "IDSEC_FORCE_AGENT_MODE"

// Source identifies which precedence level decided the agent-mode state.
type Source string

const (
	SourceFlag       Source = "flag"
	SourceEnv        Source = "env"
	SourceAutoDetect Source = "auto-detect"
	SourceDefault    Source = "default"
)

// State is written by Resolve during command start-up on the main goroutine,
// before any goroutine that reads it is spawned.
var (
	enabled      bool
	detectedSlug string
	source       = SourceDefault
)

// enable turns agent mode on and records the detected agent slug.
// Callers outside this package must use Resolve; direct use of enable
// is reserved for Resolve and internal tests.
func enable(slug string) {
	enabled = true
	detectedSlug = slug
}

// disable turns agent mode off. The detected slug is kept so that a human
// override (--no-agent inside an agent terminal) remains attributable.
func disable() {
	enabled = false
}

// IsEnabled reports whether agent mode is on for this invocation.
func IsEnabled() bool {
	return enabled
}

// DetectedAgent returns the slug of the detected agent, or
// "" if none was detected. It is populated whether or not agent mode is
// enabled; callers that only care about agent invocations must also check
// IsEnabled.
func DetectedAgent() string {
	return detectedSlug
}

// ResolvedSource returns which precedence level decided the current state.
func ResolvedSource() Source {
	return source
}

// Resolve computes agent-mode state from the parsed flags, IDSEC_AGENT_MODE, IDSEC_FORCE_AGENT_MODE and the
// detector registry, and overwrites any previous state. It is idempotent.
func Resolve(flagAgent bool, flagNoAgent bool) {
	slug, autoEnable := detect()
	on, src := decide(flagAgent, flagNoAgent, autoEnable)
	source = src
	detectedSlug = slug
	if on {
		enable(slug)
	} else {
		disable()
	}
}

func decide(flagAgent, flagNoAgent, autoEnable bool) (bool, Source) {
	switch {
	case flagNoAgent:
		return false, SourceFlag
	case flagAgent:
		return true, SourceFlag
	}
	// IDSEC_FORCE_AGENT_MODE: hard force-on (never force-off, so ignore falsy values)
	if on, ok := parseEnvBool(os.Getenv(ForceEnvVar)); ok && on {
		return true, SourceEnv
	}
	// IDSEC_AGENT_MODE: explicit on or off
	if on, ok := parseEnvBool(os.Getenv(EnvVar)); ok {
		return on, SourceEnv
	}
	if autoEnable {
		return true, SourceAutoDetect
	}
	return false, SourceDefault
}

func parseEnvBool(v string) (value bool, ok bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true, true
	case "0", "false", "no", "off":
		return false, true
	}
	return false, false
}
