package agentmode

import (
	"strconv"
	"strings"
)

// ResolveFromArgs resolves agent mode from raw argv before Cobra parses flags,
// so failures raised before PersistentPreRun can be reported correctly.
// Recognizes --agent, --agent=<bool>, --no-agent, --no-agent=<bool>; stops at "--".
func ResolveFromArgs(argv []string) {
	Resolve(scanAgentFlags(argv))
}

// scanAgentFlags mirrors pflag bool-flag semantics: the last occurrence wins,
// and a value strconv.ParseBool rejects counts as false.
func scanAgentFlags(argv []string) (flagAgent, flagNoAgent bool) {
	for _, arg := range argv {
		if arg == "--" {
			break
		}
		if v, ok := boolFlagValue(arg, "--agent"); ok {
			flagAgent = v
		} else if v, ok := boolFlagValue(arg, "--no-agent"); ok {
			flagNoAgent = v
		}
	}
	return flagAgent, flagNoAgent
}

func boolFlagValue(arg, name string) (value bool, matched bool) {
	if arg == name {
		return true, true
	}
	raw, ok := strings.CutPrefix(arg, name+"=")
	if !ok {
		return false, false
	}
	v, err := strconv.ParseBool(raw)
	return err == nil && v, true
}
