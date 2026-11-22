package agentmode

import "os"

type detector struct {
	envVar string
	slug   string
}

// agentDetectors identify AI coding agents. A match enables agent mode at the
// auto-detect precedence level. Order matters: first non-empty match wins.
var agentDetectors = []detector{
	{"CLAUDECODE", "claude-code"},
	{"CLAUDE_CODE", "claude-code"},
	{"CURSOR_AGENT", "cursor"},
	{"CODEX", "codex"},
	{"OPENAI_CODEX", "codex"},
	{"AIDER", "aider"},
	{"CLINE", "cline"},
	{"WINDSURF_AGENT", "windsurf"},
	{"GITHUB_COPILOT", "copilot"},
	{"AMAZON_Q", "amazon-q"},
	{"AWS_Q_DEVELOPER", "amazon-q"},
	{"GEMINI_CODE_ASSIST", "gemini"},
	{"SRC_CODY", "cody"},
	{"PI_CODING_AGENT", "pi"},
	{"AGENT", "generic"},
}

// Detect returns the slug of the first matching detector, or "" when no
// known agent is present.
func Detect() string {
	slug, _ := detect()
	return slug
}

// DetectorEnvVars returns every environment variable consulted by Detect, in
// evaluation order. The returned slice is a copy.
func DetectorEnvVars() []string {
	vars := make([]string, 0, len(agentDetectors))
	for _, d := range agentDetectors {
		vars = append(vars, d.envVar)
	}
	return vars
}

func detect() (slug string, autoEnable bool) {
	slug = firstMatch(agentDetectors)
	return slug, slug != ""
}

func firstMatch(detectors []detector) string {
	for _, d := range detectors {
		if os.Getenv(d.envVar) != "" {
			return d.slug
		}
	}
	return ""
}
