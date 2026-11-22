package featureadoption

import (
	"context"
	"testing"
	"time"

	"github.com/cyberark/idsec-cli-golang/pkg/agentmode"
)

func TestBuildTags(t *testing.T) {
	t.Parallel()

	got := buildTags(&ReportOptions{
		ExtraTags: map[string]string{
			"cli_command": "exec",
			"":            "empty_key",
			"empty_value": "",
		},
	})

	if len(got) != 2 {
		t.Fatalf("expected 2 tags, got %d: %v", len(got), got)
	}
	if got["cli_command"] != "exec" {
		t.Fatalf("expected cli_command=exec, got %q", got["cli_command"])
	}
	if got[TagKeyCLIAgent] != AgentHumanSlug {
		t.Fatalf("expected cla=%s, got %q", AgentHumanSlug, got[TagKeyCLIAgent])
	}
}

func TestBuildCustomData(t *testing.T) {
	t.Parallel()

	duration := 1234 * time.Millisecond
	got := buildCustomData(&ReportOptions{
		OperationDuration: &duration,
		OperationStatus:   "failure",
		Message:           "some error",
	})

	if got["correlation_id"] == "" {
		t.Fatal("expected correlation_id to be set")
	}
	if got["duration"] != "1234" {
		t.Fatalf("expected duration=1234, got %#v", got["duration"])
	}
	if got["ops"] != "failure" {
		t.Fatalf("expected ops=failure, got %#v", got["ops"])
	}
	if got["message"] != "some error" {
		t.Fatalf("expected message=some error, got %#v", got["message"])
	}
}

func TestReportOperationDefer_NoPanic(t *testing.T) {
	t.Parallel()

	status := "success"
	message := ""
	tags := map[string]string{
		TagKeyCLIService:   "pcloud",
		TagKeyCLIOperation: "create",
		TagKeyCLIResource:  "safes",
		TagKeyCLIVersion:   "0.2.0",
	}
	done := ReportOperationDefer(context.Background(), nil, nil, &status, &message, tags)

	status = "failure"
	message = "failed execution"

	done()
}

func TestReportOperationDefer_NilTags(t *testing.T) {
	t.Parallel()

	status := "success"
	message := ""
	done := ReportOperationDefer(context.Background(), nil, nil, &status, &message, nil)
	done()
}

// setAgentState clears every agent-mode env input, applies the provided env overrides,
// calls Resolve with the given flags, and restores human-mode state on test cleanup.
// Must not be called from a t.Parallel() test.
func setAgentState(t *testing.T, env map[string]string, flagAgent, flagNoAgent bool) {
	t.Helper()
	// Registered first so it runs last (LIFO), after t.Setenv restores the env.
	t.Cleanup(func() { agentmode.Resolve(false, false) })
	t.Setenv(agentmode.EnvVar, "")
	t.Setenv(agentmode.ForceEnvVar, "")
	for _, v := range agentmode.DetectorEnvVars() {
		t.Setenv(v, "")
	}
	for k, v := range env {
		t.Setenv(k, v)
	}
	agentmode.Resolve(flagAgent, flagNoAgent)
}

// assertCLATag asserts that the cla tag is present and has the expected value.
// cla is always set by buildTags so a missing key is always a bug.
func assertCLATag(t *testing.T, got map[string]string, wantCLA string) {
	t.Helper()
	v, ok := got[TagKeyCLIAgent]
	if !ok {
		t.Errorf("expected cla=%q but tag was absent", wantCLA)
		return
	}
	if v != wantCLA {
		t.Errorf("expected cla=%q, got cla=%q", wantCLA, v)
	}
}

func TestBuildTags_AgentTag(t *testing.T) {
	type tc struct {
		name        string
		env         map[string]string
		flagAgent   bool
		flagNoAgent bool
		nilOpts     bool
		extraTags   map[string]string
		wantCLA     string
		wantLen     int
	}

	base := map[string]string{TagKeyCLIService: "pcloud"}

	cases := []tc{
		// Agent detected via env var
		{name: "auto-detected claudecode", env: map[string]string{"CLAUDECODE": "1"}, extraTags: base, wantCLA: "claude-code", wantLen: 2},
		{name: "auto-detected cursor", env: map[string]string{"CURSOR_AGENT": "1"}, extraTags: base, wantCLA: "cursor", wantLen: 2},
		{name: "first-match wins", env: map[string]string{"CLAUDECODE": "1", "AGENT": "1"}, extraTags: base, wantCLA: "claude-code", wantLen: 2},
		{name: "catch-all generic", env: map[string]string{"AGENT": "1"}, extraTags: base, wantCLA: "generic", wantLen: 2},
		// Flag and env force-on
		{name: "flag agent inside agent", env: map[string]string{"CLAUDECODE": "1"}, flagAgent: true, extraTags: base, wantCLA: "claude-code", wantLen: 2},
		{name: "IDSEC_FORCE_AGENT_MODE with agent", env: map[string]string{"CURSOR_AGENT": "1", agentmode.ForceEnvVar: "1"}, extraTags: base, wantCLA: "cursor", wantLen: 2},
		// Disabled by env or flag
		{name: "detected but disabled by env", env: map[string]string{"CLAUDECODE": "1", agentmode.EnvVar: "0"}, extraTags: base, wantCLA: "human", wantLen: 2},
		{name: "detected but disabled by flag", env: map[string]string{"CURSOR_AGENT": "1"}, flagNoAgent: true, extraTags: base, wantCLA: "human", wantLen: 2},
		// Enabled but no slug
		{name: "enabled no slug flag", flagAgent: true, extraTags: base, wantCLA: "unknown", wantLen: 2},
		{name: "enabled no slug env", env: map[string]string{agentmode.EnvVar: "1"}, extraTags: base, wantCLA: "unknown", wantLen: 2},
		// Human mode
		{name: "human mode", extraTags: base, wantCLA: "human", wantLen: 2},
		{name: "human mode nil opts", nilOpts: true, wantCLA: "human", wantLen: 1},
		{name: "agent mode nil opts", env: map[string]string{"CLAUDECODE": "1"}, nilOpts: true, wantCLA: "claude-code", wantLen: 1},
		// Caller-supplied cla is overridden / discarded
		{name: "caller cla discarded in human mode", extraTags: map[string]string{TagKeyCLIService: "pcloud", TagKeyCLIAgent: "spoof"}, wantCLA: "human", wantLen: 2},
		{name: "caller cla overridden in agent mode", env: map[string]string{"CLAUDECODE": "1"}, extraTags: map[string]string{TagKeyCLIAgent: "spoof"}, wantCLA: "claude-code", wantLen: 1},
		// Full exec tag set preserved
		{
			name: "full exec tags preserved in agent mode",
			env:  map[string]string{"CLAUDECODE": "1"},
			extraTags: map[string]string{
				TagKeyCLIService: "pcloud", TagKeyCLIOperation: "create",
				TagKeyCLIResource: "safes", TagKeyCLIVersion: "0.2.0",
			},
			wantCLA: "claude-code", wantLen: 5,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// sequential: t.Setenv panics in t.Parallel
			setAgentState(t, c.env, c.flagAgent, c.flagNoAgent)
			var opts *ReportOptions
			if !c.nilOpts {
				opts = &ReportOptions{ExtraTags: c.extraTags}
			}
			got := buildTags(opts)
			assertCLATag(t, got, c.wantCLA)
			if len(got) != c.wantLen {
				t.Errorf("expected %d tags, got %d: %v", c.wantLen, len(got), got)
			}
		})
	}
}
