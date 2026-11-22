package main

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/cyberark/idsec-cli-golang/pkg/agentmode"
	"github.com/cyberark/idsec-sdk-golang/pkg/config"
)

// runMainAgent runs argv through handleCommandExecution on the real command
// tree with agent mode on and an empty profiles folder.
func runMainAgent(t *testing.T, argv ...string) (exits []int, stdout, stderr string) {
	t.Helper()
	return runMain(t, true, argv...)
}

// runMain is runMainAgent with agent mode on or off. Like main, the tree
// reads os.Args, so shorthand re-routing sees the rewritten argv.
func runMain(t *testing.T, agent bool, argv ...string) (exits []int, stdout, stderr string) {
	t.Helper()
	coloring, interactive, allowOutput := config.IsColoring(), config.IsInteractive(), config.IsAllowingOutput()
	t.Cleanup(func() {
		setConfig(coloring, config.EnableColor, config.DisableColor)
		setConfig(interactive, config.EnableInteractive, config.DisableInteractive)
		setConfig(allowOutput, config.AllowOutput, config.DisallowOutput)
	})
	setAgentMode(t, agent)
	if agent {
		t.Setenv(agentmode.EnvVar, "1")
	}
	t.Setenv("HOME", t.TempDir())
	t.Setenv("IDSEC_PROFILES_FOLDER", t.TempDir())
	t.Setenv("DEPLOY_ENV", "prod")
	setOSArgs(t, append([]string{"idsec"}, argv...)...)
	codes := stubOSExit(t)
	root := newMainRoot()
	setupDefaultRouting(root)
	stdout, stderr = captureStdio(t, func() { handleCommandExecution(root) })
	return *codes, stdout, stderr
}

func setConfig(on bool, enable, disable func()) {
	if on {
		enable()
	} else {
		disable()
	}
}

func TestMainAgent_StatusQuietAndConfigure(t *testing.T) {
	cases := []struct {
		name        string
		argv        []string
		wantCode    agentmode.Code
		wantDetails map[string]any
		// wantStderr is set when the envelope message is redacted; empty means
		// stderr carries the envelope message.
		wantStderr string
	}{
		{
			name:        "status_quiet_unknown_flag",
			argv:        []string{"status", "--quiet", "--bogus"},
			wantCode:    agentmode.CodeInvalidInput,
			wantDetails: map[string]any{"kind": agentmode.KindUnknownFlag, "command": "idsec status", "flag": "bogus"},
		},
		{
			name:        "status_quiet_invalid_query",
			argv:        []string{"status", "--quiet", "--query", ".["},
			wantCode:    agentmode.CodeInvalidInput,
			wantDetails: map[string]any{"kind": agentmode.KindInvalidQuery},
			wantStderr:  "invalid jq query \".[\": unexpected EOF\n",
		},
		{
			name:        "configure_plain_validate",
			argv:        []string{"configure", "--silent", "--work-with-isp=false"},
			wantCode:    agentmode.CodeConfigError,
			wantDetails: map[string]any{"source": "configure", "stage": "validate"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			exits, stdout, stderr := runMainAgent(t, tc.argv...)

			if !reflect.DeepEqual(exits, []int{1}) {
				t.Errorf("exits = %v, want [1]", exits)
			}
			env := decodeEnvelope(t, stdout)
			if env.Error.Code != tc.wantCode {
				t.Errorf("code = %q, want %q (envelope %+v)", env.Error.Code, tc.wantCode, env.Error)
			}
			details, _ := env.Error.Details.(map[string]any)
			for k, want := range tc.wantDetails {
				if got := details[k]; got != want {
					t.Errorf("details[%q] = %#v, want %#v", k, got, want)
				}
			}
			wantStderr := tc.wantStderr
			if wantStderr == "" {
				wantStderr = env.Error.Message + "\n"
			}
			if stderr != wantStderr {
				t.Errorf("stderr = %q, want the error once: %q", stderr, wantStderr)
			}
		})
	}
}

func TestMainAgent_StatusQuietProfileMissing(t *testing.T) {
	exits, stdout, stderr := runMainAgent(t, "status", "--quiet", "--profile-name", "nosuch")

	if !reflect.DeepEqual(exits, []int{2}) {
		t.Errorf("exits = %v, want [2]", exits)
	}
	if stdout != "" || stderr != "" {
		t.Errorf("stdout = %q, stderr = %q, want both empty", stdout, stderr)
	}
}

// An undefined flag is reported as the flag error human mode gives, not as
// an incomplete command.
func TestMainAgent_UndefinedFlagBeatsIncompleteCommand(t *testing.T) {
	for _, argv := range [][]string{
		{"--bogus"},
		{"--bogus", "--agent"},
		{"--config", "f.yaml", "--bogus"},
		{"exec", "pcloud", "--bogus"},
		{"exec", "pcloud", "--config", "f.yaml", "--bogus"},
		{"pcloud", "--bogus"},
	} {
		t.Run(fmt.Sprint(argv), func(t *testing.T) {
			exits, stdout, stderr := runMainAgent(t, argv...)

			if !reflect.DeepEqual(exits, []int{1}) {
				t.Errorf("exits = %v, want [1]", exits)
			}
			env := decodeEnvelope(t, stdout)
			details, _ := env.Error.Details.(map[string]any)
			if env.Error.Code != agentmode.CodeInvalidInput || details["kind"] != agentmode.KindUnknownFlag || details["flag"] != "bogus" {
				t.Errorf("error = %+v", env.Error)
			}
			if stderr != "unknown flag: --bogus\n" {
				t.Errorf("stderr = %q", stderr)
			}
		})
	}
	for _, argv := range [][]string{
		{"--agent"},
		{"--config", "f.yaml", "--agent"},
		{"--config=f.yaml", "--agent"},
		{"--config", "-f.yaml", "--agent"},
		{"exec", "pcloud", "--agent"},
		{"exec", "pcloud", "--agent=true"},
		{"exec", "pcloud", "--config", "f.yaml", "--agent"},
		{"exec", "pcloud", "--config", "-f.yaml", "--agent"},
	} {
		t.Run(fmt.Sprint(argv)+"/still_incomplete", func(t *testing.T) {
			setAgentMode(t, true)
			setOSArgs(t, append([]string{"idsec"}, argv...)...)

			err := validateCommandPathBeforeExecution(newMainRoot())

			var f *agentmode.Failure
			if !errors.As(err, &f) || f.Details["kind"] != agentmode.KindIncompleteCommand {
				t.Errorf("err = %#v, want incomplete_command", err)
			}
		})
	}
	t.Run("config_end_to_end", func(t *testing.T) {
		exits, stdout, _ := runMainAgent(t, "--config", "f.yaml", "--agent")

		if !reflect.DeepEqual(exits, []int{1}) {
			t.Errorf("exits = %v, want [1]", exits)
		}
		env := decodeEnvelope(t, stdout)
		details, _ := env.Error.Details.(map[string]any)
		if env.Error.Code != agentmode.CodeUnknownCommand || details["kind"] != agentmode.KindIncompleteCommand || details["parent"] != "idsec" {
			t.Errorf("error = %+v", env.Error)
		}
	})
}
