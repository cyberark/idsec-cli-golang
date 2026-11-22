package actions

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/cyberark/idsec-cli-golang/pkg/agentmode"
	"github.com/cyberark/idsec-cli-golang/pkg/common/args"
	"github.com/cyberark/idsec-cli-golang/pkg/registry"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	sdkactions "github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
)

// assertSuccessEnvelope checks the decoded envelope of an agent-mode success.
func assertSuccessEnvelope(t *testing.T, out string, wantData any, wantCount *float64, wantMsg string) map[string]any {
	t.Helper()
	v := decodeOneObject(t, out)
	if v["status"] != "success" {
		t.Fatalf("status = %v in %q", v["status"], out)
	}
	if got, ok := v["data"]; !ok || !reflect.DeepEqual(got, wantData) {
		t.Fatalf("data = %#v (present=%v), want %#v", got, ok, wantData)
	}
	if wantCount == nil {
		if _, ok := v["count"]; ok {
			t.Fatalf("count should be absent: %q", out)
		}
	} else if v["count"] != *wantCount {
		t.Fatalf("count = %v, want %v", v["count"], *wantCount)
	}
	if _, ok := v["truncated"]; ok {
		t.Fatalf("truncated should be absent: %q", out)
	}
	if wantMsg != "" && v["message"] != wantMsg {
		t.Fatalf("message = %v, want %q", v["message"], wantMsg)
	}
	return v
}

// TestExecSuccess_KindsByMode runs real exec commands (cobra tree ->
// runExecAction -> RetryCall -> RunExecAction -> SDK service -> fake backend)
// in agent and human mode.
func TestExecSuccess_KindsByMode(t *testing.T) {
	for _, mode := range []string{"agent", "human"} {
		for _, tt := range execKindCases(t) {
			t.Run(mode+"/"+tt.name, func(t *testing.T) {
				h := newExecFake(t, mode == "agent", nil)
				out, _, err := h.run(tt.path, tt.flags...)
				if err != nil {
					t.Fatalf("exec = %v", err)
				}
				if mode == "human" {
					if out != tt.human {
						t.Fatalf("human stdout =\n%q\nwant\n%q", out, tt.human)
					}
					return
				}
				assertSuccessEnvelope(t, out, tt.agentData, tt.agentCount, tt.agentMsg)
			})
		}
	}
}

// TestExecSuccess_SeamKindsByMode covers the kinds no real SDK service returns
// without a network (map, bool, non-paged channel, nil pointer) by feeding the
// output layer directly: renderAgentSuccess in agent mode, the unchanged
// serializeAndPrintOutput in human mode.
func TestExecSuccess_SeamKindsByMode(t *testing.T) {
	for _, mode := range []string{"agent", "human"} {
		for _, tt := range seamKindCases() {
			t.Run(mode+"/"+tt.name, func(t *testing.T) {
				setExecAgentMode(t, mode == "agent")
				var err error
				out := withCapturedOutput(func() {
					s := NewIdsecServiceExecAction(nil)
					if mode == "agent" {
						err = s.renderAgentSuccess(tt.mk(), "list-things", newSuccessExecCmd(t, ""))
					} else {
						s.serializeAndPrintOutput(tt.mk(), "list-things", 0)
					}
				})
				if err != nil {
					t.Fatal(err)
				}
				if mode == "human" {
					if out != tt.human {
						t.Fatalf("human stdout = %q, want %q", out, tt.human)
					}
					return
				}
				assertSuccessEnvelope(t, out, tt.agentData, tt.agentCount, tt.agentMsg)
			})
		}
	}
}

// countingFormatter records its calls.
type countingFormatter struct{ calls *int }

func (f countingFormatter) Format(any) string {
	*f.calls++
	return "\x1b[31mFORMATTED\x1b[0m"
}

// setFormatter installs a formatter on the cmgr pools "list" action definition
// for the test.
func setFormatter(t *testing.T, f sdkactions.CLIFormatter) {
	t.Helper()
	for _, top := range registry.TopLevelCLIActions() {
		if top.ActionName != "cmgr" {
			continue
		}
		for _, sub := range top.Subactions {
			if sub.ActionName != "pools" {
				continue
			}
			prev := sub.Formatters
			sub.Formatters = map[string]sdkactions.CLIFormatter{"list": f}
			t.Cleanup(func() { sub.Formatters = prev })
			return
		}
	}
	t.Fatal("cmgr pools action definition not found")
}

func TestExecSuccess_FormatterBackedAction(t *testing.T) {
	tests := []struct {
		name      string
		agent     bool
		wantCalls int
	}{
		{name: "agent_mode_bypasses_formatter", agent: true, wantCalls: 0},
		{name: "human_mode_uses_formatter", agent: false, wantCalls: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			setFormatter(t, countingFormatter{calls: &calls})
			prevTTY := args.IsStdoutTTY
			args.IsStdoutTTY = func() bool { return true }
			t.Cleanup(func() { args.IsStdoutTTY = prevTTY })

			h := newExecFake(t, tt.agent, nil)
			out, _, err := h.run([]string{"cmgr", "pools", "list"}, "--page-size", "1", "--format", "table")
			if err != nil {
				t.Fatal(err)
			}
			if calls != tt.wantCalls {
				t.Fatalf("formatter calls = %d, want %d", calls, tt.wantCalls)
			}
			if !tt.agent {
				if !strings.Contains(out, "FORMATTED") {
					t.Fatalf("human stdout = %q, want formatter output", out)
				}
				return
			}
			if strings.Contains(out, "\x1b[") {
				t.Fatalf("stdout has ANSI escapes: %q", out)
			}
			v := decodeOneObject(t, out)
			if v["status"] != "success" || v["count"] != 1.0 {
				t.Fatalf("envelope = %v", v)
			}
		})
	}
}

func TestExecSuccess_Query(t *testing.T) {
	engines := execKindCases(t)[0].agentData.([]any)
	tests := []struct {
		name      string
		path      []string
		flags     []string
		wantData  any
		wantCount *float64
	}{
		{name: "one_result", path: []string{"cmgr", "pools", "stats"}, flags: []string{"--query", ".pools_count"}, wantData: 1.0},
		{name: "several_results", path: []string{"sia", "workspaces-db", "list-engine-types"}, flags: []string{"--query", ".[0:2][]"}, wantData: engines[0:2], wantCount: f64p(2)},
		{name: "empty", path: []string{"cmgr", "pools", "stats"}, flags: []string{"--query", "empty"}, wantData: []any{}, wantCount: f64p(0)},
		{name: "raw_is_ignored", path: []string{"sia", "workspaces-db", "list-engine-types"}, flags: []string{"--query", ".[0]", "--raw"}, wantData: engines[0]},
		{name: "query_not_applied_to_envelope", path: []string{"cmgr", "pools", "stats"}, flags: []string{"--query", ".status"}, wantData: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newExecFake(t, true, nil)
			out, _, err := h.run(tt.path, tt.flags...)
			if err != nil {
				t.Fatal(err)
			}
			assertSuccessEnvelope(t, out, tt.wantData, tt.wantCount, "")
		})
	}
}

func TestExecSuccess_InvalidQueryIsInvalidInputAndWritesNothing(t *testing.T) {
	for _, query := range []string{".[", ".a | error(\"x\")"} {
		t.Run(query, func(t *testing.T) {
			h := newExecFake(t, true, nil)
			out, _, err := h.run([]string{"cmgr", "pools", "stats"}, "--query", query)
			if err == nil {
				t.Fatal("expected an error")
			}
			if out != "" {
				t.Fatalf("stdout = %q, want empty", out)
			}
			if f := failureOf(t, err); f.Code != agentmode.CodeInvalidInput {
				t.Fatalf("code = %q, want %q", f.Code, agentmode.CodeInvalidInput)
			}
		})
	}
}

func TestExecSuccess_PartialAuthWarning(t *testing.T) {
	tests := []struct {
		name         string
		agent        bool
		wantWarnings []any
	}{
		{name: "agent_mode_warning_in_envelope", agent: true, wantWarnings: []any{partialAuthMessage}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newExecFake(t, tt.agent, nil, "pvwa")
			out, stderr, err := h.run([]string{"sm", "sessions", "count"})
			if err != nil {
				t.Fatal(err)
			}
			v := assertSuccessEnvelope(t, out, 3.0, nil, "")
			if !reflect.DeepEqual(v["warnings"], tt.wantWarnings) {
				t.Fatalf("warnings = %v, want %v", v["warnings"], tt.wantWarnings)
			}
			if strings.Contains(stderr, partialAuthMessage) {
				t.Fatalf("stderr repeats the warning: %q", stderr)
			}
		})
	}
}

func TestExecSuccess_PartialAuthWarningAbsentWhenFullyAuthenticated(t *testing.T) {
	h := newExecFake(t, true, nil)
	out, _, err := h.run([]string{"sm", "sessions", "count"})
	if err != nil {
		t.Fatal(err)
	}
	if v := assertSuccessEnvelope(t, out, 3.0, nil, ""); v["warnings"] != nil {
		t.Fatalf("warnings = %v, want none", v["warnings"])
	}
}

// TestExecSuccess_RetryEmitsOneEnvelope drives common.RetryCall through the
// real exec path: the first attempt fails with a backend 500, the second
// succeeds. Exactly one success envelope reaches stdout.
func TestExecSuccess_RetryEmitsOneEnvelope(t *testing.T) {
	gets := 0
	h := newExecFake(t, true, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/pool-service/pools/p1" {
			http.NotFound(w, r)
			return
		}
		gets++
		if gets == 1 {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		_, _ = io.WriteString(w, `{"id":"p1","name":"alpha","assigned_network_ids":["n1"]}`)
	})
	out, stderr, err := h.run([]string{"cmgr", "pools", "get"}, "--pool-id", "p1", "--retry-count", "2")
	if err != nil {
		t.Fatalf("exec = %v (stderr %q)", err, stderr)
	}
	if gets != 2 {
		t.Fatalf("backend GETs = %d, want 2 (one failure, one success)", gets)
	}
	if !strings.Contains(stderr, "Retrying in") {
		t.Fatalf("stderr = %q, want the retry notice", stderr)
	}
	v := assertSuccessEnvelope(t, out, map[string]any{
		"pool_id": "p1", "name": "alpha", "assigned_network_ids": []any{"n1"}, "created_at": "", "updated_at": "",
	}, nil, "")
	if v["error"] != nil {
		t.Fatalf("unexpected error member: %v", v)
	}
}

func TestExecSuccess_RetriesExhaustedWritesNoSuccessEnvelope(t *testing.T) {
	h := newExecFake(t, true, failBackend)
	out, _, err := h.run([]string{"cmgr", "pools", "get"}, "--pool-id", "p1", "--retry-count", "1")
	if err == nil {
		t.Fatal("expected an error")
	}
	if out != "" {
		t.Fatalf("stdout = %q, want empty", out)
	}
}

// brokenStdout points os.Stdout at a pipe whose read end is closed, so every
// write fails with EPIPE.
func brokenStdout(t *testing.T) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	prev := os.Stdout
	os.Stdout = w
	t.Cleanup(func() {
		os.Stdout = prev
		_ = w.Close()
	})
}

type unmarshalable struct{}

func (unmarshalable) MarshalJSON() ([]byte, error) { return nil, io.ErrUnexpectedEOF }

// captureActionLog replaces s's logger with one writing to a buffer.
func captureActionLog(s *IdsecServiceExecAction) *bytes.Buffer {
	buf := &bytes.Buffer{}
	l := common.NewIdsecLogger("test", common.Warning, true, false)
	l.SetOutput(buf)
	s.IdsecBaseExecAction.logger = l
	return buf
}

func TestRenderAgentSuccess_WriterFailureIsLoggedAndSwallowed(t *testing.T) {
	tests := []struct {
		name   string
		result []reflect.Value
	}{
		{name: "list", result: []reflect.Value{reflect.ValueOf([]any{"a", "b"})}},
		{name: "scalar", result: []reflect.Value{reflect.ValueOf("x")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setExecAgentMode(t, true)
			s := NewIdsecServiceExecAction(nil)
			logged := captureActionLog(s)
			brokenStdout(t)
			if err := s.renderAgentSuccess(tt.result, "x", newSuccessExecCmd(t, "")); err != nil {
				t.Fatalf("renderAgentSuccess() = %v, want nil", err)
			}
			if !strings.Contains(logged.String(), "error writing success envelope") {
				t.Fatalf("log = %q, want the write failure", logged.String())
			}
		})
	}
}

func TestRenderAgentSuccess_MarshalFailureMidStreamIsTruncated(t *testing.T) {
	ch := make(chan matrixPage, 1)
	ch <- matrixPage{Items: []any{"a", unmarshalable{}, "c"}}
	close(ch)
	tests := []struct {
		name   string
		result []reflect.Value
	}{
		{name: "slice", result: []reflect.Value{reflect.ValueOf([]any{"a", unmarshalable{}, "c"})}},
		{name: "channel", result: []reflect.Value{reflect.ValueOf(ch)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setExecAgentMode(t, true)
			s := NewIdsecServiceExecAction(nil)
			logged := captureActionLog(s)
			var err error
			out := withCapturedOutput(func() {
				err = s.renderAgentSuccess(tt.result, "x", newSuccessExecCmd(t, ""))
			})
			if err != nil {
				t.Fatal(err)
			}
			var v map[string]any
			if jerr := json.Unmarshal([]byte(out), &v); jerr != nil {
				t.Fatalf("output is not valid JSON: %v: %q", jerr, out)
			}
			if !reflect.DeepEqual(v["data"], []any{"a"}) || v["count"] != 1.0 || v["truncated"] != true {
				t.Fatalf("envelope = %v, want data [a], count 1, truncated true", v)
			}
			if !strings.Contains(logged.String(), "truncated") {
				t.Fatalf("log = %q, want the truncation warning", logged.String())
			}
		})
	}
}

type nanPayload struct {
	Value float64
}

func TestRenderAgentSuccess_MarshalFailureBecomesErrorEnvelope(t *testing.T) {
	tests := []struct {
		name   string
		result []reflect.Value
		query  string
	}{
		{name: "struct_nan", result: []reflect.Value{reflect.ValueOf(nanPayload{Value: math.NaN()})}},
		{name: "map_inf", result: []reflect.Value{reflect.ValueOf(map[string]any{"v": math.Inf(1)})}},
		{name: "struct_unmarshalable_field", result: []reflect.Value{reflect.ValueOf(struct{ F func() }{F: func() {}})}},
		{name: "marshaler_error", result: []reflect.Value{reflect.ValueOf(struct{ V unmarshalable }{})}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agentmode.ResetEnvelopeState()
			setExecAgentMode(t, true)
			s := NewIdsecServiceExecAction(nil)
			captureActionLog(s)
			var err error
			out := withCapturedOutput(func() {
				err = s.renderAgentSuccess(tt.result, "x", newSuccessExecCmd(t, tt.query))
				if err != nil {
					WriteErrorEnvelope(os.Stdout, err)
				}
			})
			if err == nil {
				t.Fatal("renderAgentSuccess() = nil, want an error")
			}
			var failure *agentmode.Failure
			if !errors.As(err, &failure) || failure.Code != agentmode.CodeInternalError {
				t.Fatalf("err = %v, want INTERNAL_ERROR failure", err)
			}
			v := decodeOneObject(t, out)
			errObj, _ := v["error"].(map[string]any)
			if v["status"] != "error" || errObj["code"] != string(agentmode.CodeInternalError) {
				t.Fatalf("envelope = %v, want one INTERNAL_ERROR error envelope", v)
			}
		})
	}
}
