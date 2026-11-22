package actions

import (
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/cyberark/idsec-cli-golang/pkg/agentmode"
	"github.com/cyberark/idsec-sdk-golang/pkg/config"
)

type agentPage struct {
	Items []any
}

// newSuccessExecCmd returns an exec command with the --query and --raw flags.
func newSuccessExecCmd(t *testing.T, query string) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "exec"}
	cmd.PersistentFlags().String("query", "", "")
	cmd.PersistentFlags().Bool("raw", false, "")
	if query != "" {
		if err := cmd.PersistentFlags().Set("query", query); err != nil {
			t.Fatal(err)
		}
	}
	return cmd
}

// runRender runs renderAgentSuccess with stdout captured. It must not be
// called from a t.Parallel() test.
func runRender(t *testing.T, enabled bool, result []reflect.Value, query string) (string, error) {
	t.Helper()
	setExecAgentMode(t, enabled)
	var err error
	out := withCapturedOutput(func() {
		err = NewIdsecServiceExecAction(nil).renderAgentSuccess(result, "list-things", newSuccessExecCmd(t, query))
	})
	return out, err
}

func decodeOneObject(t *testing.T, out string) map[string]any {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(out))
	var v map[string]any
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("decode %q: %v", out, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		t.Fatalf("stdout holds more than one JSON object: %q", out)
	}
	return v
}

func TestRenderAgentSuccess_Kinds(t *testing.T) {
	ch := make(chan agentPage, 2)
	ch <- agentPage{Items: []any{"a", "b"}}
	ch <- agentPage{Items: []any{"c"}}
	close(ch)
	var nilPtr *string
	tests := []struct {
		name      string
		result    []reflect.Value
		wantData  any
		wantCount *float64
		wantMsg   string
	}{
		{name: "struct", result: []reflect.Value{reflect.ValueOf(struct{ A int }{1})}, wantData: map[string]any{"A": 1.0}},
		{name: "map", result: []reflect.Value{reflect.ValueOf(map[string]any{"k": "v"})}, wantData: map[string]any{"k": "v"}},
		{name: "int", result: []reflect.Value{reflect.ValueOf(42)}, wantData: 42.0},
		{name: "bool", result: []reflect.Value{reflect.ValueOf(true)}, wantData: true},
		{name: "string", result: []reflect.Value{reflect.ValueOf("hi")}, wantData: "hi"},
		{name: "slice", result: []reflect.Value{reflect.ValueOf([]any{"x", "y"})}, wantData: []any{"x", "y"}, wantCount: ptrF(2)},
		{name: "empty slice", result: []reflect.Value{reflect.ValueOf([]any{})}, wantData: []any{}, wantCount: ptrF(0)},
		{name: "channel of pages", result: []reflect.Value{reflect.ValueOf(ch)}, wantData: []any{"a", "b", "c"}, wantCount: ptrF(3)},
		{name: "nil pointer", result: []reflect.Value{reflect.ValueOf(nilPtr)}, wantData: nil, wantMsg: "List Things finished successfully"},
		{name: "no output", result: nil, wantData: nil, wantMsg: "List Things finished successfully"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := runRender(t, true, tt.result, "")
			if err != nil {
				t.Fatalf("renderAgentSuccess() = %v", err)
			}
			v := decodeOneObject(t, out)
			if v["status"] != "success" {
				t.Fatalf("status = %v", v["status"])
			}
			if !reflect.DeepEqual(v["data"], tt.wantData) {
				t.Fatalf("data = %#v, want %#v", v["data"], tt.wantData)
			}
			if tt.wantCount == nil {
				if _, ok := v["count"]; ok {
					t.Fatalf("count should be absent: %v", v)
				}
			} else if v["count"] != *tt.wantCount {
				t.Fatalf("count = %v, want %v", v["count"], *tt.wantCount)
			}
			if tt.wantMsg != "" && v["message"] != tt.wantMsg {
				t.Fatalf("message = %v, want %q", v["message"], tt.wantMsg)
			}
		})
	}
}

func ptrF(f float64) *float64 { return &f }

func TestRenderAgentSuccess_Query(t *testing.T) {
	tests := []struct {
		name     string
		query    string
		result   []reflect.Value
		wantData any
		wantCnt  *float64
	}{
		{name: "one result", query: ".name", result: []reflect.Value{reflect.ValueOf(map[string]any{"name": "n"})}, wantData: "n"},
		{name: "several results", query: ".[]", result: []reflect.Value{reflect.ValueOf([]any{1, 2})}, wantData: []any{1.0, 2.0}, wantCnt: ptrF(2)},
		{name: "zero results", query: "empty", result: []reflect.Value{reflect.ValueOf(map[string]any{})}, wantData: []any{}, wantCnt: ptrF(0)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := runRender(t, true, tt.result, tt.query)
			if err != nil {
				t.Fatal(err)
			}
			v := decodeOneObject(t, out)
			if !reflect.DeepEqual(v["data"], tt.wantData) {
				t.Fatalf("data = %#v", v["data"])
			}
			if tt.wantCnt != nil && v["count"] != *tt.wantCnt {
				t.Fatalf("count = %v", v["count"])
			}
		})
	}
}

func TestRenderAgentSuccess_InvalidQueryWritesNothing(t *testing.T) {
	out, err := runRender(t, true, []reflect.Value{reflect.ValueOf(map[string]any{})}, ".[")
	if err == nil {
		t.Fatal("expected invalid query error")
	}
	if out != "" {
		t.Fatalf("stdout = %q, want empty", out)
	}
}

func TestRenderAgentSuccess_PartialAuthWarningInEnvelope(t *testing.T) {
	setExecAgentMode(t, true)
	agentmode.AddWarning("partial")
	var err error
	out := withCapturedOutput(func() {
		err = NewIdsecServiceExecAction(nil).renderAgentSuccess([]reflect.Value{reflect.ValueOf(7)}, "x", newSuccessExecCmd(t, ""))
	})
	if err != nil {
		t.Fatal(err)
	}
	v := decodeOneObject(t, out)
	if !reflect.DeepEqual(v["warnings"], []any{"partial"}) {
		t.Fatalf("warnings = %v", v["warnings"])
	}
}

func TestSerializeAndPrintOutput_HumanModeUnchanged(t *testing.T) {
	setExecAgentMode(t, false)
	out := withCapturedOutput(func() {
		NewIdsecServiceExecAction(nil).serializeAndPrintOutput([]reflect.Value{reflect.ValueOf(map[string]any{"a": 1})}, "x", 0)
	})
	if !strings.Contains(out, "\"a\": 1") {
		t.Fatalf("human output changed: %q", out)
	}
}

func TestCommonActionsExecution_ReservesStdoutOnlyInAgentMode(t *testing.T) {
	tests := []struct {
		name  string
		agent bool
		want  bool
	}{
		{name: "agent reserves", agent: true, want: true},
		{name: "human does not", agent: false, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearAgentEnv(t)
			t.Cleanup(func() {
				config.ReleaseStdoutForData()
				resetAgentModeBaseline()
			})
			config.ReleaseStdoutForData()
			cmd := &cobra.Command{Use: "c"}
			action := NewIdsecBaseAction()
			action.CommonActionsConfiguration(cmd)
			if tt.agent {
				_ = cmd.PersistentFlags().Set("agent", "true")
			}
			action.CommonActionsExecution(cmd, []string{}, false)
			if got := config.IsStdoutReservedForData(); got != tt.want {
				t.Fatalf("IsStdoutReservedForData() = %v, want %v", got, tt.want)
			}
		})
	}
}
