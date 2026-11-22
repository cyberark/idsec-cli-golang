package agentmode_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"iter"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/cyberark/idsec-cli-golang/pkg/agentmode"
)

type badValue struct{}

func (badValue) MarshalJSON() ([]byte, error) { return nil, errors.New("boom") }

type failWriter struct{ after int }

func (f *failWriter) Write(p []byte) (int, error) {
	if f.after <= 0 {
		return 0, errors.New("write failed")
	}
	f.after--
	return len(p), nil
}

// isolateNoAgent isolates agent state and re-resolves so no agent is detected.
func isolateNoAgent(t *testing.T) {
	t.Helper()
	isolateAgentState(t, nil)
	agentmode.Resolve(false, false)
}

func seqOf(items ...any) iter.Seq[any] {
	return func(yield func(any) bool) {
		for _, it := range items {
			if !yield(it) {
				return
			}
		}
	}
}

func jsonKeyOrder(t *testing.T, raw string) []string {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		t.Fatalf("not an object: %v %v", tok, err)
	}
	var keys []string
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, tok.(string))
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			t.Fatal(err)
		}
	}
	return keys
}

func TestNewSuccessEnvelope(t *testing.T) {
	tests := []struct {
		name     string
		agent    map[string]string
		warnings []string
		data     any
		opts     []agentmode.SuccessOption
		want     string
	}{
		{name: "nil data still emitted", data: nil, want: `{"status":"success","data":null}` + "\n"},
		{
			name: "message", data: "x",
			opts: []agentmode.SuccessOption{agentmode.WithSuccessMessage("done")},
			want: `{"status":"success","data":"x","message":"done"}` + "\n",
		},
		{
			name: "count and truncated", data: []int{1},
			opts: []agentmode.SuccessOption{agentmode.WithCount(0), agentmode.WithTruncated(true)},
			want: `{"status":"success","data":[1],"count":0,"truncated":true}` + "\n",
		},
		{
			name: "agent and warnings", agent: map[string]string{"CURSOR_AGENT": "1"},
			warnings: []string{"w1"}, data: map[string]any{"a": 1},
			want: `{"status":"success","data":{"a":1},"warnings":["w1"],"agent":"cursor"}` + "\n",
		},
		{name: "html not escaped", data: "a<b>&c", want: `{"status":"success","data":"a<b>&c"}` + "\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isolateAgentState(t, tt.agent)
			agentmode.Resolve(false, false)
			for _, w := range tt.warnings {
				agentmode.AddWarning(w)
			}
			var buf bytes.Buffer
			if err := agentmode.WriteSuccess(&buf, agentmode.NewSuccessEnvelope(tt.data, tt.opts...)); err != nil {
				t.Fatal(err)
			}
			if buf.String() != tt.want {
				t.Fatalf("got %q want %q", buf.String(), tt.want)
			}
			if len(agentmode.DrainWarnings()) != 0 {
				t.Fatal("warnings not drained")
			}
		})
	}
}

func TestWriteSuccessClaimsOnce(t *testing.T) {
	isolateNoAgent(t)
	var buf bytes.Buffer
	if err := agentmode.Write(&buf, errorEnvelope(agentmode.CodeActionFailed, "x")); err != nil {
		t.Fatal(err)
	}
	if !agentmode.ClaimEnvelope() {
		t.Fatal("first claim should succeed")
	}
	var out bytes.Buffer
	if err := agentmode.WriteSuccess(&out, agentmode.NewSuccessEnvelope(1)); err != nil || out.Len() != 0 {
		t.Fatalf("second claim wrote %q err=%v", out.String(), err)
	}
	n, trunc, err := agentmode.StreamList(&out, seqOf(1))
	if n != 0 || trunc || err != nil || out.Len() != 0 {
		t.Fatalf("StreamList after claim wrote %q", out.String())
	}
}

func TestErrorEnvelopeBytesUnchanged(t *testing.T) {
	isolateNoAgent(t)
	got := writeString(t, errorEnvelope(agentmode.CodeActionFailed, "x"))
	want := `{"status":"error","error":{"code":"ACTION_FAILED","message":"x"}}` + "\n"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestWireKeyOrderMatchesEnvelope(t *testing.T) {
	isolateNoAgent(t)
	count := 1
	env := agentmode.Envelope{
		Status: agentmode.StatusSuccess, Data: 1, Message: "m", Count: &count, Truncated: true,
		Warnings: []string{"w"}, Hints: []string{"h"}, Agent: "a",
		Error: &agentmode.EnvelopeError{Code: agentmode.CodeActionFailed, Message: "e"},
	}
	successKeys := jsonKeyOrder(t, writeString(t, env))
	env.Status = agentmode.StatusError
	errorKeys := jsonKeyOrder(t, writeString(t, env))
	if !reflect.DeepEqual(successKeys, errorKeys) {
		t.Fatalf("key order drift: success=%v error=%v", successKeys, errorKeys)
	}
}

func TestStreamList(t *testing.T) {
	tests := []struct {
		name      string
		items     []any
		wantOut   string
		wantCount int
		wantTrunc bool
	}{
		{name: "empty", items: nil, wantOut: `{"status":"success","data":[],"count":0}` + "\n"},
		{
			name: "three items", items: []any{1, "a<b", map[string]any{"k": "v"}}, wantCount: 3,
			wantOut: `{"status":"success","data":[1,"a<b",{"k":"v"}],"count":3}` + "\n",
		},
		{
			name: "marshal failure on item 2", items: []any{1, 2, badValue{}, 4}, wantCount: 2, wantTrunc: true,
			wantOut: `{"status":"success","data":[1,2],"count":2,"truncated":true}` + "\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isolateNoAgent(t)
			var buf bytes.Buffer
			n, trunc, err := agentmode.StreamList(&buf, seqOf(tt.items...))
			if err != nil {
				t.Fatal(err)
			}
			if n != tt.wantCount || trunc != tt.wantTrunc {
				t.Fatalf("n=%d trunc=%v", n, trunc)
			}
			if buf.String() != tt.wantOut {
				t.Fatalf("got %q want %q", buf.String(), tt.wantOut)
			}
			dec := json.NewDecoder(&buf)
			var v map[string]any
			if err := dec.Decode(&v); err != nil {
				t.Fatal(err)
			}
			if _, err := dec.Token(); !errors.Is(err, io.EOF) {
				t.Fatalf("expected exactly one object, got %v", err)
			}
		})
	}
}

func TestStreamListMatchesWrite(t *testing.T) {
	isolateAgentState(t, map[string]string{"CURSOR_AGENT": "1"})
	agentmode.Resolve(false, false)
	items := []any{map[string]any{"a": 1}, "x<y"}

	agentmode.AddWarning("w")
	var streamed bytes.Buffer
	if _, _, err := agentmode.StreamList(&streamed, seqOf(items...)); err != nil {
		t.Fatal(err)
	}

	agentmode.ResetEnvelopeState()
	agentmode.AddWarning("w")
	var written bytes.Buffer
	if err := agentmode.WriteSuccess(&written, agentmode.NewSuccessEnvelope(items, agentmode.WithCount(2))); err != nil {
		t.Fatal(err)
	}
	if streamed.String() != written.String() {
		t.Fatalf("streamed %q != written %q", streamed.String(), written.String())
	}
}

func TestStreamListWriteFailure(t *testing.T) {
	tests := []struct {
		name  string
		after int
	}{
		{"header fails", 0},
		{"item fails", 1},
		{"tail fails", 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isolateNoAgent(t)
			_, _, err := agentmode.StreamList(&failWriter{after: tt.after}, seqOf(1, 2))
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestWriteSuccessMarshalFailureDoesNotClaim(t *testing.T) {
	tests := []struct {
		name string
		data any
	}{
		{name: "nan", data: math.NaN()},
		{name: "chan", data: make(chan int)},
		{name: "marshaler_error", data: badValue{}},
		{name: "nested_inf", data: map[string]any{"v": math.Inf(1)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isolateNoAgent(t)
			agentmode.ResetEnvelopeState()
			var out bytes.Buffer
			err := agentmode.WriteSuccess(&out, agentmode.NewSuccessEnvelope(tt.data))
			if !errors.Is(err, agentmode.ErrMarshal) {
				t.Fatalf("err = %v, want ErrMarshal", err)
			}
			if out.Len() != 0 {
				t.Fatalf("wrote %q, want nothing", out.String())
			}
			if !agentmode.ClaimEnvelope() {
				t.Fatal("claim was consumed by a marshal failure")
			}
		})
	}
}

func TestWriteSuccessWriteFailureIsNotMarshalError(t *testing.T) {
	isolateNoAgent(t)
	agentmode.ResetEnvelopeState()
	err := agentmode.WriteSuccess(&failWriter{}, agentmode.NewSuccessEnvelope(1))
	if err == nil || errors.Is(err, agentmode.ErrMarshal) {
		t.Fatalf("err = %v, want a non-marshal write error", err)
	}
}
