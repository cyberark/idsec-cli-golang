package actions

import (
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

// TestApplyGojqQuery exercises the shared query helper used by every command's
// --query flag: quoting rules, raw output, jq's null/empty-input model, multiple
// results, and error propagation.
func TestApplyGojqQuery(t *testing.T) {
	cases := []struct {
		name    string
		input   any
		query   string
		raw     bool
		want    string // full stdout with trailing newline(s) trimmed
		wantErr bool
	}{
		{name: "quoted_string", input: map[string]any{"name": "pool-9"}, query: ".name", want: `"pool-9"`},
		{name: "raw_string", input: map[string]any{"name": "pool-9"}, query: ".name", raw: true, want: "pool-9"},
		{name: "nil_input_is_null", input: nil, query: ".", want: "null"},
		{name: "missing_key_is_null", input: map[string]any{"a": 1}, query: ".pool_id", want: "null"},
		{name: "missing_key_fallback_raw_empty", input: map[string]any{"a": 1}, query: `.pool_id // ""`, raw: true, want: ""},
		{name: "array_output", input: map[string]any{"items": []any{map[string]any{"id": 1}, map[string]any{"id": 2}}}, query: "[.items[].id]", want: "[\n  1,\n  2\n]"},
		{name: "multiple_values_raw", input: []any{"a", "b"}, query: ".[]", raw: true, want: "a\nb"},
		{name: "raw_nonstring_stays_json", input: map[string]any{"n": 5}, query: ".n", raw: true, want: "5"},
		{name: "invalid_query", input: map[string]any{}, query: ".[", wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var err error
			out := withCapturedOutput(func() { err = applyGojqQuery(c.input, c.query, c.raw) })
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got nil (output=%q)", out)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := strings.TrimRight(out, "\n"); got != c.want {
				t.Errorf("applyGojqQuery output = %q, want %q", got, c.want)
			}
		})
	}
}

// TestApplyGojqQueryWithVars exercises variable binding: --arg values arrive as
// strings, --argjson values as parsed JSON, and a bound value is inert data
// even when it contains jq syntax (no program injection).
func TestApplyGojqQueryWithVars(t *testing.T) {
	cases := []struct {
		name  string
		input any
		query string
		raw   bool
		vars  []queryVar
		want  string
	}{
		{
			name:  "arg_string_bound",
			input: []any{map[string]any{"name": "prod", "id": float64(1)}, map[string]any{"name": "dev", "id": float64(2)}},
			query: `.[] | select(.name == $n) | .id`,
			vars:  []queryVar{{name: "n", value: "prod"}},
			want:  "1",
		},
		{
			name:  "injection_is_inert",
			input: []any{map[string]any{"name": "prod", "id": float64(1)}},
			query: `.[] | select(.name == $n) | .id`,
			vars:  []queryVar{{name: "n", value: `x") | .id, (`}},
			want:  "",
		},
		{
			name:  "argjson_number_bound",
			input: map[string]any{"items": []any{float64(1), float64(2), float64(3)}},
			query: `.items | map(select(. > $min))`,
			vars:  []queryVar{{name: "min", value: float64(1)}},
			want:  "[\n  2,\n  3\n]",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var err error
			out := withCapturedOutput(func() { err = applyGojqQuery(c.input, c.query, c.raw, c.vars...) })
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := strings.TrimRight(out, "\n"); got != c.want {
				t.Errorf("applyGojqQuery output = %q, want %q", got, c.want)
			}
		})
	}
}

// TestParseQueryVars covers --arg/--argjson parsing: string vs JSON values,
// order preservation, and rejection of malformed entries.
func TestParseQueryVars(t *testing.T) {
	t.Run("valid_mix_preserves_order", func(t *testing.T) {
		vars, err := parseQueryVars([]string{"a=hello", "b=world"}, []string{"c=42", `d={"k":true}`})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(vars) != 4 {
			t.Fatalf("expected 4 vars, got %d", len(vars))
		}
		if vars[0].name != "a" || vars[0].value != "hello" {
			t.Errorf("arg 0 = %+v", vars[0])
		}
		if vars[2].name != "c" || vars[2].value != float64(42) {
			t.Errorf("argjson 0 = %+v", vars[2])
		}
	})

	t.Run("value_with_equals_kept_intact", func(t *testing.T) {
		vars, err := parseQueryVars([]string{"a=k=v=1"}, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if vars[0].value != "k=v=1" {
			t.Errorf("expected value to keep later '=', got %q", vars[0].value)
		}
	})

	for _, c := range []struct {
		name    string
		arg     []string
		argjson []string
	}{
		{name: "arg_missing_equals", arg: []string{"noequals"}},
		{name: "arg_bad_name", arg: []string{"1bad=x"}},
		{name: "arg_empty_name", arg: []string{"=x"}},
		{name: "argjson_invalid_json", argjson: []string{"n=not-json"}},
		{name: "argjson_bad_name", argjson: []string{"bad-name=1"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := parseQueryVars(c.arg, c.argjson); err == nil {
				t.Errorf("expected an error for %s", c.name)
			}
		})
	}
}

// TestApplyGojqQueryExposesEnv verifies the process environment is reachable via
// jq's env function and $ENV variable — the channel build_request.sh (env[$v])
// and resolve_creds.sh (env.V) rely on. gojq does not populate these by default.
func TestApplyGojqQueryExposesEnv(t *testing.T) {
	t.Setenv("IDSEC_QUERY_TEST_SECRET", "s3cr3t")

	t.Run("env_function", func(t *testing.T) {
		var err error
		out := withCapturedOutput(func() {
			err = applyGojqQuery(nil, `env.IDSEC_QUERY_TEST_SECRET`, true)
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := strings.TrimRight(out, "\n"); got != "s3cr3t" {
			t.Errorf("env.NAME = %q, want %q", got, "s3cr3t")
		}
	})

	t.Run("ENV_variable", func(t *testing.T) {
		var err error
		out := withCapturedOutput(func() {
			err = applyGojqQuery(nil, `$ENV.IDSEC_QUERY_TEST_SECRET`, true)
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := strings.TrimRight(out, "\n"); got != "s3cr3t" {
			t.Errorf("$ENV.NAME = %q, want %q", got, "s3cr3t")
		}
	})

	// Dynamic lookup env[$v], as build_request.sh resolves password_from_env.
	t.Run("dynamic_env_index_with_arg", func(t *testing.T) {
		var err error
		out := withCapturedOutput(func() {
			err = applyGojqQuery(
				map[string]any{"password_from_env": "IDSEC_QUERY_TEST_SECRET"},
				`.password_from_env as $v | env[$v]`,
				true,
			)
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := strings.TrimRight(out, "\n"); got != "s3cr3t" {
			t.Errorf("env[$v] = %q, want %q", got, "s3cr3t")
		}
	})
}

// TestQueryVarFlagsRoundTrip verifies the shared registration/read helpers used
// by every command's --query so --arg/--argjson bind consistently.
func TestQueryVarFlagsRoundTrip(t *testing.T) {
	fs := pflag.NewFlagSet("t", pflag.ContinueOnError)
	registerQueryVarFlags(fs)
	if err := fs.Parse([]string{"--arg", "a=hello", "--argjson", "b=[1,2]"}); err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	vars, err := queryVarsFromFlags(fs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vars) != 2 {
		t.Fatalf("expected 2 vars, got %d", len(vars))
	}
	if vars[0].name != "a" || vars[0].value != "hello" {
		t.Errorf("arg var = %+v", vars[0])
	}
	if vars[1].name != "b" {
		t.Errorf("argjson name = %q", vars[1].name)
	}
}

// TestApplyQueryAndPrintNoValueRunsAgainstNull verifies the exec sentinel fix:
// when a command produces no printable value the query runs against JSON null
// (jq's empty-input model) instead of printing a "finished successfully"
// sentence, so a shell capture stays clean.
func TestApplyQueryAndPrintNoValueRunsAgainstNull(t *testing.T) {
	action := NewIdsecServiceExecAction(nil)

	t.Run("fallback_yields_empty_not_sentinel", func(t *testing.T) {
		var err error
		out := withCapturedOutput(func() { err = action.applyQueryAndPrint(nil, `.pool_id // ""`, true) })
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if strings.Contains(out, "finished successfully") {
			t.Errorf("expected no sentinel on the query path, got %q", out)
		}
		if strings.TrimRight(out, "\n") != "" {
			t.Errorf("expected empty raw output, got %q", out)
		}
	})

	t.Run("identity_yields_null", func(t *testing.T) {
		var err error
		out := withCapturedOutput(func() { err = action.applyQueryAndPrint(nil, ".", false) })
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if strings.TrimRight(out, "\n") != "null" {
			t.Errorf("expected null, got %q", out)
		}
	})
}
