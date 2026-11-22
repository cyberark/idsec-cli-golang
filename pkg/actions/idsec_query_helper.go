package actions

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/itchyny/gojq"
	"github.com/spf13/pflag"
	"github.com/cyberark/idsec-cli-golang/pkg/agentmode"
	"github.com/cyberark/idsec-cli-golang/pkg/common/args"
)

// queryVarNamePattern matches a valid jq variable name (the part after '$').
var queryVarNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// registerQueryVarFlags adds the --arg/--argjson flags to a flag set so every
// command that exposes --query can bind jq variables the same way. Callers pass
// the flag set the rest of their query flags live on (Flags or PersistentFlags).
func registerQueryVarFlags(fs *pflag.FlagSet) {
	fs.StringArray("arg", nil, "Bind a jq variable to a string value, as name=value (usable as $name); repeatable")
	fs.StringArray("argjson", nil, "Bind a jq variable to a JSON value, as name=json (usable as $name); repeatable")
}

// queryVarsFromFlags reads the --arg/--argjson flags from a flag set and parses
// them into ordered queryVars, mirroring registerQueryVarFlags.
func queryVarsFromFlags(fs *pflag.FlagSet) ([]queryVar, error) {
	argPairs, _ := fs.GetStringArray("arg")
	argjsonPairs, _ := fs.GetStringArray("argjson")
	return parseQueryVars(argPairs, argjsonPairs)
}

// parseQueryVars converts repeated --arg and --argjson "name=value" entries into
// ordered queryVars. --arg values are bound as strings; --argjson values are
// parsed as JSON. Both forms bind $name for use in the query expression, so a
// user-supplied value never has to be interpolated into the query string.
func parseQueryVars(argPairs, argjsonPairs []string) ([]queryVar, error) {
	var vars []queryVar
	for _, p := range argPairs {
		name, value, ok := strings.Cut(p, "=")
		if !ok || !queryVarNamePattern.MatchString(name) {
			return nil, invalidQueryVar("arg", "invalid --arg, expected name=value with a valid variable name",
				fmt.Errorf("invalid --arg %q, expected name=value with a valid variable name", p))
		}
		vars = append(vars, queryVar{name: name, value: value})
	}
	for _, p := range argjsonPairs {
		name, raw, ok := strings.Cut(p, "=")
		if !ok || !queryVarNamePattern.MatchString(name) {
			return nil, invalidQueryVar("argjson", "invalid --argjson, expected name=json with a valid variable name",
				fmt.Errorf("invalid --argjson %q, expected name=json with a valid variable name", p))
		}
		var value any
		if err := json.Unmarshal([]byte(raw), &value); err != nil {
			return nil, invalidQueryVar("argjson", "invalid JSON value for --argjson",
				fmt.Errorf("invalid JSON for --argjson %s: %w", name, err))
		}
		vars = append(vars, queryVar{name: name, value: value})
	}
	return vars, nil
}

// invalidQueryVar marks a bad --arg/--argjson binding. err quotes the binding,
// which may hold a secret, so the envelope gets the fixed safeMsg instead.
func invalidQueryVar(flag, safeMsg string, err error) error {
	return agentmode.NewFailure(agentmode.CodeInvalidInput, err,
		agentmode.WithRedactedMessage(safeMsg),
		agentmode.WithDetail("kind", agentmode.KindInvalidValue),
		agentmode.WithDetail("flag", flag))
}

// invalidQueryMessages are the envelope messages per jq stage. gojq errors
// quote the expression and, at run time, values from the input data.
var invalidQueryMessages = map[string]string{
	"parse":   "invalid jq query: parse error; see stderr for details",
	"compile": "invalid jq query: compile error; see stderr for details",
	"run":     "jq query failed at run time; see stderr for details",
}

// invalidQuery marks a jq failure at stage parse, compile or run.
func invalidQuery(stage string, err error) error {
	return agentmode.NewFailure(agentmode.CodeInvalidInput, err,
		agentmode.WithRedactedMessage(invalidQueryMessages[stage]),
		agentmode.WithDetail("kind", agentmode.KindInvalidQuery),
		agentmode.WithDetail("flag", "query"),
		agentmode.WithDetail("stage", stage),
		agentmode.WithHint(hintInvalidQuery))
}

// queryVar binds a jq variable (referenced as $name in the expression) to a
// value. Values are passed to gojq out-of-band rather than interpolated into
// the query string, which prevents jq-program injection when the value is
// user-supplied (for example a safe or role name).
type queryVar struct {
	// name is the variable name without the leading '$'.
	name string
	// value is the bound value: a string for --arg, or parsed JSON for --argjson.
	value any
}

// compileGojqQuery round-trips input through JSON, parses and compiles query,
// and returns the compiled code with the plain input tree and the variable
// values to pass to code.Run. It is the shared setup of applyGojqQuery (human
// path, prints as it goes) and runGojqQuery (agent path, collects results).
func compileGojqQuery(input any, query string, vars ...queryVar) (*gojq.Code, any, []any, error) {
	serialized, err := json.Marshal(input)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to serialize output for query: %w", err)
	}
	var parsed interface{}
	if err := json.Unmarshal(serialized, &parsed); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse output for query: %w", err)
	}
	q, err := gojq.Parse(query)
	if err != nil {
		return nil, nil, nil, invalidQuery("parse", fmt.Errorf("invalid jq query %q: %w", query, err))
	}

	names := make([]string, len(vars))
	values := make([]any, len(vars))
	for i, v := range vars {
		names[i] = "$" + v.name
		values[i] = v.value
	}

	code, err := gojq.Compile(q,
		gojq.WithVariables(names),
		gojq.WithEnvironLoader(os.Environ),
	)
	if err != nil {
		return nil, nil, nil, invalidQuery("compile", fmt.Errorf("failed to compile jq query: %w", err))
	}
	return code, parsed, values, nil
}

// runGojqQuery evaluates query against input and returns every result without
// printing anything, so a run-time failure leaves stdout untouched. Errors are
// the same invalidQuery failures applyGojqQuery returns.
func runGojqQuery(input any, query string, vars ...queryVar) ([]any, error) {
	code, parsed, values, err := compileGojqQuery(input, query, vars...)
	if err != nil {
		return nil, err
	}
	results := []any{}
	it := code.Run(parsed, values...)
	for {
		v, ok := it.Next()
		if !ok {
			break
		}
		if queryErr, ok := v.(error); ok {
			return nil, invalidQuery("run", fmt.Errorf("query failed: %w", queryErr))
		}
		results = append(results, v)
	}
	return results, nil
}

// applyGojqQuery applies a jq expression to input and prints each result as
// JSON via args.PrintSuccess. It is shared by exec, login, status, profiles
// list, configure, and the standalone query command so every --query behaves
// consistently.
//
// The input is round-tripped through JSON so gojq always receives a plain
// interface{} tree rather than SDK-specific struct types. A nil input becomes
// JSON null, matching jq's empty-input model — so a missing-value query such as
// `.pool_id` yields null rather than any human-readable sentinel.
//
// Each output value is printed on its own line, consistent with jq. When raw is
// true, a top-level string result is printed unquoted and unescaped (jq's -r);
// non-string results are always serialized as indented JSON.
//
// vars binds jq variables ($name) to values so callers can inject shell values
// safely instead of interpolating them into the query string.
//
// The process environment is exposed to the expression via jq's env function
// and $ENV variable (gojq does not populate these by default). This matches jq
// and lets expressions read secrets from the environment — a channel that,
// unlike argv, is not world-readable via ps. It carries no injection risk here
// because query expressions are program constants and user-supplied values are
// bound through vars rather than interpolated.
func applyGojqQuery(input any, query string, raw bool, vars ...queryVar) error {
	code, parsed, values, err := compileGojqQuery(input, query, vars...)
	if err != nil {
		return err
	}
	iter := code.Run(parsed, values...)
	for {
		v, ok := iter.Next()
		if !ok {
			break
		}
		if queryErr, ok := v.(error); ok {
			return invalidQuery("run", fmt.Errorf("query failed: %w", queryErr))
		}
		if raw {
			if s, ok := v.(string); ok {
				args.PrintSuccess(s)
				continue
			}
		}
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to serialize query result: %w", err)
		}
		args.PrintSuccess(string(b))
	}
	return nil
}
