package actions

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestNewIdsecQueryAction(t *testing.T) {
	t.Parallel()

	action := NewIdsecQueryAction()
	if action == nil {
		t.Fatal("Expected non-nil action")
	}
	if action.IdsecBaseAction == nil {
		t.Error("Expected IdsecBaseAction to be initialized")
	}
}

func TestIdsecQueryAction_DefineAction(t *testing.T) {
	t.Parallel()

	action := NewIdsecQueryAction()
	rootCmd := &cobra.Command{Use: "idsec"}
	action.DefineAction(rootCmd)

	queryCmd, _, err := rootCmd.Find([]string{"query"})
	if err != nil {
		t.Fatalf("Expected to find query command, got error: %v", err)
	}
	if queryCmd == nil || queryCmd.Use != "query" {
		t.Fatalf("Expected a 'query' command to be added, got %+v", queryCmd)
	}
	if queryCmd.RunE == nil {
		t.Error("Expected the query command to have a RunE function")
	}
	if queryCmd.PersistentPreRun == nil {
		t.Error("Expected the query command to have a PersistentPreRun function")
	}
	for _, flagName := range []string{"path", "query", "arg", "argjson", "null-input"} {
		if queryCmd.Flags().Lookup(flagName) == nil {
			t.Errorf("Expected flag '%s' to be defined on the query command", flagName)
		}
	}
	if queryCmd.Flags().ShorthandLookup("n") == nil {
		t.Error("Expected '-n' shorthand for --null-input on the query command")
	}
	// raw is the common persistent flag from CommonActionsConfiguration.
	if queryCmd.PersistentFlags().Lookup("raw") == nil {
		t.Error("Expected common '--raw' flag to be available on the query command")
	}
	// Only query is required; path is optional (defaults to stdin).
	if flag := queryCmd.Flags().Lookup("query"); flag == nil {
		t.Error("Expected 'query' flag to be defined")
	} else if _, ok := flag.Annotations[cobra.BashCompOneRequiredFlag]; !ok {
		t.Error("Expected flag 'query' to be marked required")
	}
	if flag := queryCmd.Flags().Lookup("path"); flag != nil {
		if _, ok := flag.Annotations[cobra.BashCompOneRequiredFlag]; ok {
			t.Error("Expected flag 'path' to be optional (defaults to stdin)")
		}
	}
}

func TestIdsecQueryAction_IdsecActionInterface(t *testing.T) {
	t.Parallel()

	action := NewIdsecQueryAction()
	var _ IdsecAction = action

	rootCmd := &cobra.Command{Use: "idsec"}
	action.DefineAction(rootCmd)
	if _, _, err := rootCmd.Find([]string{"query"}); err != nil {
		t.Errorf("Expected query command to be registered, got error: %v", err)
	}
}

// newQueryCmd builds a cobra command carrying the flags runQueryAction reads.
func newQueryCmd(path, query string, raw bool) *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String("path", "", "")
	cmd.Flags().String("query", "", "")
	cmd.Flags().Bool("raw", false, "")
	cmd.Flags().Bool("null-input", false, "")
	cmd.Flags().StringArray("arg", nil, "")
	cmd.Flags().StringArray("argjson", nil, "")
	_ = cmd.Flags().Set("path", path)
	_ = cmd.Flags().Set("query", query)
	if raw {
		_ = cmd.Flags().Set("raw", "true")
	}
	return cmd
}

// withStdin swaps os.Stdin for a pipe carrying input for the duration of fn,
// so tests can exercise the query command's stdin path.
func withStdin(t *testing.T, input string, fn func()) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	orig := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = orig }()

	go func() {
		_, _ = w.WriteString(input)
		_ = w.Close()
	}()
	fn()
	_ = r.Close()
}

// writeTempJSON writes content to a temp file and returns its path.
func writeTempJSON(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "out.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	return path
}

func TestIdsecQueryAction_runQueryAction_Success(t *testing.T) {
	action := NewIdsecQueryAction()
	path := writeTempJSON(t, `{"name":"pool-9","type":"ACCESS","items":[{"id":1},{"id":2}]}`)

	cases := []struct {
		name  string
		query string
		raw   bool
		want  string
	}{
		{name: "quoted_string", query: ".name", want: `"pool-9"`},
		{name: "raw_string", query: ".name", raw: true, want: "pool-9"},
		{name: "array", query: "[.items[].id]", want: "[\n  1,\n  2\n]"},
		{name: "missing_key_fallback", query: `.nope // ""`, raw: true, want: ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var err error
			out := withCapturedOutput(func() {
				err = action.runQueryAction(newQueryCmd(path, c.query, c.raw), []string{})
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := strings.TrimRight(out, "\n"); got != c.want {
				t.Errorf("runQueryAction output = %q, want %q", got, c.want)
			}
		})
	}
}

func TestIdsecQueryAction_runQueryAction_MissingFile(t *testing.T) {
	action := NewIdsecQueryAction()
	cmd := newQueryCmd(filepath.Join(t.TempDir(), "does-not-exist.json"), ".", false)

	var err error
	out := withCapturedOutput(func() { err = action.runQueryAction(cmd, []string{}) })

	var exitErr *ExitCodeError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected *ExitCodeError, got %v", err)
	}
	if exitErr.Code != 1 {
		t.Errorf("expected exit code 1, got %d", exitErr.Code)
	}
	if !strings.Contains(out, "Failed to read") {
		t.Errorf("expected a read-failure message, got %q", out)
	}
}

func TestIdsecQueryAction_runQueryAction_InvalidJSON(t *testing.T) {
	action := NewIdsecQueryAction()
	path := writeTempJSON(t, "not json at all")
	cmd := newQueryCmd(path, ".", false)

	var err error
	out := withCapturedOutput(func() { err = action.runQueryAction(cmd, []string{}) })

	var exitErr *ExitCodeError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected *ExitCodeError, got %v", err)
	}
	if !strings.Contains(out, "Failed to parse") {
		t.Errorf("expected a parse-failure message, got %q", out)
	}
}

func TestIdsecQueryAction_runQueryAction_InvalidQuery(t *testing.T) {
	action := NewIdsecQueryAction()
	path := writeTempJSON(t, `{"a":1}`)
	cmd := newQueryCmd(path, ".[", false)

	var err error
	_ = withCapturedOutput(func() { err = action.runQueryAction(cmd, []string{}) })

	var exitErr *ExitCodeError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected *ExitCodeError for an invalid query, got %v", err)
	}
}

func TestIdsecQueryAction_runQueryAction_Stdin(t *testing.T) {
	action := NewIdsecQueryAction()

	cases := []struct {
		name string
		path string
	}{
		{name: "explicit_dash", path: "-"},
		{name: "omitted", path: ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cmd := newQueryCmd(c.path, ".a", true)
			var err error
			var out string
			withStdin(t, `{"a":"from-stdin"}`, func() {
				out = withCapturedOutput(func() { err = action.runQueryAction(cmd, []string{}) })
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := strings.TrimRight(out, "\n"); got != "from-stdin" {
				t.Errorf("stdin query output = %q, want %q", got, "from-stdin")
			}
		})
	}
}

// TestIdsecQueryAction_runQueryAction_NullInput verifies -n/--null-input runs
// the query against null with no input read, so JSON can be constructed purely
// from --arg/--argjson bindings (like jq -n).
func TestIdsecQueryAction_runQueryAction_NullInput(t *testing.T) {
	action := NewIdsecQueryAction()

	cmd := newQueryCmd("", `{safe: $s, size: $sz}`, false)
	_ = cmd.Flags().Set("null-input", "true")
	_ = cmd.Flags().Set("arg", "s=Prod DB")
	_ = cmd.Flags().Set("argjson", "sz=10")

	var err error
	out := withCapturedOutput(func() { err = action.runQueryAction(cmd, []string{}) })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "{\n  \"safe\": \"Prod DB\",\n  \"size\": 10\n}"
	if got := strings.TrimRight(out, "\n"); got != want {
		t.Errorf("null-input query output = %q, want %q", got, want)
	}
}

func TestIdsecQueryAction_runQueryAction_Arg(t *testing.T) {
	action := NewIdsecQueryAction()
	path := writeTempJSON(t, `[{"name":"prod","id":1},{"name":"dev","id":2}]`)

	cmd := newQueryCmd(path, `.[] | select(.name == $n) | .id`, false)
	_ = cmd.Flags().Set("arg", "n=prod")

	var err error
	out := withCapturedOutput(func() { err = action.runQueryAction(cmd, []string{}) })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := strings.TrimRight(out, "\n"); got != "1" {
		t.Errorf("arg-bound query output = %q, want %q", got, "1")
	}
}

// TestIdsecQueryAction_runQueryAction_ArgInjectionSafe verifies that a value
// bound with --arg is treated as inert data even when it contains jq syntax, so
// a user-supplied name cannot rewrite the query (no jq-program injection).
func TestIdsecQueryAction_runQueryAction_ArgInjectionSafe(t *testing.T) {
	action := NewIdsecQueryAction()
	path := writeTempJSON(t, `[{"name":"prod","id":1},{"name":"secret","id":2}]`)

	cmd := newQueryCmd(path, `.[] | select(.name == $n) | .id`, true)
	// A malicious "name" that would rewrite the query if interpolated.
	_ = cmd.Flags().Set("arg", `n=x") | .id, (`)

	var err error
	out := withCapturedOutput(func() { err = action.runQueryAction(cmd, []string{}) })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := strings.TrimRight(out, "\n"); got != "" {
		t.Errorf("injection string should match nothing, got output %q", got)
	}
}

func TestIdsecQueryAction_runQueryAction_ArgJSON(t *testing.T) {
	action := NewIdsecQueryAction()
	path := writeTempJSON(t, `{"items":[1,2,3,4]}`)

	cmd := newQueryCmd(path, `.items | map(select(. > $min))`, false)
	_ = cmd.Flags().Set("argjson", "min=2")

	var err error
	out := withCapturedOutput(func() { err = action.runQueryAction(cmd, []string{}) })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := strings.TrimRight(out, "\n"); got != "[\n  3,\n  4\n]" {
		t.Errorf("argjson query output = %q", got)
	}
}

func TestIdsecQueryAction_runQueryAction_BadArg(t *testing.T) {
	action := NewIdsecQueryAction()
	path := writeTempJSON(t, `{}`)

	cases := []struct {
		name string
		flag string
		val  string
	}{
		{name: "arg_no_equals", flag: "arg", val: "noequals"},
		{name: "arg_bad_name", flag: "arg", val: "1bad=x"},
		{name: "argjson_invalid_json", flag: "argjson", val: "n=not-json"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cmd := newQueryCmd(path, ".", false)
			_ = cmd.Flags().Set(c.flag, c.val)

			var err error
			_ = withCapturedOutput(func() { err = action.runQueryAction(cmd, []string{}) })

			var exitErr *ExitCodeError
			if !errors.As(err, &exitErr) {
				t.Fatalf("expected *ExitCodeError, got %v", err)
			}
		})
	}
}
