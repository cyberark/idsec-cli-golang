package actions

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	commonargs "github.com/cyberark/idsec-cli-golang/pkg/common/args"
)

// IdsecQueryAction implements the IdsecAction interface for running jq
// expressions against JSON produced by other idsec commands.
//
// Many idsec commands can persist their JSON result to a file via
// --output-path, or emit it to stdout. IdsecQueryAction reads such JSON — from
// a file (--path) or stdin — parses it, and evaluates a jq expression against
// it in-process using gojq, so the output can be filtered or reshaped without
// needing the jq binary installed. Reading from stdin keeps secret-bearing JSON
// off disk. It embeds IdsecBaseAction for common CLI functionality.
type IdsecQueryAction struct {
	// IdsecBaseAction provides common action functionality
	*IdsecBaseAction
}

// NewIdsecQueryAction creates a new instance of IdsecQueryAction.
//
// NewIdsecQueryAction initializes a new IdsecQueryAction with an embedded
// IdsecBaseAction, providing all the common CLI functionality along with the
// query-specific operation. The returned instance is ready to be used for
// defining the query command.
//
// Returns a new IdsecQueryAction instance ready for CLI integration.
//
// Example:
//
//	queryAction := NewIdsecQueryAction()
//	queryAction.DefineAction(rootCmd)
func NewIdsecQueryAction() *IdsecQueryAction {
	return &IdsecQueryAction{
		IdsecBaseAction: NewIdsecBaseAction(),
	}
}

// DefineAction defines the CLI `query` action and attaches it to the parent command.
//
// DefineAction configures the query command with the flags needed to select the
// input (file or stdin), the jq expression, and any jq variable bindings. Raw
// output reuses the common --raw flag.
//
// Command flags added:
//   - path: Path to a JSON file; use '-' or omit to read JSON from stdin
//   - query: jq expression to evaluate against the JSON content
//   - null-input (-n): Do not read any input; run the query against null
//   - arg: Bind a jq variable to a string value, as name=value (repeatable)
//   - argjson: Bind a jq variable to a JSON value, as name=json (repeatable)
//
// The common --raw flag, when set, prints string results unquoted (like jq -r)
// in addition to disabling colored output.
//
// Parameters:
//   - cmd: The parent cobra command to attach the query command to
//
// Example:
//
//	queryAction := NewIdsecQueryAction()
//	queryAction.DefineAction(rootCmd)
//	// Now 'idsec query' command is available
func (a *IdsecQueryAction) DefineAction(cmd *cobra.Command) {
	queryCmd := &cobra.Command{
		Use:   "query",
		Short: "Run a jq query on JSON produced by an idsec command (from a file or stdin)",
		Long: "Run a jq expression against JSON produced by an idsec command — read from a file " +
			"(--path) or from stdin (--path - or no --path). The expression is evaluated in-process, " +
			"so the jq binary does not need to be installed. Use --arg/--argjson to bind shell values " +
			"to jq variables ($name) instead of interpolating them into the query string.",
		RunE: a.runQueryAction,
	}
	queryCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		a.CommonActionsExecution(cmd, args, true)
	}
	a.CommonActionsConfiguration(queryCmd)

	queryCmd.Flags().String("path", "", "Path to a JSON file produced by an idsec command; use '-' or omit to read JSON from stdin")
	queryCmd.Flags().String("query", "", "jq expression to evaluate against the JSON content")
	queryCmd.Flags().BoolP("null-input", "n", false, "Do not read any input; run the query against null (like jq -n)")
	registerQueryVarFlags(queryCmd.Flags())
	_ = queryCmd.MarkFlagRequired("query")

	cmd.AddCommand(queryCmd)
}

// runQueryAction evaluates the --query expression and prints each result. Input
// comes from --path, or stdin when --path is empty or "-", or is skipped
// entirely (running against null) when --null-input/-n is set — matching jq -n
// for constructing JSON purely from --arg/--argjson bindings. On any failure
// (unreadable input, invalid JSON, invalid variable binding, invalid or failing
// query) it reports the error and exits non-zero so scripts can branch on the
// exit code.
func (a *IdsecQueryAction) runQueryAction(cmd *cobra.Command, _ []string) error {
	path, _ := cmd.Flags().GetString("path")
	query, _ := cmd.Flags().GetString("query")
	rawOutput, _ := cmd.Flags().GetBool("raw")
	nullInput, _ := cmd.Flags().GetBool("null-input")

	vars, err := queryVarsFromFlags(cmd.Flags())
	if err != nil {
		commonargs.PrintFailure(err.Error())
		return &ExitCodeError{Code: 1}
	}

	var parsed interface{}
	if !nullInput {
		data, err := readQueryInput(path)
		if err != nil {
			commonargs.PrintFailure(fmt.Sprintf("Failed to read %s: %v", queryInputName(path), err))
			return &ExitCodeError{Code: 1}
		}
		if err := json.Unmarshal(data, &parsed); err != nil {
			commonargs.PrintFailure(fmt.Sprintf("Failed to parse %s as JSON: %v", queryInputName(path), err))
			return &ExitCodeError{Code: 1}
		}
	}

	if err := applyGojqQuery(parsed, query, rawOutput, vars...); err != nil {
		commonargs.PrintFailure(err.Error())
		return &ExitCodeError{Code: 1}
	}
	return nil
}

// readQueryInput returns the JSON bytes for the query, from stdin when path is
// empty or "-", otherwise from the file at path. The raw read error is returned
// as-is; the caller labels the source via queryInputName.
func readQueryInput(path string) ([]byte, error) {
	if path == "" || path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path) // #nosec G304 -- the path is supplied by the user running the CLI
}

// queryInputName is a human-readable label for the JSON source, for messages.
func queryInputName(path string) string {
	if path == "" || path == "-" {
		return "stdin"
	}
	return fmt.Sprintf("%q", path)
}
