package deprecation

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestMarkCommandKeepsCommandVisibleAndMarksHelp(t *testing.T) {
	cmd := &cobra.Command{
		Use:   "old",
		Short: "Old command",
		Run:   func(_ *cobra.Command, _ []string) {},
	}

	MarkCommand(cmd, Deprecation{
		Message:     "Use the new command.",
		Replacement: "new",
	})

	if cmd.Deprecated != "" {
		t.Fatalf("expected Cobra Deprecated field to remain empty, got %q", cmd.Deprecated)
	}
	if cmd.Hidden {
		t.Fatal("expected deprecated command to remain visible")
	}
	if !strings.Contains(cmd.Short, deprecatedShortSuffix) {
		t.Fatalf("expected command short help to contain %q, got %q", deprecatedShortSuffix, cmd.Short)
	}
}

func TestMarkCommandPrintsWarningToStderr(t *testing.T) {
	root := &cobra.Command{Use: "idsec"}
	cmd := &cobra.Command{
		Use: "old",
		Run: func(_ *cobra.Command, _ []string) {},
	}
	MarkCommand(cmd, Deprecation{
		Message:     "This command is going away.",
		Replacement: "new",
	})
	root.AddCommand(cmd)
	root.SetArgs([]string{"old"})

	var stderr bytes.Buffer
	root.SetErr(&stderr)

	if err := root.Execute(); err != nil {
		t.Fatalf("expected command to execute successfully, got %v", err)
	}

	output := stderr.String()
	if !strings.Contains(output, `WARNING: command "old" is deprecated.`) {
		t.Fatalf("expected warning to include command name, got %q", output)
	}
	if !strings.Contains(output, `Use "new" instead.`) {
		t.Fatalf("expected warning to include replacement, got %q", output)
	}
}

func TestMarkCommandPreservesParentPersistentPreRun(t *testing.T) {
	var parentPreRunCalled bool
	var childRunCalled bool

	root := &cobra.Command{Use: "idsec"}
	parent := &cobra.Command{
		Use: "parent",
		PersistentPreRun: func(_ *cobra.Command, _ []string) {
			parentPreRunCalled = true
		},
	}
	child := &cobra.Command{
		Use: "child",
		Run: func(_ *cobra.Command, _ []string) {
			childRunCalled = true
		},
	}
	MarkCommand(child, Deprecation{Message: "Deprecated."})
	parent.AddCommand(child)
	root.AddCommand(parent)
	root.SetArgs([]string{"parent", "child"})
	root.SetErr(&bytes.Buffer{})

	if err := root.Execute(); err != nil {
		t.Fatalf("expected command to execute successfully, got %v", err)
	}
	if !parentPreRunCalled {
		t.Fatal("expected parent persistent pre-run to be called")
	}
	if !childRunCalled {
		t.Fatal("expected child run to be called")
	}
}

func TestMarkCommandOnParentWarnsWhenChildRuns(t *testing.T) {
	var parentPreRunCalled bool
	var childRunCalled bool

	root := &cobra.Command{Use: "idsec"}
	parent := &cobra.Command{
		Use: "profiles",
		PersistentPreRun: func(_ *cobra.Command, _ []string) {
			parentPreRunCalled = true
		},
	}
	child := &cobra.Command{
		Use: "list",
		Run: func(_ *cobra.Command, _ []string) {
			childRunCalled = true
		},
	}
	MarkCommand(parent, Deprecation{
		Message:     "The profiles command group is deprecated.",
		Replacement: "auth profiles",
	})
	parent.AddCommand(child)
	root.AddCommand(parent)
	root.SetArgs([]string{"profiles", "list"})

	var stderr bytes.Buffer
	root.SetErr(&stderr)

	if err := root.Execute(); err != nil {
		t.Fatalf("expected command to execute successfully, got %v", err)
	}
	if !parentPreRunCalled {
		t.Fatal("expected parent persistent pre-run to be called")
	}
	if !childRunCalled {
		t.Fatal("expected child run to be called")
	}
	output := stderr.String()
	if !strings.Contains(output, `WARNING: command "profiles" is deprecated.`) {
		t.Fatalf("expected parent deprecation warning when child runs, got %q", output)
	}
}

func TestMarkCommandOnParentWarnsWhenHelpIsShown(t *testing.T) {
	root := &cobra.Command{Use: "idsec"}
	parent := &cobra.Command{
		Use:   "profiles",
		Short: "Manage profiles",
	}
	MarkCommand(parent, Deprecation{
		Message:     "The profiles command group is deprecated.",
		Replacement: "auth profiles",
	})
	root.AddCommand(parent)
	root.SetArgs([]string{"profiles"})

	var stderr bytes.Buffer
	root.SetErr(&stderr)
	root.SetOut(&bytes.Buffer{})

	if err := root.Execute(); err != nil {
		t.Fatalf("expected command help to execute successfully, got %v", err)
	}

	output := stderr.String()
	if !strings.Contains(output, `WARNING: command "profiles" is deprecated.`) {
		t.Fatalf("expected parent deprecation warning when help is shown, got %q", output)
	}
}

func TestMarkCommandPreservesExistingPreRunE(t *testing.T) {
	var preRunCalled bool
	var runCalled bool

	root := &cobra.Command{Use: "idsec"}
	cmd := &cobra.Command{
		Use: "old",
		PreRunE: func(_ *cobra.Command, _ []string) error {
			preRunCalled = true
			return nil
		},
		Run: func(_ *cobra.Command, _ []string) {
			runCalled = true
		},
	}
	MarkCommand(cmd, Deprecation{Message: "Deprecated."})
	root.AddCommand(cmd)
	root.SetArgs([]string{"old"})
	root.SetErr(&bytes.Buffer{})

	if err := root.Execute(); err != nil {
		t.Fatalf("expected command to execute successfully, got %v", err)
	}
	if !preRunCalled {
		t.Fatal("expected existing PreRunE to be called")
	}
	if !runCalled {
		t.Fatal("expected command Run to be called")
	}
}

func TestMarkCommandReturnsExistingPreRunEError(t *testing.T) {
	expectedErr := errors.New("pre-run failed")
	var runCalled bool

	root := &cobra.Command{Use: "idsec"}
	cmd := &cobra.Command{
		Use: "old",
		PreRunE: func(_ *cobra.Command, _ []string) error {
			return expectedErr
		},
		Run: func(_ *cobra.Command, _ []string) {
			runCalled = true
		},
	}
	MarkCommand(cmd, Deprecation{Message: "Deprecated."})
	root.AddCommand(cmd)
	root.SetArgs([]string{"old"})
	root.SetErr(&bytes.Buffer{})

	if err := root.Execute(); !errors.Is(err, expectedErr) {
		t.Fatalf("expected pre-run error %v, got %v", expectedErr, err)
	}
	if runCalled {
		t.Fatal("expected command Run not to be called after PreRunE error")
	}
}

func TestMarkCommandIsIdempotent(t *testing.T) {
	root := &cobra.Command{Use: "idsec"}
	cmd := &cobra.Command{
		Use: "old",
		Run: func(_ *cobra.Command, _ []string) {},
	}
	dep := Deprecation{Message: "Deprecated."}
	MarkCommand(cmd, dep)
	MarkCommand(cmd, dep)
	root.AddCommand(cmd)
	root.SetArgs([]string{"old"})

	var stderr bytes.Buffer
	root.SetErr(&stderr)

	if err := root.Execute(); err != nil {
		t.Fatalf("expected command to execute successfully, got %v", err)
	}

	if got := strings.Count(cmd.Short, deprecatedShortSuffix); got != 1 {
		t.Fatalf("expected help suffix once, got %d in %q", got, cmd.Short)
	}
	if got := strings.Count(stderr.String(), "WARNING:"); got != 1 {
		t.Fatalf("expected warning once, got %d in %q", got, stderr.String())
	}
}

func TestMarkFlagKeepsFlagVisibleAndMarksHelp(t *testing.T) {
	cmd := &cobra.Command{
		Use: "test",
		Run: func(_ *cobra.Command, _ []string) {},
	}
	cmd.Flags().String("old-flag", "", "Old flag")

	err := MarkFlag(cmd.Flags(), "old-flag", Deprecation{
		Message:     "will be removed in v2",
		Replacement: "--new-flag",
	})
	if err != nil {
		t.Fatalf("expected MarkFlag to succeed, got %v", err)
	}

	flag := cmd.Flags().Lookup("old-flag")
	if flag == nil {
		t.Fatal("expected old-flag to exist")
	}
	if flag.Hidden {
		t.Fatal("expected deprecated flag to remain visible")
	}
	if !strings.Contains(flag.Deprecated, `Use "--new-flag" instead.`) {
		t.Fatalf("expected flag deprecation message to include replacement, got %q", flag.Deprecated)
	}

	usage := cmd.Flags().FlagUsages()
	if !strings.Contains(usage, "--old-flag") {
		t.Fatalf("expected help to include deprecated flag, got %q", usage)
	}
	if !strings.Contains(usage, "(DEPRECATED:") {
		t.Fatalf("expected help to mark flag deprecated, got %q", usage)
	}
}

func TestMarkFlagPrintsWarningWhenUsed(t *testing.T) {
	cmd := &cobra.Command{
		Use: "test",
		Run: func(_ *cobra.Command, _ []string) {},
	}
	cmd.Flags().String("old-flag", "", "Old flag")
	// SetOutput before MarkFlag so MarkFlag wraps our test buffer; otherwise
	// SetOutput later would replace the wrapper.
	var stderr bytes.Buffer
	cmd.SetErr(&stderr)
	cmd.Flags().SetOutput(&stderr)

	if err := MarkFlag(cmd.Flags(), "old-flag", Deprecation{
		Message:     "will be removed in v2",
		Replacement: "--new-flag",
	}); err != nil {
		t.Fatalf("expected MarkFlag to succeed, got %v", err)
	}
	cmd.SetArgs([]string{"--old-flag", "value"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected command to execute successfully, got %v", err)
	}

	output := stderr.String()
	if !strings.Contains(output, `WARNING: flag --old-flag is deprecated.`) {
		t.Fatalf("expected colored WARNING-style flag deprecation, got %q", output)
	}
	if strings.Contains(output, "Flag --old-flag has been deprecated") {
		t.Fatalf("did not expect raw pflag deprecation line, got %q", output)
	}
	if !strings.Contains(output, `Use "--new-flag" instead.`) {
		t.Fatalf("expected flag warning to include replacement, got %q", output)
	}
}

func TestMarkFlagReturnsErrorForMissingFlag(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}

	err := MarkFlag(cmd.Flags(), "missing", Deprecation{Message: "Deprecated."})
	if err == nil {
		t.Fatal("expected error for missing flag")
	}
}

func TestMarkFlagAppliesDefaultBodyForEmptyDeprecation(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("old-flag", "", "Old flag")

	if err := MarkFlag(cmd.Flags(), "old-flag", Deprecation{}); err != nil {
		t.Fatalf("expected MarkFlag to accept empty deprecation, got %v", err)
	}

	flag := cmd.Flags().Lookup("old-flag")
	if flag == nil {
		t.Fatal("expected old-flag to exist")
	}
	if flag.Hidden {
		t.Fatal("expected deprecated flag to remain visible")
	}
	if flag.Deprecated != flagDefaultMessage {
		t.Fatalf("expected default body %q, got %q", flagDefaultMessage, flag.Deprecated)
	}
}
