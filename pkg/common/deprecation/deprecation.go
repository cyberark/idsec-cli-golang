// Package deprecation provides helpers for marking CLI commands and flags as
// deprecated without hiding them from Cobra/pflag help output.
package deprecation

import (
	"fmt"
	"io"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/cyberark/idsec-sdk-golang/pkg/config"
)

const (
	deprecatedShortSuffix = " [DEPRECATED]"
	markCommandAnnotation = "idsec.cyberark.com/deprecation-marked"
	flagDefaultMessage    = "will be removed in a future release"
)

// Deprecation describes why a command or flag is deprecated and what users
// should use instead. Both fields are optional; when both are empty, helpers
// still mark the target and emit a generic deprecation warning.
type Deprecation struct {
	Message     string
	Replacement string
}

// MarkCommand marks a Cobra command as deprecated while keeping it visible in
// help. A Deprecation with empty Message and Replacement is still applied; the
// runtime warning falls back to "command X is deprecated." in that case.
func MarkCommand(cmd *cobra.Command, dep Deprecation) {
	if cmd == nil {
		return
	}

	markCommandHelp(cmd)
	if cmd.Annotations != nil && cmd.Annotations[markCommandAnnotation] == "true" {
		return
	}
	if cmd.Annotations == nil {
		cmd.Annotations = map[string]string{}
	}
	cmd.Annotations[markCommandAnnotation] = "true"

	wrapHelp(cmd, dep)
	if cmd.Runnable() {
		wrapPreRun(cmd, dep)
		return
	}
	wrapPersistentPreRun(cmd, dep)
}

// MarkFlag marks a flag as deprecated while keeping it visible in help. A
// Deprecation with empty Message and Replacement is still applied; the runtime
// warning falls back to a generic body in that case (pflag requires a
// non-empty deprecation body).
func MarkFlag(flags *pflag.FlagSet, name string, dep Deprecation) error {
	if flags == nil {
		return fmt.Errorf("flag set is required")
	}
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("flag name is required")
	}

	if err := flags.MarkDeprecated(name, FlagWarning(dep)); err != nil {
		return err
	}
	if flag := flags.Lookup(name); flag != nil {
		flag.Hidden = false
	}
	installFlagWarningWriter(flags)
	return nil
}

// flagWarningWriter wraps pflag's output writer and rewrites the deprecation line pflag emits.
type flagWarningWriter struct {
	underlying io.Writer
}

// Write rewrites pflag's "Flag --<name> has been deprecated, <body>\n" line
// into a colored "WARNING: flag --<name> is deprecated. <body>" line.
func (w *flagWarningWriter) Write(p []byte) (int, error) {
	line := string(p)
	if !strings.HasPrefix(line, "Flag --") {
		return w.underlying.Write(p)
	}
	rest := line[len("Flag --"):]
	idx := strings.Index(rest, " has been deprecated, ")
	if idx < 0 {
		return w.underlying.Write(p)
	}
	name := rest[:idx]
	body := strings.TrimRight(rest[idx+len(" has been deprecated, "):], "\n")
	warning := fmt.Sprintf("WARNING: flag --%s is deprecated. %s\n", name, body)
	if config.IsColoring() {
		if _, err := color.New(color.FgYellow).Fprint(w.underlying, warning); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	if _, err := io.WriteString(w.underlying, warning); err != nil {
		return 0, err
	}
	return len(p), nil
}

// installFlagWarningWriter wraps the flag set's output writer with
// flagWarningWriter, idempotently.
func installFlagWarningWriter(flags *pflag.FlagSet) {
	out := flags.Output()
	if _, ok := out.(*flagWarningWriter); ok {
		return
	}
	flags.SetOutput(&flagWarningWriter{underlying: out})
}

// WarnCommand writes the deprecation warning for a command to stderr.
func WarnCommand(cmd *cobra.Command, dep Deprecation) {
	if cmd == nil {
		return
	}
	warning := CommandWarning(cmd, dep)
	if config.IsColoring() {
		_, _ = color.New(color.FgYellow).Fprintln(cmd.ErrOrStderr(), warning)
		return
	}
	_, _ = fmt.Fprintln(cmd.ErrOrStderr(), warning)
}

// CommandWarning formats the user-facing command deprecation warning.
func CommandWarning(cmd *cobra.Command, dep Deprecation) string {
	name := ""
	if cmd != nil {
		name = cmd.Name()
	}
	if name == "" {
		name = "command"
	}

	warning := fmt.Sprintf("WARNING: command %q is deprecated.", name)
	message, replacement := normalizeDeprecationParts(dep)
	if message != "" {
		warning += " " + message
		if replacement != "" {
			warning += ","
		} else {
			warning += "."
		}
	}
	if replacement != "" {
		warning += fmt.Sprintf(" Use %q instead.", replacement)
	}
	return warning
}

// FlagWarning formats the body pflag appends after "Flag --X has been
// deprecated, ". It uses the same Message/Replacement formatting as
// CommandWarning, with a generic fallback when both fields are empty so the
// pflag MarkDeprecated call never receives an empty body.
func FlagWarning(dep Deprecation) string {
	message, replacement := normalizeDeprecationParts(dep)
	if message == "" && replacement == "" {
		return flagDefaultMessage
	}

	var warning string
	if message != "" {
		warning = message
		if replacement != "" {
			warning += ","
		} else {
			warning += "."
		}
	}
	if replacement != "" {
		if warning != "" {
			warning += " "
		}
		warning += fmt.Sprintf("Use %q instead.", replacement)
	}
	return warning
}

// normalizeDeprecationParts trims whitespace from both fields and strips
// trailing punctuation from Message so it joins cleanly with Replacement.
func normalizeDeprecationParts(dep Deprecation) (string, string) {
	message := strings.TrimRight(strings.TrimSpace(dep.Message), ".,;:")
	replacement := strings.TrimSpace(dep.Replacement)
	return message, replacement
}

// markCommandHelp appends the deprecation marker to the command's short help text.
func markCommandHelp(cmd *cobra.Command) {
	if strings.Contains(cmd.Short, deprecatedShortSuffix) {
		return
	}
	short := strings.TrimSpace(cmd.Short)
	if short == "" {
		cmd.Short = strings.TrimSpace(deprecatedShortSuffix)
		return
	}
	cmd.Short = short + deprecatedShortSuffix
}

// wrapPreRun emits a deprecation warning before running an existing command pre-run hook.
func wrapPreRun(cmd *cobra.Command, dep Deprecation) {
	previousPreRun := cmd.PreRun
	previousPreRunE := cmd.PreRunE
	cmd.PreRun = nil
	cmd.PreRunE = func(c *cobra.Command, args []string) error {
		WarnCommand(cmd, dep)
		if previousPreRunE != nil {
			return previousPreRunE(c, args)
		}
		if previousPreRun != nil {
			previousPreRun(c, args)
		}
		return nil
	}
}

// wrapPersistentPreRun emits a deprecation warning before running an existing inherited pre-run hook.
func wrapPersistentPreRun(cmd *cobra.Command, dep Deprecation) {
	previousPersistentPreRun := cmd.PersistentPreRun
	previousPersistentPreRunE := cmd.PersistentPreRunE
	cmd.PersistentPreRun = nil
	cmd.PersistentPreRunE = func(c *cobra.Command, args []string) error {
		WarnCommand(cmd, dep)
		if previousPersistentPreRunE != nil {
			return previousPersistentPreRunE(c, args)
		}
		if previousPersistentPreRun != nil {
			previousPersistentPreRun(c, args)
		}
		return nil
	}
}

// wrapHelp emits a deprecation warning whenever Cobra renders command help.
func wrapHelp(cmd *cobra.Command, dep Deprecation) {
	previousHelpFunc := cmd.HelpFunc()
	cmd.SetHelpFunc(func(c *cobra.Command, args []string) {
		WarnCommand(cmd, dep)
		previousHelpFunc(c, args)
	})
}
