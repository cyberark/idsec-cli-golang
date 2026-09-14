package actions

import (
	"reflect"
	"slices"
	"sort"
	"testing"

	"github.com/spf13/cobra"
)

func TestDeriveOperation(t *testing.T) {
	tests := []struct {
		name         string
		serviceParts []string
		actionName   string
		want         string
	}{
		{"nested with dashes", []string{"sia", "access"}, "install-connector", "sia.access.install_connector"},
		{"simple", []string{"pcloud", "accounts"}, "create", "pcloud.accounts.create"},
		{"no service parts", nil, "version", "version"},
		{"dashes in every segment", []string{"sia", "workspaces-target-sets"}, "add-target-set", "sia.workspaces_target_sets.add_target_set"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := deriveOperation(tt.serviceParts, tt.actionName); got != tt.want {
				t.Errorf("deriveOperation(%v, %q) = %q, want %q", tt.serviceParts, tt.actionName, got, tt.want)
			}
		})
	}
}

// dryInner is an embedded struct (squash) carrying a secret to exercise the
// recursive secret-flag collection.
type dryInner struct {
	EmbeddedSecret string `flag:"embedded-secret" secret:"true"`
	EmbeddedPlain  string `flag:"embedded-plain"`
}

// drySchema mimics a real request schema with a squashed embed, top-level
// secret, plain fields, and a field with a default.
type drySchema struct {
	dryInner    `mapstructure:",squash"`
	SafeName    string `flag:"safe-name"`
	Secret      string `flag:"secret" secret:"true"`
	ConnectorOS string `flag:"connector-os"`
	PlatformID  string `flag:"platform-id"`
}

func newDryCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "create"}
	cmd.Flags().String("safe-name", "", "")
	cmd.Flags().String("secret", "", "")
	cmd.Flags().String("connector-os", "linux", "") // applied default
	cmd.Flags().String("platform-id", "", "")       // no default, left unset
	cmd.Flags().String("embedded-secret", "", "")
	cmd.Flags().String("embedded-plain", "", "") // no default, left unset
	return cmd
}

func TestResolveDryRunArgs(t *testing.T) {
	cmd := newDryCommand()
	_ = cmd.Flags().Set("safe-name", "MySafe")
	_ = cmd.Flags().Set("secret", "hunter2")
	_ = cmd.Flags().Set("embedded-secret", "topsecret")

	resolved, secretFields := resolveDryRunArgs(cmd, &drySchema{}, nil)

	want := map[string]string{
		"safe-name":       "MySafe",
		"secret":          secretMask,
		"connector-os":    "linux", // default applied
		"embedded-secret": secretMask,
	}
	if !reflect.DeepEqual(resolved, want) {
		t.Errorf("resolved args = %#v, want %#v", resolved, want)
	}

	sort.Strings(secretFields)
	wantSecrets := []string{"embedded-secret", "secret"}
	if !reflect.DeepEqual(secretFields, wantSecrets) {
		t.Errorf("secret fields = %v, want %v", secretFields, wantSecrets)
	}
}

func TestResolveDryRunArgsExcludesUnsetWithoutDefault(t *testing.T) {
	cmd := newDryCommand()
	_ = cmd.Flags().Set("safe-name", "MySafe")

	resolved, secretFields := resolveDryRunArgs(cmd, &drySchema{}, nil)

	if _, ok := resolved["platform-id"]; ok {
		t.Errorf("platform-id should be omitted (unset, no default): %#v", resolved)
	}
	if _, ok := resolved["embedded-plain"]; ok {
		t.Errorf("embedded-plain should be omitted (unset, no default): %#v", resolved)
	}
	if _, ok := resolved["secret"]; ok {
		t.Errorf("secret should be omitted when not provided: %#v", resolved)
	}
	if len(secretFields) != 0 {
		t.Errorf("secret fields should be empty when no secret provided, got %v", secretFields)
	}
	if resolved["connector-os"] != "linux" {
		t.Errorf("connector-os default should be included, got %#v", resolved)
	}
}

func TestResolveDryRunArgsNilSchema(t *testing.T) {
	cmd := newDryCommand()
	_ = cmd.Flags().Set("secret", "hunter2")

	resolved, secretFields := resolveDryRunArgs(cmd, nil, nil)

	// With no schema, nothing is treated as secret.
	if resolved["secret"] != "hunter2" {
		t.Errorf("without a schema, secret should not be masked, got %#v", resolved)
	}
	if len(secretFields) != 0 {
		t.Errorf("expected no secret fields for nil schema, got %v", secretFields)
	}
}

func TestResolveDryRunArgsMergesRequestFile(t *testing.T) {
	cmd := newDryCommand()
	// safe-name is provided on the command line and must win over the request file.
	_ = cmd.Flags().Set("safe-name", "FlagSafe")

	requestFileArgs := map[string]interface{}{
		"safe_name":   "FileSafe", // overridden by the explicit flag above
		"secret":      "hunter2",  // secret carried only by the request file
		"platform_id": "Platform-Windows",
	}

	resolved, secretFields := resolveDryRunArgs(cmd, &drySchema{}, requestFileArgs)

	if resolved["safe-name"] != "FlagSafe" {
		t.Errorf("explicit flag should win over request file, got %#v", resolved["safe-name"])
	}
	if resolved["secret"] != secretMask {
		t.Errorf("request-file secret must be masked, got %#v", resolved["secret"])
	}
	if resolved["platform-id"] != "Platform-Windows" {
		t.Errorf("request-file plain value should be surfaced, got %#v", resolved["platform-id"])
	}
	if !slices.Contains(secretFields, "secret") {
		t.Errorf("request-file secret must appear in secret_fields, got %v", secretFields)
	}
}

func TestCollectSecretFlags(t *testing.T) {
	set := map[string]bool{}
	collectSecretFlags(reflect.TypeOf(&drySchema{}), set)

	want := map[string]bool{"secret": true, "embedded-secret": true}
	if !reflect.DeepEqual(set, want) {
		t.Errorf("collectSecretFlags = %v, want %v", set, want)
	}
}

func TestFlagNameForField(t *testing.T) {
	type sample struct {
		WithFlag         string `flag:"with-flag" mapstructure:"with_flag"`
		WithMapstructure string `mapstructure:"with_mapstructure,omitempty"`
		Bare             string
	}
	rt := reflect.TypeOf(sample{})
	cases := map[string]string{
		"WithFlag":         "with-flag",
		"WithMapstructure": "with_mapstructure",
		"Bare":             "bare",
	}
	for field, want := range cases {
		f, _ := rt.FieldByName(field)
		if got := flagNameForField(f); got != want {
			t.Errorf("flagNameForField(%s) = %q, want %q", field, got, want)
		}
	}
}

func TestIsZeroDefaultValue(t *testing.T) {
	zero := []string{"", "0", "false", "[]", "map[]", "0s"}
	for _, v := range zero {
		if !isZeroDefaultValue(v) {
			t.Errorf("isZeroDefaultValue(%q) = false, want true", v)
		}
	}
	nonZero := []string{"linux", "10", "true", "ON-PREMISE", "https"}
	for _, v := range nonZero {
		if isZeroDefaultValue(v) {
			t.Errorf("isZeroDefaultValue(%q) = true, want false", v)
		}
	}
}
