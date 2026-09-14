package actions

import (
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"os"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/mitchellh/mapstructure"
	"github.com/octago/sflags"
	"github.com/octago/sflags/gen/gpflag"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/cyberark/idsec-cli-golang/pkg/cli"
	"github.com/cyberark/idsec-cli-golang/pkg/common/args"
	"github.com/cyberark/idsec-cli-golang/pkg/common/deprecation"
	"github.com/cyberark/idsec-cli-golang/pkg/registry"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/profiles"
	sdkservices "github.com/cyberark/idsec-sdk-golang/pkg/services"
	"github.com/cyberark/idsec-sdk-golang/pkg/validation"
)

// secretMask is the placeholder printed in place of a secret argument value.
const secretMask = "***"

// IdsecServiceExecAction is a struct that implements the IdsecExecAction interface for executing service actions.
//
// IdsecServiceExecAction provides functionality for dynamically executing service actions
// based on service action definitions. It handles the parsing of command-line flags,
// schema validation, method invocation, and output serialization for service operations.
//
// The action supports:
//   - Dynamic command generation from service action definitions
//   - Complex type parsing for JSON and array inputs
//   - Flag validation with choices and required field checking
//   - Method reflection and invocation on service APIs
//   - Multiple output format serialization (JSON, primitive types, channels)
//   - Request file input support for complex payloads
type IdsecServiceExecAction struct {
	// IdsecExecAction interface for execution capabilities
	IdsecExecAction
	// IdsecBaseExecAction provides common execution functionality
	*IdsecBaseExecAction
}

// dryRunPlan is the JSON document printed by `idsec exec ... --dry-run`. It
// describes the action that would run without authenticating or executing it.
type dryRunPlan struct {
	// Operation is the dotted service path and action, e.g. "sia.access.install_connector".
	Operation string `json:"operation"`
	// Profile is the effective profile name that would be used (resolved, not loaded).
	Profile string `json:"profile"`
	// ResolvedArgs are the effective arguments (provided flags plus applied
	// defaults), keyed by kebab-case flag name. Secret values are masked.
	ResolvedArgs map[string]string `json:"resolved_args"`
	// SecretFields lists the resolved_args keys whose values were masked.
	SecretFields []string `json:"secret_fields"`
}

// NewIdsecServiceExecAction creates a new instance of IdsecServiceExecAction.
//
// NewIdsecServiceExecAction initializes a new IdsecServiceExecAction with the provided
// profile loader and embedded IdsecBaseExecAction for common execution functionality.
// The action is configured with reflection-based method invocation capabilities
// for dynamic service action execution.
//
// Parameters:
//   - profilesLoader: A pointer to a ProfileLoader for handling profile operations
//
// Returns a new IdsecServiceExecAction instance ready for defining and executing
// service commands.
//
// Example:
//
//	loader := profiles.NewProfileLoader()
//	serviceExecAction := NewIdsecServiceExecAction(loader)
//	serviceExecAction.DefineExecAction(rootCmd)
func NewIdsecServiceExecAction(profilesLoader *profiles.ProfileLoader) *IdsecServiceExecAction {
	action := &IdsecServiceExecAction{}
	var actionInterface IdsecExecAction = action
	baseAction := NewIdsecBaseExecAction(&actionInterface, "IdsecServiceExecAction", profilesLoader)
	action.IdsecBaseExecAction = baseAction
	return action
}

// isComplexType determines if a struct field represents a complex type requiring JSON parsing.
//
// isComplexType checks if the field is a map[string]struct or slice/array of structs,
// which require special handling during flag parsing as they need to be parsed from
// JSON strings rather than simple flag values.
//
// Parameters:
//   - field: The reflect.StructField to check for complexity
//
// Returns true if the field is a complex type (map[string]struct or []struct),
// false otherwise.
func (s *IdsecServiceExecAction) isComplexType(field reflect.StructField) bool {
	if field.Type.Kind() == reflect.Map && field.Type.Key().Kind() == reflect.String && field.Type.Elem().Kind() == reflect.Struct {
		return true
	}
	if (field.Type.Kind() == reflect.Slice || field.Type.Kind() == reflect.Array) && field.Type.Elem().Kind() == reflect.Struct {
		return true
	}
	return false
}

// fillRemainingSchema adds flags for complex types and squashed struct fields.
//
// fillRemainingSchema processes a schema struct and adds command-line flags for
// complex types (maps and slices of structs) that require JSON parsing, and
// recursively processes squashed struct fields to flatten their fields into
// the parent command's flag set.
//
// Parameters:
//   - schema: The schema interface to process for flag generation
//   - flags: The pflag.FlagSet to add the generated flags to
//
// The function handles:
//   - Complex types by adding string flags with JSON parsing hints
//   - Squashed struct fields by recursively processing embedded structs
//   - Flag naming from struct tags (flag, mapstructure, or field name)
//   - Description enhancement for complex types
func (s *IdsecServiceExecAction) fillRemainingSchema(schema interface{}, flags *pflag.FlagSet) {
	schemaType := reflect.TypeOf(schema).Elem()
	for i := 0; i < schemaType.NumField(); i++ {
		field := schemaType.Field(i)

		// Skip unexported fields
		if field.PkgPath != "" && !field.Anonymous {
			continue
		}

		if s.isComplexType(field) {
			flagName := field.Tag.Get("flag")
			if flagName == "" {
				flagName = field.Tag.Get("mapstructure")
			}
			if flagName == "" {
				flagName = field.Name
			}
			desc := field.Tag.Get("desc")
			if desc != "" {
				desc += " (This is a complex type and will be parsed as JSON or array of JSONs)"
			}
			flags.String(flagName, field.Tag.Get("default"), desc)
		}
		if field.Tag.Get("mapstructure") == ",squash" {
			// If the field is a struct with the `squash` tag, we need to add its fields as flags
			subSchema := reflect.New(field.Type).Interface()
			s.fillRemainingSchema(subSchema, flags)
		}
	}
}

// applyDefaults applies default values to struct fields based on `default` tags.
func (s *IdsecServiceExecAction) applyDefaults(target any) error {
	v := reflect.ValueOf(target)
	if v.Kind() != reflect.Pointer || v.IsNil() {
		return fmt.Errorf("target must be a non-nil pointer to struct")
	}

	return s.applyDefaultsRec(v.Elem())
}

// applyDefaultsRec is a recursive helper function to apply defaults to struct fields.
func (s *IdsecServiceExecAction) applyDefaultsRec(v reflect.Value) error {
	if v.Kind() != reflect.Struct {
		return nil
	}

	t := v.Type()

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		fv := v.Field(i)

		if !fv.CanSet() {
			continue
		}

		squash := strings.Contains(field.Tag.Get("mapstructure"), ",squash")

		if fv.Kind() == reflect.Struct {
			if err := s.applyDefaultsRec(fv); err != nil {
				return err
			}
		}

		if fv.Kind() == reflect.Pointer {
			if fv.IsNil() {
				if s.hasInnerDefaults(field.Type) {
					newV := reflect.New(field.Type.Elem())
					fv.Set(newV)

					if field.Type.Elem().Kind() == reflect.Struct {
						if err := s.applyDefaultsRec(newV.Elem()); err != nil {
							return err
						}
					}
				}
			} else {
				if fv.Elem().Kind() == reflect.Struct {
					if err := s.applyDefaultsRec(fv.Elem()); err != nil {
						return err
					}
				}
			}
		}

		if def := field.Tag.Get("default"); def != "" {
			if s.isZeroValue(fv) { // only set if user didn't override
				if err := s.setFromString(fv, def); err != nil {
					return fmt.Errorf("cannot set default for field %s: %w", field.Name, err)
				}
			}
		}

		// Handle embedded struct with squash
		if field.Anonymous || squash {
			if fv.Kind() == reflect.Struct {
				if err := s.applyDefaultsRec(fv); err != nil {
					return err
				}
			}
			if fv.Kind() == reflect.Pointer && !fv.IsNil() {
				if fv.Elem().Kind() == reflect.Struct {
					if err := s.applyDefaultsRec(fv.Elem()); err != nil {
						return err
					}
				}
			}
		}
	}

	return nil
}

// hasInnerDefaults checks if a struct type has any fields with `default` tags.
func (s *IdsecServiceExecAction) hasInnerDefaults(t reflect.Type) bool {
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return false
	}

	for i := 0; i < t.NumField(); i++ {
		if t.Field(i).Tag.Get("default") != "" {
			return true
		}
		// recurse into inner structs
		ft := t.Field(i).Type
		if ft.Kind() == reflect.Struct || (ft.Kind() == reflect.Pointer && ft.Elem().Kind() == reflect.Struct) {
			if s.hasInnerDefaults(ft) {
				return true
			}
		}
	}
	return false
}

// isZeroValue checks if a reflect.Value is the zero value for its type.
func (s *IdsecServiceExecAction) isZeroValue(v reflect.Value) bool {
	return reflect.DeepEqual(v.Interface(), reflect.Zero(v.Type()).Interface())
}

// setFromString sets a reflect.Value from its string representation.
func (s *IdsecServiceExecAction) setFromString(v reflect.Value, str string) error {
	switch v.Kind() {

	case reflect.String:
		v.SetString(str)

	case reflect.Bool:
		b, err := strconv.ParseBool(str)
		if err != nil {
			return err
		}
		v.SetBool(b)

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n, err := strconv.ParseInt(str, 10, 64)
		if err != nil {
			return err
		}
		v.SetInt(n)

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n, err := strconv.ParseUint(str, 10, 64)
		if err != nil {
			return err
		}
		v.SetUint(n)

	case reflect.Float32, reflect.Float64:
		n, err := strconv.ParseFloat(str, 64)
		if err != nil {
			return err
		}
		v.SetFloat(n)

	case reflect.Pointer:
		// allocate pointer then set its underlying type
		elem := reflect.New(v.Type().Elem())
		if err := s.setFromString(elem.Elem(), str); err != nil {
			return err
		}
		v.Set(elem)

	case reflect.Array, reflect.Slice:
		// assume comma-separated values
		parts := strings.Split(str, ",")
		slice := reflect.MakeSlice(v.Type(), len(parts), len(parts))
		for i, part := range parts {
			err := s.setFromString(slice.Index(i), part)
			if err != nil {
				return err
			}
		}
		v.Set(slice)
	default:
		return fmt.Errorf("unsupported type %s", v.Kind())
	}

	return nil
}

// applyActionDefDeprecation marks the cobra command as deprecated when the SDK
// service action definition carries deprecation metadata.
func applyActionDefDeprecation(cmd *cobra.Command, actionDef *actions.IdsecServiceCLIActionDefinition) {
	if cmd == nil || actionDef == nil || actionDef.Deprecation == nil {
		return
	}
	deprecation.MarkCommand(cmd, deprecation.Deprecation{
		Message:     actionDef.Deprecation.Message,
		Replacement: actionDef.Deprecation.Replacement,
	})
}

// applySchemaEntryDeprecation marks a leaf cobra command deprecated when the
// matching ActionToSchemaMap entry was wrapped with modelsactions.Deprecated.
func applySchemaEntryDeprecation(cmd *cobra.Command, dep *actions.Deprecation) {
	if cmd == nil || dep == nil {
		return
	}
	deprecation.MarkCommand(cmd, deprecation.Deprecation{
		Message:     dep.Message,
		Replacement: dep.Replacement,
	})
}

// defineServiceExecAction creates a cobra command for a service action definition.
//
// defineServiceExecAction processes a service action definition and creates the
// corresponding cobra command with subcommands for each schema. It handles flag
// generation, validation, and default value assignment based on struct tags.
//
// Parameters:
//   - actionDef: The service action definition to process
//   - cmd: The parent cobra command to add the action command to
//   - parentActionsDef: Slice of parent action definitions for nested actions
//
// Returns the created action command and any error encountered during processing.
//
// The function handles:
//   - Command creation with proper naming from action definitions
//   - Schema-based subcommand generation
//   - Flag parsing using sflags library
//   - Required field marking based on validation tags
//   - Default value assignment from struct tags
func (s *IdsecServiceExecAction) defineServiceExecAction(
	actionDef *actions.IdsecServiceCLIActionDefinition,
	cmd *cobra.Command,
	parentActionsDef []*actions.IdsecServiceCLIActionDefinition,
) (*cobra.Command, error) {
	shortDescription := ""
	descriptionWithAliases := actionDef.ActionDescription
	if len(actionDef.ActionAliases) > 0 {
		descriptionWithAliases += fmt.Sprintf(" (aliases: %s)", strings.Join(actionDef.ActionAliases, ", "))
		shortDescription = fmt.Sprintf("(aliases: %s)", strings.Join(actionDef.ActionAliases, ", "))
	}
	actionCmd := &cobra.Command{
		Use:     actionDef.ActionName,
		Aliases: actionDef.ActionAliases,
		Short:   shortDescription,
		Long:    descriptionWithAliases,
	}

	applyActionDefDeprecation(actionCmd, actionDef)

	actionDest := actionDef.ActionName
	if len(parentActionsDef) > 0 {
		for _, p := range parentActionsDef {
			actionDest += "_" + p.ActionName
		}
	}

	if len(actionDef.Schemas) > 0 {
		for actionName, rawSchema := range actionDef.Schemas {
			schema, schemaDep := actions.UnwrapSchema(rawSchema)
			subCmd := &cobra.Command{
				Use: actionName,
				Run: func(cmd *cobra.Command, args []string) {
					if help, _ := cmd.Flags().GetBool("help"); help {
						_ = cmd.Help()
						return
					}
					if dryRun, _ := cmd.Flags().GetBool("dry-run"); dryRun {
						_ = s.dryRunExecAction(cmd)
						return
					}
					s.runExecAction(cmd, args)
				},
			}
			applySchemaEntryDeprecation(subCmd, schemaDep)
			if schema != nil {
				flags, err := sflags.ParseStruct(schema)
				if err != nil {
					s.logger.Error("Error parsing flags to IdsecAuthMethod settings %v", err)
					return nil, err
				}
				gpflag.GenerateTo(flags, subCmd.Flags())
				s.fillRemainingSchema(schema, subCmd.Flags())
				reflectedSchema := reflect.TypeOf(schema).Elem()
				// We find the field by the flag name
				// There might be a misalignment between the flag name and the field name case wise
				// So we first try to find the field by the flag name
				// And then try to find it with ignore case
				for _, flag := range flags {
					caser := cases.Title(language.English)
					flagNameTitled := strings.ReplaceAll(caser.String(flag.Name), "-", "")
					field, ok := reflectedSchema.FieldByName(flagNameTitled)
					if !ok {
						fieldFound := false
						for i := 0; i < reflectedSchema.NumField(); i++ {
							possibleField := reflectedSchema.Field(i)
							if strings.EqualFold(possibleField.Name, flagNameTitled) {
								field = possibleField
								fieldFound = true
								break
							}
						}
						if !fieldFound {
							continue
						}
					}
					// Skip cobra's required-flag enforcement under --dry-run so a
					// plan can be produced from a request file alone, without
					// re-specifying every required flag on the command line.
					if strings.Contains(field.Tag.Get("validate"), "required") && !dryRunRequested() {
						err = subCmd.MarkFlagRequired(flag.Name)
						if err != nil {
							return nil, err
						}
					}
					if field.Tag.Get("default") != "" {
						subCmd.Flag(flag.Name).DefValue = field.Tag.Get("default")
					}
					if fieldDep := actions.FieldDeprecation(field); fieldDep != nil {
						if err := deprecation.MarkFlag(subCmd.Flags(), flag.Name, deprecation.Deprecation{
							Message:     fieldDep.Message,
							Replacement: fieldDep.Replacement,
						}); err != nil {
							return nil, err
						}
					}
				}
			}
			actionCmd.AddCommand(subCmd)
		}
	}

	cmd.AddCommand(actionCmd)
	return actionCmd, nil
}

// defineServiceExecActions recursively defines service execution actions and their subactions.
//
// defineServiceExecActions processes a service action definition and its nested
// subactions, creating a hierarchy of cobra commands. It recursively processes
// subactions to build a complete command tree structure.
//
// Parameters:
//   - actionDef: The service action definition to process
//   - cmd: The parent cobra command to add actions to
//   - parentActionsDef: Slice of parent action definitions for context
//
// Returns an error if any action definition processing fails.
//
// The function handles:
//   - Primary action definition processing through defineServiceExecAction
//   - Recursive subaction processing for nested command structures
//   - Error propagation from nested action creation
func (s *IdsecServiceExecAction) defineServiceExecActions(
	actionDef *actions.IdsecServiceCLIActionDefinition,
	cmd *cobra.Command,
	parentActionsDef []*actions.IdsecServiceCLIActionDefinition,
) error {
	actionSubparsers, err := s.defineServiceExecAction(actionDef, cmd, parentActionsDef)
	if err != nil {
		return err
	}
	if len(actionDef.Subactions) > 0 {
		for _, subaction := range actionDef.Subactions {
			err = s.defineServiceExecActions(subaction, actionSubparsers, append(parentActionsDef, actionDef))
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// fillParsedFlag processes complex flag values and validates choices for schema fields.
//
// fillParsedFlag handles the parsing of complex types (JSON objects and arrays)
// from string flag values and validates that field values match defined choices
// constraints. It processes mapstructure tags to find matching schema fields
// and applies appropriate transformations and validations.
//
// Parameters:
//   - schemaElem: The reflect.Type of the schema struct to process
//   - flags: Map of flag names to values being processed
//   - key: The specific flag key being processed
//   - f: The pflag.Flag being processed for error reporting
//
// Returns an error if JSON parsing fails or choice validation fails.
//
// The function handles:
//   - JSON unmarshaling for complex map and slice types
//   - Choice validation for string, string slice, and map types
//   - Recursive processing of squashed struct fields
//   - Error reporting with context about which flag failed
func (s *IdsecServiceExecAction) fillParsedFlag(schemaElem reflect.Type, flags map[string]interface{}, key string, f *pflag.Flag) error {
	for i := 0; i < schemaElem.NumField(); i++ {
		field := schemaElem.Field(i)
		if strings.HasPrefix(field.Tag.Get("mapstructure"), key) {
			if s.isComplexType(field) {
				if field.Type.Kind() == reflect.Map && field.Type.Key().Kind() == reflect.String && field.Type.Elem().Kind() == reflect.Struct {
					var mapJSON map[string]interface{}
					err := json.Unmarshal([]byte(flags[key].(string)), &mapJSON)
					if err != nil {
						return err
					}
					flags[key] = mapJSON
				} else {
					var sliceJSON []map[string]interface{}
					err := json.Unmarshal([]byte(flags[key].(string)), &sliceJSON)
					if err != nil {
						return err
					}
					flags[key] = sliceJSON
				}
			}
			if field.Tag.Get("choices") != "" {
				choices := strings.Split(field.Tag.Get("choices"), ",")
				switch v := flags[key].(type) {
				case string:
					if !slices.Contains(choices, v) {
						return fmt.Errorf("invalid value for flag %s: %s, valid choices are: %s", f.Name, v, strings.Join(choices, ", "))
					}
				case []string:
					for _, item := range v {
						if !slices.Contains(choices, item) {
							return fmt.Errorf("invalid value for flag %s: %s, valid choices are: %s", f.Name, item, strings.Join(choices, ", "))
						}
					}
				case map[string]any:
					for fieldKey := range v {
						if !slices.Contains(choices, fieldKey) {
							return fmt.Errorf("invalid key for flag %s: %s, valid choices are: %s", f.Name, fieldKey, strings.Join(choices, ", "))
						}
					}
				default:
					return fmt.Errorf("unexpected type for flag %s: %T", f.Name, flags[key])
				}
			}
		} else if field.Tag.Get("mapstructure") == ",squash" {
			err := s.fillParsedFlag(field.Type, flags, key, f)
			if err != nil {
				return err
			}
			continue
		}
	}
	return nil
}

// parseFlag extracts and converts flag values to appropriate types for schema processing.
//
// parseFlag handles the extraction of flag values from cobra commands and converts
// them to the appropriate Go types for later processing by mapstructure. It supports
// all common Go primitive types and collections, then applies complex type processing
// and choice validation through fillParsedFlag.
//
// Parameters:
//   - f: The pflag.Flag to process
//   - cmd: The cobra.Command containing the flag values
//   - flags: Map to store the parsed flag values
//   - schema: The schema interface for validation and complex type processing
//
// Returns an error if flag parsing or validation fails.
//
// The function handles:
//   - Type-specific flag value extraction (bool, int variants, float variants, slices, maps)
//   - Conversion of flag names from kebab-case to snake_case
//   - Delegation to fillParsedFlag for complex type processing and validation
//   - Skipping unchanged flags to avoid unnecessary processing
func (s *IdsecServiceExecAction) parseFlag(f *pflag.Flag, cmd *cobra.Command, flags map[string]interface{}, schema interface{}) error {
	if !f.Changed {
		return nil
	}
	key := strings.ReplaceAll(f.Name, "-", "_")
	switch f.Value.Type() {
	case "bool":
		val, err := cmd.Flags().GetBool(f.Name)
		if err == nil {
			flags[key] = val
		}
	case "int":
		val, err := cmd.Flags().GetInt(f.Name)
		if err == nil {
			flags[key] = val
		}
	case "int8":
		val, err := cmd.Flags().GetInt8(f.Name)
		if err == nil {
			flags[key] = val
		}
	case "int16":
		val, err := cmd.Flags().GetInt16(f.Name)
		if err == nil {
			flags[key] = val
		}
	case "int32":
		val, err := cmd.Flags().GetInt32(f.Name)
		if err == nil {
			flags[key] = val
		}
	case "int64":
		val, err := cmd.Flags().GetInt64(f.Name)
		if err == nil {
			flags[key] = val
		}
	case "uint":
		val, err := cmd.Flags().GetUint(f.Name)
		if err == nil {
			flags[key] = val
		}
	case "uint8":
		val, err := cmd.Flags().GetUint8(f.Name)
		if err == nil {
			flags[key] = val
		}
	case "uint16":
		val, err := cmd.Flags().GetUint16(f.Name)
		if err == nil {
			flags[key] = val
		}
	case "uint32":
		val, err := cmd.Flags().GetUint32(f.Name)
		if err == nil {
			flags[key] = val
		}
	case "uint64":
		val, err := cmd.Flags().GetUint64(f.Name)
		if err == nil {
			flags[key] = val
		}
	case "float32":
		val, err := cmd.Flags().GetFloat32(f.Name)
		if err == nil {
			flags[key] = val
		}
	case "float64":
		val, err := cmd.Flags().GetFloat64(f.Name)
		if err == nil {
			flags[key] = val
		}
	case "stringSlice":
		val, err := cmd.Flags().GetStringSlice(f.Name)
		if err == nil {
			flags[key] = val
		}
	case "[]string":
		val, err := cmd.Flags().GetStringSlice(f.Name)
		if err == nil {
			flags[key] = val
		}
	case "stringArray":
		val, err := cmd.Flags().GetStringArray(f.Name)
		if err == nil {
			flags[key] = val
		}
	case "intSlice":
		val, err := cmd.Flags().GetIntSlice(f.Name)
		if err == nil {
			flags[key] = val
		}
	case "[]int":
		val, err := cmd.Flags().GetIntSlice(f.Name)
		if err == nil {
			flags[key] = val
		}
	case "stringToString":
		val, err := cmd.Flags().GetStringToString(f.Name)
		if err == nil {
			flags[key] = val
		}
	case "map[string]string":
		// pflag actually parses it as a string in the format "map[key1:value1 key2:value2]"
		// And GetStringToString does not support it
		// Weird behavior, but we parse it ourselves
		value := cmd.Flag(f.Name).Value.String()
		value = strings.TrimSuffix(strings.TrimPrefix(value, "map["), "]")
		if len(value) == 0 {
			return nil
		}
		pairs := strings.Split(value, " ")
		out := make(map[string]string, len(pairs))
		for _, pair := range pairs {
			kv := strings.SplitN(pair, ":", 2)
			if len(kv) != 2 {
				return fmt.Errorf("%s must be formatted as key:value", pair)
			}
			out[kv[0]] = kv[1]
		}
		flags[key] = out
	default:
		flags[key] = f.Value.String()
	}
	schemaElem := reflect.TypeOf(schema).Elem()
	return s.fillParsedFlag(schemaElem, flags, key, f)
}

// serializeAndPrintOutput formats and displays the results of service action execution.
//
// serializeAndPrintOutput processes the reflection values returned from service
// method execution and formats them appropriately for console output. It handles
// various result types including structs, maps, arrays, channels, and primitive types.
//
// When pageSize > 0, list-shaped results (slices, arrays, channels) are rendered
// with one JSON item per line. In an interactive terminal, the CLI prints
// pageSize items, pauses for a keypress, and clears the screen before showing
// the next page. In non-interactive output (pipes, CI, redirections), the CLI
// writes a regular JSON array so the output remains scriptable. When pageSize
// is 0, the output is identical to the legacy pretty-printed JSON format.
//
// Parameters:
//   - result: Slice of reflect.Value containing the method execution results
//   - actionName: The name of the action being executed (for generic success messages)
//   - pageSize: Items per page for interactive paging (0 = disabled, legacy behavior)
//
// The function handles:
//   - JSON serialization for complex types (structs, maps, arrays, slices)
//   - Channel processing for paginated results with Items field extraction
//   - Integer formatting for numeric results
//   - Generic success messages when no specific output is available
//   - Error handling for JSON serialization failures with fallback output
func (s *IdsecServiceExecAction) serializeAndPrintOutput(result []reflect.Value, actionName string, pageSize int) {
	shouldPrintGenericResult := true
	for _, res := range result {
		if res.Kind() == reflect.Pointer && res.IsNil() {
			continue
		}
		if res.Kind() == reflect.Interface && res.Type().Implements(reflect.TypeOf((*error)(nil)).Elem()) {
			continue
		}
		if res.Kind() == reflect.Pointer {
			res = res.Elem()
		}
		if res.Kind() == reflect.Struct || res.Kind() == reflect.Map || res.Kind() == reflect.Array || res.Kind() == reflect.Slice {
			if pageSize > 0 && (res.Kind() == reflect.Array || res.Kind() == reflect.Slice) {
				s.pageItems(seqFromSlice(res), pageSize)
			} else {
				jsonData, err := json.MarshalIndent(res.Interface(), "", "  ")
				if err != nil {
					s.logger.Warning("error serializing result to JSON: %v", err)
					args.PrintSuccess(res.Interface())
				} else {
					args.PrintSuccess(string(jsonData))
				}
			}
			shouldPrintGenericResult = false
		} else if res.Kind() == reflect.Chan {
			if pageSize > 0 {
				s.pageItems(seqFromChannel(res), pageSize)
			} else {
				items := slices.Collect(seqFromChannel(res))
				if items == nil {
					items = []interface{}{}
				}
				jsonData, err := json.MarshalIndent(items, "", "  ")
				if err != nil {
					s.logger.Warning("error serializing result to JSON: %v", err)
					args.PrintSuccess(items)
				} else {
					args.PrintSuccess(string(jsonData))
				}
			}
			shouldPrintGenericResult = false
		} else if res.Kind() == reflect.Int {
			args.PrintSuccess(fmt.Sprintf("%d", res.Int()))
			shouldPrintGenericResult = false
		} else if res.Kind() == reflect.Bool {
			args.PrintSuccess(fmt.Sprintf("%t", res.Bool()))
			shouldPrintGenericResult = false
		} else {
			args.PrintSuccess(res.Interface())
			shouldPrintGenericResult = false
		}
	}
	if len(result) == 0 || shouldPrintGenericResult {
		caser := cases.Title(language.English)
		args.PrintSuccess(fmt.Sprintf("%s finished successfully", strings.ReplaceAll(caser.String(actionName), "-", " ")))
	}
}

// extractOutputValue returns the single printable value from a method result
// slice using the same kind discrimination as serializeAndPrintOutput. Channels
// are drained into a slice. Returns (nil, false) when every value is nil or an
// error — the "no printable output" case.
func (s *IdsecServiceExecAction) extractOutputValue(result []reflect.Value) (any, bool) {
	for _, res := range result {
		if res.Kind() == reflect.Pointer && res.IsNil() {
			continue
		}
		if res.Kind() == reflect.Interface && res.Type().Implements(reflect.TypeOf((*error)(nil)).Elem()) {
			continue
		}
		if res.Kind() == reflect.Pointer {
			res = res.Elem()
		}
		switch res.Kind() {
		case reflect.Struct, reflect.Map, reflect.Array, reflect.Slice:
			return res.Interface(), true
		case reflect.Chan:
			items := slices.Collect(seqFromChannel(res))
			if items == nil {
				items = []interface{}{}
			}
			return items, true
		case reflect.Int:
			return res.Int(), true
		case reflect.Bool:
			return res.Bool(), true
		default:
			return res.Interface(), true
		}
	}
	return nil, false
}

// applyQueryAndPrint evaluates a jq expression against the command result and
// prints each output value, one per line (see applyGojqQuery for raw/JSON
// rendering rules).
//
// When the result carries no printable value the query runs against JSON null
// (jq's empty-input model) rather than emitting a human-readable sentinel — so
// a capture like ID=$(idsec ... --query '.pool_id') stays a clean null/empty
// instead of picking up a "finished successfully" sentence.
func (s *IdsecServiceExecAction) applyQueryAndPrint(result []reflect.Value, query string, raw bool, vars ...queryVar) error {
	value, _ := s.extractOutputValue(result)
	return applyGojqQuery(value, query, raw, vars...)
}

// seqFromSlice yields each element of a slice or array reflect.Value as a
// generic value, so slice-based and channel-based results can share one
// rendering path.
func seqFromSlice(v reflect.Value) iter.Seq[any] {
	return func(yield func(any) bool) {
		for i := 0; i < v.Len(); i++ {
			if !yield(v.Index(i).Interface()) {
				return
			}
		}
	}
}

// seqFromChannel receives pages from a channel reflect.Value and yields each
// item. Each page exposes its elements via an Items slice field; a page without
// that field is yielded whole. Consumers that read the whole sequence drain the
// SDK channel; interactive paging may stop early when the user quits.
func seqFromChannel(ch reflect.Value) iter.Seq[any] {
	return func(yield func(any) bool) {
		for {
			pageValue, ok := ch.Recv()
			if !ok {
				return
			}
			if !pageValue.IsValid() {
				continue
			}
			if pageValue.Kind() == reflect.Pointer {
				pageValue = pageValue.Elem()
			}
			itemsField := pageValue.FieldByName("Items")
			if !itemsField.IsValid() || itemsField.Kind() != reflect.Slice {
				if !yield(pageValue.Interface()) {
					return
				}
				continue
			}
			for i := 0; i < itemsField.Len(); i++ {
				if !yield(itemsField.Index(i).Interface()) {
					return
				}
			}
		}
	}
}

// shouldContinueForNextItem is the generic paging decision hook. It is a var so
// tests can stub boundary behavior without terminal input.
var shouldContinueForNextItem = args.ShouldContinueForNextItem

// pageItems renders items as JSON. When stdout is an
// interactive terminal it pages the output, printing pageSize items and then
// pausing for a keypress before continuing, so "--page-size N" means exactly N
// items per page. When stdout is not a TTY (pipes, CI, redirections) it instead
// writes a valid JSON array so the output stays scriptable.
func (s *IdsecServiceExecAction) pageItems(items iter.Seq[any], pageSize int) {
	if pageSize > 0 && args.IsStdoutTTY() {
		s.pageItemsInteractive(items, pageSize)
		return
	}
	s.writeJSONArray(os.Stdout, items)
}

// pageItemsInteractive prints items as pretty JSON, a page of pageSize items at
// a time. At each page boundary it pauses for a keypress; on continue it prints
// the next page below the previous output, and on quit it returns immediately.
// Returning stops reading the sequence at once (important for
// channel-backed results so quitting does not wait for the rest to be fetched);
// any remaining SDK producer goroutine is reclaimed when the process exits.
func (s *IdsecServiceExecAction) pageItemsInteractive(items iter.Seq[any], pageSize int) {
	count := 0
	for item := range items {
		line, err := json.MarshalIndent(item, "", "  ")
		if err != nil {
			s.logger.Warning("error marshaling item to JSON: %v", err)
			continue
		}
		if !shouldContinueForNextItem(count, pageSize) {
			return
		}
		_, _ = os.Stdout.Write(line)
		// Add a blank line between items for readability in interactive paging.
		_, _ = io.WriteString(os.Stdout, "\n")
		count++
	}
}

// writeJSONArray writes items as a pretty JSON array, suitable for piping or
// redirection. Write errors (e.g. a broken pipe when the downstream consumer
// exits early, as in "... | head") stop the loop so the channel is not
// needlessly drained, and are logged once.
func (s *IdsecServiceExecAction) writeJSONArray(w io.Writer, items iter.Seq[any]) {
	var werr error
	write := func(str string) {
		if werr != nil {
			return
		}
		_, werr = io.WriteString(w, str)
	}

	write("[\n")
	first := true
	for item := range items {
		if werr != nil {
			break
		}
		line, err := json.MarshalIndent(item, "", "  ")
		if err != nil {
			s.logger.Warning("error marshaling item to JSON: %v", err)
			continue
		}
		if !first {
			write(",\n")
		}
		first = false
		write("  " + strings.ReplaceAll(string(line), "\n", "\n  "))
	}
	write("\n]\n")
	if werr != nil {
		s.logger.Warning("error writing output: %v", werr)
	}
}

// findMethodByName locates a method on a reflect.Value using case-insensitive matching.
//
// findMethodByName searches for a method by name on the provided reflection value,
// first attempting an exact match and then falling back to case-insensitive matching
// if the exact match fails. This provides flexibility for method name variations.
//
// Parameters:
//   - value: The reflect.Value to search for methods on
//   - methodName: The name of the method to find
//
// Returns a pointer to the reflect.Value representing the method and any error
// encountered during the search.
//
// The function handles:
//   - Exact method name matching first
//   - Case-insensitive fallback matching through all available methods
//   - Error reporting when no matching method is found
func (s *IdsecServiceExecAction) findMethodByName(value reflect.Value, methodName string) (*reflect.Value, error) {
	actionMethod := value.MethodByName(methodName)
	if !actionMethod.IsValid() {
		for i := 0; i < value.NumMethod(); i++ {
			method := value.Type().Method(i)
			if strings.EqualFold(method.Name, methodName) {
				actionMethod = value.MethodByName(method.Name)
				break
			}
		}
		if !actionMethod.IsValid() {
			return nil, fmt.Errorf("method %s not found", methodName)
		}
	}
	return &actionMethod, nil
}

// resolveActionArgs resolves and prepares action arguments from command flags and schema.
//
// resolveActionArgs processes command-line flags, applies validation and defaults,
// and prepares the final argument values for service method invocation. It handles
// reading from request files and the complete flow of flag parsing, schema population, and default value application.
//
// Parameters:
//   - cmd: The cobra command being executed, containing the flags to parse
//   - execCmd: The parent execution command for context, used for accessing persistent flags such as request-file
//   - actionSchema: The schema struct to populate with flag values and defaults
//
// Returns a slice containing a single reflect.Value wrapping the populated schema,
// ready for use with reflect method invocation. Returns error if file reading,
// flag parsing, mapstructure decoding, or default application fails.
//
// Example:
//
//	actionArgs, err := s.resolveActionArgs(cmd, execCmd, &addDatabaseSchema)
//	if err != nil {
//	    return nil, err
//	}
//	result := actionMethod.Call(actionArgs)
func (s *IdsecServiceExecAction) resolveActionArgs(cmd *cobra.Command, execCmd *cobra.Command, actionSchema interface{}) ([]reflect.Value, error) {
	flags := map[string]interface{}{}
	if requestFile, err := execCmd.PersistentFlags().GetString("request-file"); err == nil && requestFile != "" {
		fileContent, err := os.ReadFile(requestFile) // #nosec G304
		if err != nil {
			return nil, err
		}
		var data map[string]interface{}
		err = json.Unmarshal(fileContent, &data)
		if err != nil {
			return nil, err
		}
		schemaType := reflect.ValueOf(actionSchema).Type()
		flags = common.ConvertToSnakeCase(data, &schemaType).(map[string]interface{})
	}
	var err error
	err = s.applyDefaults(actionSchema)
	if err != nil {
		return nil, err
	}
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		// Prevent overwriting an existing error from a previously parsed flag.
		if err != nil {
			return
		}
		err = s.parseFlag(f, cmd, flags, actionSchema)
	})
	if err != nil {
		return nil, err
	}
	decoderConfig := &mapstructure.DecoderConfig{
		ZeroFields: true,
		Result:     actionSchema,
		TagName:    "mapstructure",
	}
	decoder, err := mapstructure.NewDecoder(decoderConfig)
	if err != nil {
		return nil, err
	}
	err = decoder.Decode(flags)
	if err != nil {
		return nil, err
	}
	actionArgs := []reflect.Value{reflect.ValueOf(actionSchema)}
	return actionArgs, nil
}

// DefineExecAction defines the execution actions for all supported service operations.
//
// DefineExecAction processes all supported service action definitions and creates
// the corresponding cobra command hierarchy for service execution. It iterates through
// the available service actions and creates the complete command structure for
// dynamic service operation execution.
//
// Parameters:
//   - cmd: The parent cobra command to add service execution commands to
//
// Returns an error if any service action definition processing fails.
//
// The function handles:
//   - Processing all supported service actions from the services package
//   - Creating command hierarchies for each service action through defineServiceExecActions
//   - Error propagation from nested action processing
//
// Example:
//
//	err := serviceExecAction.DefineExecAction(rootCmd)
//	// This adds all supported service commands to rootCmd
func (s *IdsecServiceExecAction) DefineExecAction(cmd *cobra.Command) error {
	for _, cliActionDef := range registry.TopLevelCLIActions() {
		err := s.defineServiceExecActions(cliActionDef, cmd, nil)
		if err != nil {
			return err
		}
	}

	return nil
}

// RunExecAction executes a service action using reflection-based method invocation.
//
// RunExecAction processes the command hierarchy to determine the target service and action,
// then uses reflection to locate and invoke the appropriate method on the API service.
// It handles flag parsing, schema validation, method resolution, and output formatting
// for dynamic service action execution.
//
// Parameters:
//   - api: The IdsecCLIAPI instance containing the service methods
//   - cmd: The cobra command being executed
//   - execCmd: The parent execution command for context
//   - execArgs: Command line arguments for the execution
//
// Returns an error if service resolution, method invocation, or parameter processing fails.
//
// The function handles:
//   - Service path resolution from command hierarchy
//   - Method name transformation and case-insensitive lookup
//   - Schema resolution from service action definitions
//   - Flag parsing and validation against schema constraints
//   - Request file input for complex payloads
//   - Method invocation with appropriate parameters
//   - Result serialization and output formatting
//
// Example:
//
//	err := serviceExecAction.RunExecAction(api, cmd, execCmd, args)
//	// Executes the service method and displays formatted output
func (s *IdsecServiceExecAction) RunExecAction(api *cli.IdsecCLIAPI, cmd *cobra.Command, execCmd *cobra.Command, execArgs []string) error {
	serviceParts := make([]string, 0)
	for currentCmd := cmd.Parent(); currentCmd != execCmd; currentCmd = currentCmd.Parent() {
		serviceParts = append([]string{currentCmd.Name()}, serviceParts...)
	}
	actionName := cmd.Name()
	caser := cases.Title(language.English)
	actionNameTitled := strings.ReplaceAll(caser.String(actionName), "-", "")
	serviceNameTitled := ""
	for _, part := range serviceParts {
		serviceNameTitled += caser.String(part)
	}
	serviceNameTitled = strings.ReplaceAll(caser.String(serviceNameTitled), "-", "")
	// First, resolve the action method
	serviceMethod, err := s.findMethodByName(reflect.ValueOf(api), serviceNameTitled)
	if err != nil {
		return err
	}
	serviceErr := serviceMethod.Call(nil)
	service := serviceErr[0]
	if len(serviceErr) > 1 {
		if err, ok := serviceErr[1].Interface().(error); ok && err != nil {
			return err
		}
	}
	if svc, ok := service.Interface().(sdkservices.IdsecService); ok {
		for shortKey, value := range s.cliContextTags {
			_ = svc.AddExtraContextField(cliContextFullName(shortKey), shortKey, value)
		}
		defer func() { _ = svc.ClearExtraContext() }()
	}
	actionMethod, err := s.findMethodByName(reflect.ValueOf(service.Interface()), actionNameTitled)
	if err != nil {
		return err
	}

	// Resolve the action schema
	var actionSchemaDef *actions.IdsecServiceCLIActionDefinition = nil
	for _, servicePart := range serviceParts {
		if actionSchemaDef != nil {
			for _, actionDef := range actionSchemaDef.Subactions {
				if actionDef.ActionName == servicePart {
					actionSchemaDef = actionDef
					break
				}
			}
		} else {
			for _, cliActionDef := range registry.TopLevelCLIActions() {
				if cliActionDef.ActionName == servicePart {
					actionSchemaDef = cliActionDef
					break
				}
			}
			if actionSchemaDef == nil {
				return fmt.Errorf("action %s not found in service %s", actionName, serviceNameTitled)
			}
		}
	}
	rawActionSchema, ok := actionSchemaDef.Schemas[actionName]
	if !ok {
		return fmt.Errorf("action %s not supported", actionName)
	}
	actionSchema, _ := actions.UnwrapSchema(rawActionSchema)
	if actionSchema != nil {
		actionSchemaType := reflect.TypeOf(actionSchema)
		if actionSchemaType.Kind() == reflect.Ptr {
			actionSchemaType = actionSchemaType.Elem()
		}
		actionSchema = reflect.New(actionSchemaType).Interface()
	}
	var result []reflect.Value
	if actionSchema != nil {
		actionArgs, err := s.resolveActionArgs(cmd, execCmd, actionSchema)
		if err != nil {
			return err
		}
		if err := validation.ValidateStruct(actionSchema); err != nil {
			return fmt.Errorf("invalid input for action %q: %w", actionName, err)
		}
		result = actionMethod.Call(actionArgs)
	} else {
		var actionArgs []reflect.Value
		result = actionMethod.Call(actionArgs)
	}
	for _, res := range result {
		if err, ok := res.Interface().(error); ok && err != nil {
			return err
		}
	}

	// --query takes precedence over formatters and the default JSON serializer.
	query, _ := execCmd.PersistentFlags().GetString("query")
	if query != "" {
		raw, _ := execCmd.PersistentFlags().GetBool("raw")
		vars, err := queryVarsFromFlags(execCmd.PersistentFlags())
		if err != nil {
			return err
		}
		return s.applyQueryAndPrint(result, query, raw, vars...)
	}

	format, _ := execCmd.PersistentFlags().GetString("format")
	pageSize, _ := execCmd.PersistentFlags().GetInt("page-size")
	if pageSize < 0 {
		pageSize = 0
	}

	// When the action definition carries a CLIFormatter for this action name
	// and the user has not explicitly requested JSON output, delegate rendering
	// to the formatter instead of the default JSON serializer.
	var formatter actions.CLIFormatter
	if actionSchemaDef != nil && actionSchemaDef.Formatters != nil {
		formatter = actionSchemaDef.Formatters[actionName]
	}
	if formatter != nil && format != "json" {
		for _, res := range result {
			if res.Kind() == reflect.Pointer && res.IsNil() {
				continue
			}
			if res.Kind() == reflect.Interface && res.Type().Implements(reflect.TypeOf((*error)(nil)).Elem()) {
				continue
			}
			args.PrintNormal(formatter.Format(res.Interface()))
			return nil
		}
		// Nothing printable — fall through to generic message.
		s.serializeAndPrintOutput(result, actionName, pageSize)
		return nil
	}

	s.serializeAndPrintOutput(result, actionName, pageSize)

	return nil
}

// dryRunExecAction builds the dry-run plan for the leaf command and prints it
// as indented JSON to stdout. It performs no authentication, profile loading,
// or SDK invocation. When --query is given, the jq expression is applied to the
// plan instead of the plan being dumped whole, so the same expression can be
// rehearsed against a plan before it is run for real. The returned error is also
// surfaced to the user; the caller may ignore it.
func (s *IdsecServiceExecAction) dryRunExecAction(cmd *cobra.Command) error {
	plan, err := s.buildDryRunPlan(cmd)
	if err != nil {
		args.PrintFailure(fmt.Sprintf("Failed to build dry-run plan: %s", err))
		return err
	}

	// Non-nil here: buildDryRunPlan already failed out if exec was not found.
	execCmd := findExecCommand(cmd)
	if query, _ := execCmd.PersistentFlags().GetString("query"); query != "" {
		raw, _ := execCmd.PersistentFlags().GetBool("raw")
		vars, err := queryVarsFromFlags(execCmd.PersistentFlags())
		if err != nil {
			args.PrintFailure(err.Error())
			return err
		}
		if err := applyGojqQuery(plan, query, raw, vars...); err != nil {
			args.PrintFailure(err.Error())
			return err
		}
		return nil
	}

	data, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		args.PrintFailure(fmt.Sprintf("Failed to render dry-run plan: %s", err))
		return err
	}
	_, _ = fmt.Fprintln(os.Stdout, string(data))
	return nil
}

// buildDryRunPlan resolves the operation identity, effective profile name, and
// effective arguments (with secrets masked) for the leaf command, using only
// the command tree and the CLI action registry. It never authenticates or
// calls a service.
func (s *IdsecServiceExecAction) buildDryRunPlan(cmd *cobra.Command) (*dryRunPlan, error) {
	execCmd := findExecCommand(cmd)
	if execCmd == nil {
		return nil, fmt.Errorf("failed to find exec command")
	}

	serviceParts := commandServiceParts(cmd, execCmd)
	actionName := cmd.Name()

	profileName, _ := execCmd.Flags().GetString("profile-name")

	actionSchema, err := resolveDryRunSchema(serviceParts, actionName)
	if err != nil {
		return nil, err
	}

	requestFileArgs, err := readDryRunRequestFile(execCmd, actionSchema)
	if err != nil {
		return nil, err
	}

	resolvedArgs, secretFields := resolveDryRunArgs(cmd, actionSchema, requestFileArgs)

	return &dryRunPlan{
		Operation:    deriveOperation(serviceParts, actionName),
		Profile:      profiles.DeduceProfileName(profileName),
		ResolvedArgs: resolvedArgs,
		SecretFields: secretFields,
	}, nil
}

// findExecCommand walks up from cmd to the "exec" command, returning nil when
// it is not found.
func findExecCommand(cmd *cobra.Command) *cobra.Command {
	for c := cmd; c != nil; c = c.Parent() {
		if c.Use == "exec" {
			return c
		}
	}
	return nil
}

// commandServiceParts returns the command path between exec (exclusive) and the
// leaf command (exclusive), i.e. the service/resource segments. For
// "idsec exec sia access install-connector" it returns ["sia", "access"].
func commandServiceParts(cmd *cobra.Command, execCmd *cobra.Command) []string {
	parts := make([]string, 0)
	for c := cmd.Parent(); c != nil && c != execCmd; c = c.Parent() {
		parts = append([]string{c.Name()}, parts...)
	}
	return parts
}

// deriveOperation joins the service parts and action name into a dotted
// operation identifier, converting each segment's dashes to underscores.
// ["sia", "access"] + "install-connector" -> "sia.access.install_connector".
func deriveOperation(serviceParts []string, actionName string) string {
	segments := make([]string, 0, len(serviceParts)+1)
	for _, part := range serviceParts {
		segments = append(segments, strings.ReplaceAll(part, "-", "_"))
	}
	segments = append(segments, strings.ReplaceAll(actionName, "-", "_"))
	return strings.Join(segments, ".")
}

// resolveDryRunSchema locates the request schema for the action from the CLI
// action registry, mirroring the resolution used by RunExecAction. It returns
// a nil schema (and nil error) for actions that take no arguments.
func resolveDryRunSchema(serviceParts []string, actionName string) (interface{}, error) {
	var actionSchemaDef *actions.IdsecServiceCLIActionDefinition
	for _, servicePart := range serviceParts {
		if actionSchemaDef != nil {
			var next *actions.IdsecServiceCLIActionDefinition
			for _, sub := range actionSchemaDef.Subactions {
				if sub.ActionName == servicePart {
					next = sub
					break
				}
			}
			actionSchemaDef = next
		} else {
			for _, cliActionDef := range registry.TopLevelCLIActions() {
				if cliActionDef.ActionName == servicePart {
					actionSchemaDef = cliActionDef
					break
				}
			}
		}
		if actionSchemaDef == nil {
			return nil, fmt.Errorf("action %s not found for service path %s", actionName, strings.Join(serviceParts, " "))
		}
	}
	if actionSchemaDef == nil {
		return nil, fmt.Errorf("action %s not found", actionName)
	}
	rawActionSchema, ok := actionSchemaDef.Schemas[actionName]
	if !ok {
		return nil, fmt.Errorf("action %s not supported", actionName)
	}
	schema, _ := actions.UnwrapSchema(rawActionSchema)
	return schema, nil
}

// readDryRunRequestFile loads and snake-cases the --request-file JSON so the
// dry-run plan reflects the same values a real run would merge. --request-file
// is the mandated secret channel, so its contents must appear in the plan
// (with secrets masked). It returns (nil, nil) when no request file is set.
func readDryRunRequestFile(execCmd *cobra.Command, schema interface{}) (map[string]interface{}, error) {
	requestFile, err := execCmd.PersistentFlags().GetString("request-file")
	if err != nil || requestFile == "" {
		return nil, nil
	}
	fileContent, err := os.ReadFile(requestFile) // #nosec G304
	if err != nil {
		return nil, err
	}
	var data map[string]interface{}
	if err := json.Unmarshal(fileContent, &data); err != nil {
		return nil, err
	}
	if schema == nil {
		return data, nil
	}
	schemaType := reflect.ValueOf(schema).Type()
	converted, _ := common.ConvertToSnakeCase(data, &schemaType).(map[string]interface{})
	return converted, nil
}

// resolveDryRunArgs builds the resolved_args map (kebab-case keys) and the
// list of masked secret fields from the leaf command's local flags merged with
// the request file. A flag is included when the user provided it or it carries
// a non-zero applied default; request-file values fill in fields not set on the
// command line (an explicit flag wins). Values backed by a `secret:"true"`
// schema field are masked wherever they originate.
func resolveDryRunArgs(cmd *cobra.Command, schema interface{}, requestFileArgs map[string]interface{}) (map[string]string, []string) {
	secretFlags := map[string]bool{}
	snakeToFlag := map[string]string{}
	if schema != nil {
		collectSecretFlags(reflect.TypeOf(schema), secretFlags)
		collectRequestFileKeyMap(reflect.TypeOf(schema), snakeToFlag)
	}

	resolvedArgs := map[string]string{}
	secretSet := map[string]bool{}
	cmd.LocalFlags().VisitAll(func(f *pflag.Flag) {
		if f.Name == "help" || !dryRunFlagIncluded(f) {
			return
		}
		if secretFlags[f.Name] {
			resolvedArgs[f.Name] = secretMask
			secretSet[f.Name] = true
			return
		}
		resolvedArgs[f.Name] = effectiveFlagValue(f)
	})

	for snakeKey, value := range requestFileArgs {
		flagName := snakeToFlag[snakeKey]
		if flagName == "" {
			flagName = strings.ReplaceAll(snakeKey, "_", "-")
		}
		if _, ok := resolvedArgs[flagName]; ok {
			continue // an explicit flag takes precedence over the request file
		}
		if secretFlags[flagName] {
			resolvedArgs[flagName] = secretMask
			secretSet[flagName] = true
			continue
		}
		resolvedArgs[flagName] = fmt.Sprintf("%v", value)
	}

	secretFields := make([]string, 0, len(secretSet))
	for name := range secretSet {
		secretFields = append(secretFields, name)
	}
	sort.Strings(secretFields)
	return resolvedArgs, secretFields
}

// collectRequestFileKeyMap walks a schema struct type, recursing through
// squashed embedded structs, and maps each field's request-file (snake_case)
// key to its CLI flag name, so request-file values can be presented and masked
// under the same names as command-line flags.
func collectRequestFileKeyMap(t reflect.Type, set map[string]string) {
	if t == nil {
		return
	}
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return
	}
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if strings.Contains(field.Tag.Get("mapstructure"), ",squash") {
			collectRequestFileKeyMap(field.Type, set)
			continue
		}
		set[requestFileKeyForField(field)] = flagNameForField(field)
	}
}

// requestFileKeyForField derives the snake_case key a request file would use
// for a schema field, preferring the first `mapstructure` segment and falling
// back to the flag name with dashes converted to underscores.
func requestFileKeyForField(field reflect.StructField) string {
	if v := field.Tag.Get("mapstructure"); v != "" {
		if idx := strings.Index(v, ","); idx >= 0 {
			v = v[:idx]
		}
		if v != "" && v != "-" {
			return v
		}
	}
	return strings.ReplaceAll(flagNameForField(field), "-", "_")
}

// dryRunRequested reports whether --dry-run appears (truthy) in the process
// arguments. Required-flag validation is skipped in that case.
func dryRunRequested() bool {
	for _, arg := range os.Args[1:] {
		if arg == "--dry-run" {
			return true
		}
		if strings.HasPrefix(arg, "--dry-run=") {
			if enabled, err := strconv.ParseBool(strings.TrimPrefix(arg, "--dry-run=")); err == nil && enabled {
				return true
			}
		}
	}
	return false
}

// dryRunFlagIncluded reports whether a flag should appear in resolved_args: it
// was changed by the user, or it has a meaningful (non-zero) default value.
func dryRunFlagIncluded(f *pflag.Flag) bool {
	if f.Changed {
		return true
	}
	return f.DefValue != "" && !isZeroDefaultValue(f.DefValue)
}

// effectiveFlagValue returns the value that would actually be sent: the value
// the user provided when the flag was changed, otherwise the applied default.
// Unchanged flags carry their zero value in Value while the schema default is
// mirrored onto DefValue, so DefValue is the effective value in that case.
func effectiveFlagValue(f *pflag.Flag) string {
	if f.Changed {
		return f.Value.String()
	}
	return f.DefValue
}

// isZeroDefaultValue reports whether a pflag default string represents the zero
// value for its type, so unset fields without a meaningful default are omitted.
func isZeroDefaultValue(def string) bool {
	switch def {
	case "", "0", "false", "[]", "map[]", "0s":
		return true
	default:
		return false
	}
}

// collectSecretFlags walks a schema struct type, recursing through squashed
// embedded structs, and records the flag name of every field marked
// `secret:"true"`.
func collectSecretFlags(t reflect.Type, set map[string]bool) {
	if t == nil {
		return
	}
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return
	}
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if strings.Contains(field.Tag.Get("mapstructure"), ",squash") {
			collectSecretFlags(field.Type, set)
			continue
		}
		if actions.FieldIsSecret(field) {
			set[flagNameForField(field)] = true
		}
	}
}

// flagNameForField derives the CLI flag name for a schema field, preferring the
// `flag` tag, then the first `mapstructure` segment, then the lowercased field
// name.
func flagNameForField(field reflect.StructField) string {
	if v := field.Tag.Get("flag"); v != "" {
		return v
	}
	if v := field.Tag.Get("mapstructure"); v != "" {
		if idx := strings.Index(v, ","); idx >= 0 {
			v = v[:idx]
		}
		if v != "" && v != "-" {
			return v
		}
	}
	return strings.ToLower(field.Name)
}
