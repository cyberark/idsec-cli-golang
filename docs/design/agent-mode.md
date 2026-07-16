# Design: Agent Mode for `idsec-cli-golang`

> Status: Proposal / Design (no code changes yet). All Go snippets are illustrative.

## 1. Overview & Goals

### Motivation

`idsec` (the CyberArk Idira Identity Security CLI) is a Go/Cobra binary designed
around a *human* operator: it prompts interactively with `survey`, prints colored
success/failure lines, shows an upgrade nag, and gates most output on
"interactive OR allow-output". When driven by an AI coding agent (Claude Code,
Cursor, Codex, etc.) this is actively harmful: prompts hang on a closed stdin,
prose output is hard to parse, and errors are emitted to **stdout** as free text.

We want an **agent mode** — modeled on Datadog's [`pup`](https://docs.datadoghq.com/cli/)
CLI — that is *auto-detected* when running under a known agent and adjusts
behavior so the CLI is safe and ergonomic for machine consumption.

### Goals

1. **Zero behavior change for humans.** Default (no agent detected, no flag)
   output is byte-for-byte identical to today.
2. **Never hang.** In agent mode, no code path may block on stdin. Missing
   required input → fail fast with a structured error.
3. **Structured, parseable output.** Success payloads, generic messages, and
   errors are emitted as a single stable JSON envelope on stdout.
4. **Machine-readable discovery.** A dedicated `idsec schema` command serializes
   the registry + struct-tag metadata to JSON so an agent can discover
   services/resources/actions/flags without scraping `--help` prose.
5. **stdout/stderr discipline.** Machine data → stdout; diagnostics, warnings,
   logs → stderr.
6. **Idiomatic to idsec.** Follow `Idsec<Domain><Entity>` naming, `IDSEC_<FEATURE>`
   env vars, full struct-tag set, interface-satisfaction checks, table-driven
   tests, and the existing `flags > env > config > default` precedence.

### Non-goals

- Rewriting the reflection/`sflags` exec engine.
- Changing the SDK's public `config` API surface for TF-provider consumers.
- Adding new network behavior. Agent mode only changes *presentation* and
  *interactivity*, not *what* the CLI calls.

## 2. Current-State Analysis (verified in-repo)

| Concern | Where it lives today | Relevant behavior |
|---|---|---|
| Entry / error handling | `cmd/idsec/idsec.go` → `handleCommandExecution` | Errors printed with `fmt.Println(err)` to **stdout**, then `os.Exit(1)`. Unknown first-arg routed to `exec`. Custom help appends "Available services". |
| Common flags | `pkg/actions/idsec_action.go` → `CommonActionsConfiguration(cmd)` | Registers persistent flags: `raw`, `silent`, `allow-output`, `verbose`, etc. **Natural home for `--agent`/`--no-agent`.** |
| Flag→state resolution | `pkg/actions/idsec_action.go` → `CommonActionsExecution(cmd,args,printUpgrade)` | Sets SDK config defaults then flips toggles per flag; also prints the upgrade nag (gated on `IsInteractive()`). **Natural home to resolve agent mode + flip toggles.** |
| Global runtime state | SDK `github.com/cyberark/idsec-sdk-golang/pkg/config` | Package-level vars + getters/setters: `IsColoring`, `IsInteractive`, `IsAllowingOutput`, telemetry, proxy, trusted cert, `SetIdsecToolInUse`. **Shared with the Terraform provider.** No agent concept. |
| CLI-local config | CLI `pkg/config/config_file.go` | Loads `~/.idsec/config.yaml` → sets `IDSEC_*` env vars if not already set. `envVarPrefix = "IDSEC_"`. |
| Output primitives | CLI `pkg/common/args/idsec_args_formatter.go` | `PrintColored/Success/Failure/Warning/Normal` all gate on `config.IsInteractive() || config.IsAllowingOutput()` and write to **stdout**. |
| Interactive prompts | CLI `pkg/common/args/idsec_args_formatter.go` | `GetArg/GetBoolArg/GetSwitchArg/GetCheckboxArgs` call `survey.AskOne` — **block on stdin**, no TTY guard. |
| Exec output | CLI `pkg/actions/idsec_service_exec_action.go` → `serializeAndPrintOutput` | Structs/maps/slices/channels → `json.MarshalIndent` via `args.PrintSuccess`. Generic `"<Action> finished successfully"` plain string. `pageItems` pages only when `args.IsStdoutTTY()`, else writes a JSON array. |
| Exec failure path | CLI `pkg/actions/idsec_exec_action.go` → `runExecAction` | Failures via `args.PrintFailure(...)` (stdout). "Not all authenticators are logged in" gated on `IsInteractive()`. |
| Schema model | SDK `pkg/models/actions/...` + CLI `pkg/registry/{registry,init}.go` | `TopLevelCLIActions()` returns a tree of `*IdsecServiceCLIActionDefinition{ ActionName, ActionAliases, ActionDescription, Schemas map[string]interface{}, Subactions, Deprecation }`. `Schemas` values unwrap via `actions.UnwrapSchema`. Struct tags: `flag`, `desc`, `default`, `validate:"required"`, `choices`, `mapstructure`, `json`. |
| TTY helper | CLI `pkg/common/args/pager.go` → `IsStdoutTTY` (overridable var) | Already used for paging decisions. |
| Machine-output precedent | CLI `pkg/actions/idsec_version_action.go` | `idsec version --silent` prints bare version; suppresses the upgrade hint for scriptability. |
| File logging | SDK config env vars (`IDSEC_FILE_LOG_PATH`, `.idsec/logs`) | Credential-sanitized, independent of stdout. Already agent-safe. |

**Key architectural takeaway:** almost every human-only behavior is already gated
on the SDK config trio `IsColoring / IsInteractive / IsAllowingOutput`. Agent mode
can be implemented largely by *setting those toggles correctly* plus a small
CLI-local "am I in agent mode?" flag that the CLI's `args` and exec code consult
to switch on the JSON envelope. **No SDK change is required.**

## 3. Detection & Activation Design

### 3.1 New package: `pkg/agentmode`

Create a **CLI-local leaf package** `github.com/cyberark/idsec-cli-golang/pkg/agentmode`.
It holds:

- the detection registry (env-var → agent name),
- the resolution/precedence logic,
- the resolved global state (`Enable`, `IsEnabled`, `DetectedAgent`).

It depends only on `os` (and optionally the SDK `common` logger), so both
`pkg/actions` and `pkg/common/args` can import it without an import cycle
(`args` already imports SDK `config`; `agentmode` will not import `args`).

> Naming note: `pkg/agentmode` (short, discoverable) is recommended over
> `pkg/common/agentmode`. It is a top-level cross-cutting concern like
> `pkg/config`, not a `common` utility. Exported types stay idsec-idiomatic
> (e.g. `agentmode.KnownAgent`).

### 3.2 Detection registry (env-var table)

Third-party detection variables are kept **exactly as the tools set them** (they
are not idsec's to rename). Only idsec's own override/mode vars carry the
`IDSEC_` prefix.

```go
// pkg/agentmode/detect.go (illustrative)
package agentmode

// knownAgents maps a detector to the tool that sets it. Order is stable so the
// first matching entry wins for reporting DetectedAgent().
var knownAgents = []struct {
    EnvVar string
    Name   string
}{
    {"CLAUDECODE", "claude-code"},
    {"CLAUDE_CODE", "claude-code"},
    {"CURSOR_AGENT", "cursor"},
    {"CODEX", "codex"},
    {"OPENAI_CODEX", "codex"},
    {"AIDER", "aider"},
    {"CLINE", "cline"},
    {"WINDSURF_AGENT", "windsurf"},
    {"GITHUB_COPILOT", "github-copilot"},
    {"AMAZON_Q", "amazon-q"},
    {"AWS_Q_DEVELOPER", "amazon-q"},
    {"GEMINI_CODE_ASSIST", "gemini-code-assist"},
    {"SRC_CODY", "sourcegraph-cody"},
    {"PI_CODING_AGENT", "pi"},
    {"AGENT", "generic"}, // generic opt-in; lowest-priority detector
}
```

| Env var(s) | Agent |
|---|---|
| `CLAUDECODE`, `CLAUDE_CODE` | Claude Code |
| `CURSOR_AGENT` | Cursor |
| `CODEX`, `OPENAI_CODEX` | OpenAI Codex |
| `AIDER` | Aider |
| `CLINE` | Cline |
| `WINDSURF_AGENT` | Windsurf |
| `GITHUB_COPILOT` | GitHub Copilot |
| `AMAZON_Q`, `AWS_Q_DEVELOPER` | Amazon Q Developer |
| `GEMINI_CODE_ASSIST` | Gemini Code Assist |
| `SRC_CODY` | Sourcegraph Cody |
| `PI_CODING_AGENT` | Pi |
| `AGENT` | Generic (explicit opt-in) |
| **idsec overrides** | |
| `IDSEC_AGENT_MODE` (`1/true/on` → force on, `0/false/off` → force off) | idsec explicit control via env |
| `IDSEC_FORCE_AGENT_MODE=1` | idsec hard force-on (alias, matches `pup`'s `FORCE_AGENT_MODE`) |
| `--agent` / `--no-agent` | idsec explicit control via flag |

A detector counts as "set" when the env var is present **and non-empty**
(matching how `pup` and idsec treat env presence, and avoiding surprises from
`AGENT=`).

### 3.3 Precedence

Consistent with the README's documented `flags > env > config > default` order,
resolved **once** inside `CommonActionsExecution`:

```
1. Explicit flag         --agent  → ON        --no-agent → OFF   (highest)
2. idsec env override     IDSEC_AGENT_MODE (parse bool),  or IDSEC_FORCE_AGENT_MODE=1 → ON
3. Auto-detection         any knownAgents env var set → ON  (records DetectedAgent)
4. Default                human mode (OFF)
```

- `--agent` and `--no-agent` are mutually exclusive; if both are supplied, that
  is a startup usage error.
- `IDSEC_AGENT_MODE` can *disable* even under auto-detect (`IDSEC_AGENT_MODE=0`),
  giving env-level parity with `--no-agent`. `IDSEC_FORCE_AGENT_MODE` is
  force-on only (kept for `pup` familiarity).
- Because the config file (`config.yaml`) sets `IDSEC_*` env vars during
  `LoadConfigFile`, a user can persist `IDSEC_AGENT_MODE: true` there and it
  participates at the env layer automatically — no extra code.

```go
// pkg/agentmode/agentmode.go (illustrative)
package agentmode

import (
    "os"
    "strconv"
)

type Resolution struct {
    Enabled   bool
    Source    string // "flag", "env", "auto-detect", "default"
    AgentName string // populated when Source == "auto-detect"
}

// Resolve computes agent-mode state. flagAgent/flagNoAgent come from the parsed
// cobra flags.
func Resolve(flagAgent, flagNoAgent bool) Resolution {
    switch {
    case flagNoAgent:
        return Resolution{Enabled: false, Source: "flag"}
    case flagAgent:
        return Resolution{Enabled: true, Source: "flag"}
    }
    if v := os.Getenv("IDSEC_AGENT_MODE"); v != "" {
        if on, err := strconv.ParseBool(v); err == nil {
            return Resolution{Enabled: on, Source: "env"}
        }
    }
    if os.Getenv("IDSEC_FORCE_AGENT_MODE") == "1" {
        return Resolution{Enabled: true, Source: "env"}
    }
    if name := detect(); name != "" {
        return Resolution{Enabled: true, Source: "auto-detect", AgentName: name}
    }
    return Resolution{Enabled: false, Source: "default"}
}

func detect() string {
    for _, a := range knownAgents {
        if os.Getenv(a.EnvVar) != "" {
            return a.Name
        }
    }
    return ""
}
```

State is stored in a package-level bool (mirroring how SDK `config` stores
`isInteractive`), set once and read everywhere:

```go
var (
    enabled       bool
    detectedAgent string
)

func Enable(agent string)   { enabled = true; detectedAgent = agent }
func Disable()              { enabled = false; detectedAgent = "" }
func IsEnabled() bool       { return enabled }
func DetectedAgent() string { return detectedAgent }
```

### 3.4 Wiring into `CommonActionsExecution`

Add the flags in `CommonActionsConfiguration` and resolve in
`CommonActionsExecution` (both in `pkg/actions/idsec_action.go`). Resolution must
run **before** the upgrade-nag block so the nag can be suppressed.

```go
// CommonActionsConfiguration (add)
cmd.PersistentFlags().Bool("agent", false, "Force agent mode: structured JSON output, non-interactive, machine-friendly")
cmd.PersistentFlags().Bool("no-agent", false, "Force human mode even when an AI agent is auto-detected")

// CommonActionsExecution (near the top, after the default toggles)
flagAgent, _   := cmd.Flags().GetBool("agent")
flagNoAgent, _ := cmd.Flags().GetBool("no-agent")
res := agentmode.Resolve(flagAgent, flagNoAgent)
if res.Enabled {
    agentmode.Enable(res.AgentName)
    // Flip existing SDK toggles so all currently-gated human noise is suppressed
    // while structured stdout still flows (see §4).
    config.DisableColor()
    config.DisableInteractive()
    config.AllowOutput()      // so args.Print* still writes the JSON envelope to stdout
} else {
    agentmode.Disable()
}
```

Why set `AllowOutput()` **and** `DisableInteractive()`? The `args.Print*` helpers
gate on `IsInteractive() || IsAllowingOutput()`. Disabling interactive (kills
prompts) while allowing output (keeps the JSON envelope on stdout) is exactly the
combination agent mode needs. Color is disabled so envelopes are never
ANSI-polluted.

## 4. Behavioral Spec (behavior → human vs agent → file/function)

| # | Behavior | Human (today, unchanged) | Agent mode | File / function to change |
|---|---|---|---|---|
| 1 | Success payload (struct/map/slice/channel) | Pretty `json.MarshalIndent` via `PrintSuccess` | Wrapped in envelope: `{status, data, count, truncated, ...}` | `pkg/actions/idsec_service_exec_action.go` → `serializeAndPrintOutput`, `pageItems`, `writeJSONArray` |
| 2 | Generic success (`"X finished successfully"`) | Plain green line | `{status:"success", data:null, message:"..."}` envelope | `serializeAndPrintOutput` (tail branch) |
| 3 | Action/runtime error | `args.PrintFailure(...)` to stdout | `{status:"error", error:{code,message,details}, hints:[...]}` envelope to **stdout** (data channel) | `pkg/actions/idsec_exec_action.go` → `runExecAction`; envelope built in `agentmode`/`args` helper |
| 4 | Top-level CLI error (bad command/flag) | `fmt.Println(err)` to stdout + help | Structured error envelope to stdout; **no** prose help dump | `cmd/idsec/idsec.go` → `handleCommandExecution`, `setupDefaultRouting`, `validateCommandPathBeforeExecution` |
| 5 | Interactive prompt (`GetArg` etc.) | `survey.AskOne` blocks for input | **Never prompt.** Return fail-fast error naming the missing flag | `pkg/common/args/idsec_args_formatter.go` → all four `Get*Arg` |
| 6 | `login`/`configure` missing creds | Prompts interactively | Structured error: which `--<auth>-secret`/profile is required | `pkg/actions/idsec_login_action.go`, `idsec_configure_action.go` (already branch on `IsInteractive()`; verify all paths) |
| 7 | Upgrade nag | Yellow warning (12h cached) | Suppressed | `pkg/actions/idsec_action.go` → `CommonActionsExecution` (already gated on `IsInteractive()`; agent mode disables interactive → auto-suppressed) |
| 8 | Color / spinners | ANSI colors | Disabled | SDK `config.DisableColor()` set in `CommonActionsExecution` (existing `IsColoring()` gate covers `args.ColorText`) |
| 9 | "Not all authenticators logged in" | Printed (gated on `IsInteractive()`) | Suppressed from stdout; may appear as a `warnings[]` entry in the envelope | `pkg/actions/idsec_exec_action.go` → `runExecAction` |
| 10 | `--help` | Cobra prose usage + services list | Prose still available; **preferred path is `idsec schema`** (JSON). Optionally, in agent mode `--help` emits a pointer envelope suggesting `idsec schema` | `cmd/idsec/idsec.go` → `setupCustomHelp`; new `idsec schema` command |
| 11 | Diagnostics / logs | stderr already (file logger) | Ensure all non-data writes go to **stderr** | audit `fmt.Println`/`Print*` call sites (see §4.3) |
| 12 | Interactive pager (`--page-size`) | Pages on TTY | Non-TTY path already writes JSON array; agent mode forces the non-interactive path regardless of TTY | `pkg/actions/idsec_service_exec_action.go` → `pageItems` |
| 13 | Confirmation prompts (`GetBoolArg` "Yes/No") | Prompts | Auto-approve to the safe default (or the flag value if provided); never block | `pkg/common/args/idsec_args_formatter.go` → `GetBoolArg` |

### 4.1 Non-interactive / auto-approve (behavior #5, #13)

The four `Get*Arg` helpers are the only blocking surfaces. Add an agent-mode
guard at the top of each:

```go
// pkg/common/args/idsec_args_formatter.go (illustrative, GetArg)
func GetArg(cmd *cobra.Command, key, prompt, existingVal string, hidden, prioritizeExistingVal, emptyValueAllowed bool) (string, error) {
    val := valueFromFlags(cmd, key, existingVal, prioritizeExistingVal)
    if agentmode.IsEnabled() {
        if val == "" && !emptyValueAllowed {
            return "", agentmode.MissingInputError(key) // fail fast, names the flag
        }
        return val, nil // use flag/existing value, never prompt
    }
    // ... existing survey.AskOne loop unchanged ...
}
```

- `GetBoolArg`: in agent mode, return the resolved flag/existing value (default
  `false` / the `Default` option) without prompting — this is the "auto-approve
  confirmations" behavior. Because idsec confirmations default to the
  non-destructive choice, auto-answering the default is safe; destructive actions
  still require an explicit flag.
- `GetSwitchArg`/`GetCheckboxArgs`: in agent mode, return the flag/existing
  selection; if empty and a value is mandatory, `MissingInputError`.
- `MissingInputError(flag)` returns a typed error that the envelope layer renders
  as `error.code = "missing_required_input"` with a `hints` entry like
  `"provide --<flag> because agent mode does not prompt"`.

This also fixes the closed-stdin hang for `login`/`configure`: those already
branch on `config.IsInteractive()` (which agent mode turns off), and the
remaining interactive helpers now fail fast instead of blocking.

### 4.2 Structured output interception (behavior #1, #2)

`serializeAndPrintOutput` is the single choke point for exec results. Wrap its
output in agent mode:

```go
// illustrative shape
func (s *IdsecServiceExecAction) serializeAndPrintOutput(result []reflect.Value, actionName string, pageSize int) {
    if agentmode.IsEnabled() {
        env := s.buildEnvelope(result, actionName) // status/data/count/truncated/warnings
        args.PrintSuccess(env.JSON())              // single JSON object to stdout
        return
    }
    // ... existing human rendering unchanged ...
}
```

- For list-shaped results, populate `count` (items rendered) and `truncated`
  (true if a page limit or a broken pipe cut the stream short). Agent mode
  ignores interactive paging (`pageItems` already has a non-TTY JSON-array path —
  reuse it inside `data`, or stream `data` as an array and set `count`).
- Preserve the exact serialized value shape inside `data` so existing consumers
  that already parse `idsec ...` JSON get the *same* objects, just nested under
  `data`.

### 4.3 stdout/stderr discipline (behavior #4, #11) — call out as a fix

Today `cmd/idsec/idsec.go` prints errors with `fmt.Println(err)` (→ **stdout**)
in `handleCommandExecution`, `setupDefaultRouting`, and the reroute path. This is
a pre-existing correctness smell for scripting and is *incompatible* with agent
mode (an error would corrupt the stdout JSON stream if we're not careful).

**Fix (applies to both modes, low-risk):**

- Human mode: route error text to `os.Stderr` (`fmt.Fprintln(os.Stderr, err)`).
  This is a behavior change only in *stream*, not content; call it out in the PR
  and README.
- Agent mode: emit the **error envelope to stdout** (agents read the structured
  result from stdout; a nonzero exit code still signals failure) and keep
  human-readable diagnostics on stderr. Rationale: for a machine consumer the
  error *is* the result payload, so it belongs on the data channel as JSON; the
  process exit code remains the out-of-band failure signal.

`args.Print*` continue to write to stdout; in agent mode only the enveloped
success/error goes through them, and incidental human warnings are either
suppressed (interactive-gated) or redirected to the `warnings[]` field.

## 5. Config Surface Decision (SDK vs CLI) + Rationale

**Decision: keep agent-mode state in a new CLI-local `pkg/agentmode` package. Do
NOT add an agent concept to the SDK `config` package.**

Rationale:

- The SDK `config` package is **shared with the Terraform provider**
  (`SetIdsecToolInUse`, `IsInteractive`, etc.). "Agent mode" is a CLI-presentation
  concept with no meaning for a Terraform provider; adding
  `EnableAgentMode()`/`IsAgentMode()` there would leak a CLI-only idea into a
  shared library and force a coordinated SDK release for a CLI feature.
- Everything agent mode needs from the SDK **already exists** as generic toggles:
  `DisableColor`, `DisableInteractive`, `AllowOutput`. Agent mode is expressible
  as "set these three, plus a CLI-local boolean that switches on the envelope."
- The CLI's output/exec code (`pkg/common/args`, `pkg/actions`) is where the
  envelope logic lives, and those packages can freely import a sibling CLI
  package (`pkg/agentmode`) with no import cycle.
- Detection env vars are CLI-specific and version with the CLI release cadence,
  which is faster and independent of SDK releases.

Interaction with existing CLI config: `pkg/config/config_file.go` already turns
`IDSEC_*` YAML keys into env vars before Cobra parses anything, so
`IDSEC_AGENT_MODE`/`IDSEC_FORCE_AGENT_MODE` set in `config.yaml` participate at
the env layer for free. No change needed to `config_file.go` except a doc note.

Precedence summary (extends the README table):

| Priority | Source |
|---|---|
| 1 | `--agent` / `--no-agent` flag |
| 2 | `IDSEC_AGENT_MODE` / `IDSEC_FORCE_AGENT_MODE` env (settable via `config.yaml`) |
| 3 | Auto-detected agent env var (`CURSOR_AGENT`, `CLAUDECODE`, …) |
| 4 | Default: human mode |

## 6. Response / Error Envelope Schema

A single envelope type serves success, generic-message, and error cases (mirrors
`pup`'s metadata envelope: count, truncation, warnings, error, hints). Defined in
`pkg/agentmode` (or a small `pkg/agentmode/envelope.go`), with `json` tags
following idsec's snake_case convention.

```go
// pkg/agentmode/envelope.go (illustrative)
type Envelope struct {
    Status    string         `json:"status"`              // "success" | "error"
    Data      any            `json:"data,omitempty"`      // the raw result value(s)
    Message   string         `json:"message,omitempty"`   // generic success text
    Error     *EnvelopeError `json:"error,omitempty"`
    Count     *int           `json:"count,omitempty"`     // # items for list results
    Truncated bool           `json:"truncated,omitempty"` // stream cut short (page limit / pipe)
    Warnings  []string       `json:"warnings,omitempty"`  // non-fatal (e.g. partial auth)
    Hints     []string       `json:"hints,omitempty"`     // machine-actionable next steps
    Agent     string         `json:"agent,omitempty"`     // detected agent name (diagnostic)
}

type EnvelopeError struct {
    Code    string `json:"code"`              // e.g. "missing_required_input", "action_failed"
    Message string `json:"message"`
    Details any    `json:"details,omitempty"` // validation errors, field list, etc.
}
```

### JSON examples

Success (list):

```json
{
  "status": "success",
  "data": [
    { "safeName": "prod-db", "description": "Production DB creds" },
    { "safeName": "prod-web", "description": "Web tier creds" }
  ],
  "count": 2,
  "truncated": false,
  "agent": "cursor"
}
```

Generic success (no return payload):

```json
{
  "status": "success",
  "data": null,
  "message": "Delete Safe finished successfully",
  "agent": "claude-code"
}
```

Error (missing required input — the anti-hang case):

```json
{
  "status": "error",
  "error": {
    "code": "missing_required_input",
    "message": "required flag --isp-secret was not provided",
    "details": { "missing_flags": ["isp-secret"] }
  },
  "hints": [
    "agent mode never prompts; pass --isp-secret or set IDSEC_SECRET",
    "run `idsec schema` to list required flags for this action"
  ],
  "agent": "cursor"
}
```

Error (action failure with partial-auth warning):

```json
{
  "status": "error",
  "error": { "code": "action_failed", "message": "Failed to execute action: 403 Forbidden" },
  "warnings": ["Not all authenticators are logged in; some functionality is disabled"],
  "agent": "codex"
}
```

## 7. `idsec schema` — Machine-Readable Discovery

**Decision: add a dedicated `idsec schema` command rather than overriding
`--help` to emit JSON.** Rationale: it matches `pup agent schema`, keeps `--help`
prose stable for humans, is independently testable, and is explicitly invokable
regardless of agent detection (agents can call `idsec schema` deterministically).
In agent mode, the custom help function may additionally emit a one-line envelope
hint pointing at `idsec schema`.

`idsec schema` walks `registry.TopLevelCLIActions()` and, for each action's
`Schemas` map, reflects over the schema struct's fields (reusing the same
tag-reading logic already in `idsec_service_exec_action.go`) to serialize:

- services → resources/subactions (recursively via `Subactions`)
- per action: name, aliases, description, deprecation
- per flag: `flag` name, `desc`, `default`, `required` (from
  `validate:"required"`), `choices` (split on `,`), and inferred type

```jsonc
// idsec schema  (shape, abbreviated)
{
  "status": "success",
  "data": {
    "services": [
      {
        "name": "pcloud", "aliases": ["privilegecloud", "pc"],
        "description": "CyberArk Privilege Cloud ...",
        "resources": [
          {
            "name": "safes",
            "actions": [
              {
                "name": "add-safe",
                "flags": [
                  { "name": "safe-name", "type": "string", "required": true, "description": "Safe name" },
                  { "name": "retention-days", "type": "int", "required": false, "default": "7" }
                ]
              }
            ]
          }
        ]
      }
    ]
  }
}
```

Implementation notes:

- Factor the field→flag-metadata extraction out of
  `defineServiceExecAction`/`fillRemainingSchema` into a small reusable
  `schemaFlags(schema any) []FlagMeta` helper so both command-building and
  `idsec schema` share one source of truth (avoids drift).
- `idsec schema` is always JSON (like `version --silent`), independent of agent
  mode; it never prompts and never authenticates.
- Optional `idsec schema <service> [<resource>]` scoping to limit output size for
  large registries.

## 8. Backward Compatibility & Risks

### Guarantees

- Default path (no flag, no detector) leaves every existing gate
  (`IsColoring/IsInteractive/IsAllowingOutput`) at today's values → **identical
  human output**.
- The only *unconditional* change is stdout→stderr for top-level error text
  (§4.3). This is a deliberate, documented fix; content is unchanged, only the
  stream differs. If even that is deemed risky, gate it behind agent mode only in
  Phase 1 and roll the human-mode stderr fix separately.

### Risks & mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| **Auto-detect fires in the dev's own shell.** Running `idsec` inside a Cursor/Claude Code terminal (which sets e.g. `CURSOR_AGENT`) would silently give agent mode. | Confusing JSON-only output for a human. | `--no-agent` escape hatch; `IDSEC_AGENT_MODE=0` persistent opt-out in `config.yaml`; the envelope includes `"agent": "<name>"` so it's obvious *why* mode flipped. Document prominently. |
| **CI sets `AGENT`** (generic) unrelated to AI agents. | CI scripts parsing prose break. | The generic `AGENT` detector is lowest priority and documented as opt-in; teams that don't want it set `IDSEC_AGENT_MODE=0`. Consider making the generic `AGENT` detector opt-in via a build/README note if it proves noisy. |
| **A script relied on error text on stdout.** | Broken parsing. | Documented in README/CHANGELOG; nonzero exit code unchanged. |
| **New envelope nesting** (`data:`) for agent consumers. | N/A for humans; agents are new consumers so no back-compat surface. | Envelope is only emitted in agent mode; version it implicitly via `status`. |
| **Import cycle** if `agentmode` imported `args`. | Build break. | `agentmode` stays a leaf (only `os`, maybe SDK `common` logger). `args`/`actions` import `agentmode`, never the reverse. |
| **Global mutable state** in tests. | Flaky tests. | Provide `agentmode.Disable()` and save/restore in tests, exactly like the version test saves/restores `config.IsInteractive()`. Detection reads env, so tests use `t.Setenv`. |

## 9. Phased Implementation Plan (ordered, file-level)

### Phase 1 — Flag, detection, config state (foundation)

- **New** `pkg/agentmode/agentmode.go` — state (`Enable/Disable/IsEnabled/DetectedAgent`).
- **New** `pkg/agentmode/detect.go` — `knownAgents` table + `detect()`.
- **New** `pkg/agentmode/resolve.go` — `Resolve(flagAgent, flagNoAgent)` precedence.
- **Edit** `pkg/actions/idsec_action.go` — add `--agent`/`--no-agent` in
  `CommonActionsConfiguration`; resolve + flip SDK toggles in
  `CommonActionsExecution` (before the upgrade-nag block).
- Effort: **~0.5–1 day.** Pure state; no output change yet.

### Phase 2 — Non-interactive / auto-approve + fail-fast errors

- **New** `pkg/agentmode/envelope.go` — `Envelope`, `EnvelopeError`,
  `MissingInputError`, `JSON()`.
- **Edit** `pkg/common/args/idsec_args_formatter.go` — agent-mode guards in
  `GetArg/GetBoolArg/GetSwitchArg/GetCheckboxArgs` (never call `survey`; fail fast
  or use flag value).
- **Edit** `pkg/actions/idsec_login_action.go`, `idsec_configure_action.go` —
  verify every interactive branch is `IsInteractive()`-gated (mostly already
  true); add structured "required flag" errors where they currently prompt.
- Effort: **~1–1.5 days.**

### Phase 3 — JSON envelope for exec output + error path + stdout/stderr fix

- **Edit** `pkg/actions/idsec_service_exec_action.go` — wrap
  `serializeAndPrintOutput` (and the generic-success tail) in the envelope when
  `agentmode.IsEnabled()`; set `count`/`truncated`; force non-interactive array
  path in `pageItems`.
- **Edit** `pkg/actions/idsec_exec_action.go` — `runExecAction` failure path
  emits error envelope; "not all authenticators" → `warnings[]`.
- **Edit** `cmd/idsec/idsec.go` — `handleCommandExecution`/`setupDefaultRouting`/
  reroute: errors to `os.Stderr` (human) / error envelope to stdout (agent);
  suppress prose help dump in agent mode.
- Effort: **~1.5–2 days.**

### Phase 4 — `idsec schema` command + JSON help hint

- **Refactor** extract `schemaFlags(schema any) []FlagMeta` from
  `idsec_service_exec_action.go`.
- **New** `pkg/actions/idsec_schema_action.go` — `IdsecSchemaAction` walking
  `registry.TopLevelCLIActions()`; register in `cmd/idsec/idsec.go`
  `registerActions`.
- **Edit** `cmd/idsec/idsec.go` `setupCustomHelp` — in agent mode, append/emit a
  one-line hint pointing to `idsec schema`.
- Effort: **~1.5 days.**

### Phase 5 — Docs + tests

- README "Agent Mode" section + detection table + precedence update (§11).
- Tests per §10.
- CHANGELOG / version bump per repo convention.
- Effort: **~1–1.5 days.**

Total rough effort: **~6–8 engineering days**, shippable incrementally (Phases
1–2 are safe no-ops for humans; Phase 3 carries the only cross-mode change).

## 10. Testing Strategy

Follow idsec conventions: table-driven, `t.Parallel()` where no global state is
mutated, test-case names `success_* / error_* / edge_case_*`, save/restore global
toggles (as the version test already does for `config.IsInteractive()`),
`t.Setenv` for detection.

- **`pkg/agentmode/detect_test.go`** — table-driven detection: each known env var
  → detected; empty value → not detected; ordering/first-match.
  - `success_detects_cursor_agent`, `success_detects_claudecode`,
    `edge_case_empty_agent_var_not_detected`, `success_generic_agent_lowest_priority`.
- **`pkg/agentmode/resolve_test.go`** — precedence matrix: flag beats env beats
  detect beats default; `--no-agent` overrides detection; `IDSEC_AGENT_MODE=0`
  disables under detection; `IDSEC_FORCE_AGENT_MODE=1` forces on.
  - `success_flag_agent_wins_over_no_env`, `edge_case_both_flags`,
    `success_env_override_disables_autodetect`.
- **`pkg/agentmode/envelope_test.go`** — serialization: success/list (`count`,
  `truncated`), generic message, error with `hints`/`details`; stable field
  ordering/omitempty.
- **`pkg/common/args/idsec_args_formatter_test.go`** — with agent mode on:
  `Get*Arg` never call `survey` (stub/asserts), return flag value, and
  `MissingInputError` when required+empty; with agent mode off, existing behavior
  preserved. Assert no read on closed stdin.
- **`pkg/actions/idsec_service_exec_action_test.go`** (extend) —
  `serializeAndPrintOutput` in agent mode wraps envelope; non-TTY + agent → JSON
  array under `data`; generic-success envelope. Reuse `IsStdoutTTY` override var.
- **`pkg/actions/idsec_schema_action_test.go`** — `idsec schema` output includes
  a known service/resource/action with correct `required`/`default`/`choices`
  derived from struct tags; valid JSON; deterministic.
- **`cmd`-level / integration** (a `scripts/` smoke test or Go test invoking the
  built binary):
  - `idsec pcloud safes list-safes --agent` → stdout parses as one JSON envelope
    with `status`.
  - Prompt-heavy command under `--agent` with **closed stdin** returns promptly
    (nonzero exit, error envelope) — asserts no hang (wrap in a timeout).
  - `idsec boguscmd --agent` → structured error envelope on stdout, no prose help.
  - Human mode unchanged: golden-output test comparing `--no-agent` (or unset) to
    current output.

## 11. Docs Plan (README)

Add an **"Agent Mode"** section (modeled on `pup`'s), placed near the
"Configuration File / Precedence" section, covering:

1. **What it is** — one paragraph: structured JSON, never prompts, machine
   discovery.
2. **Activation** — `--agent`/`--no-agent`, `IDSEC_AGENT_MODE`,
   `IDSEC_FORCE_AGENT_MODE`, and auto-detection; the **detection table** from §3.2.
3. **Precedence** — extend the existing precedence table with the agent-mode row
   set (§5), emphasizing `--no-agent` / `IDSEC_AGENT_MODE=0` as the escape hatch
   (call out the "running inside Cursor/Claude Code sets the env var" gotcha
   explicitly).
4. **Output contract** — the envelope schema (§6) with the three JSON examples;
   note stdout=data, stderr=diagnostics, exit code = success/failure.
5. **Discovery** — document `idsec schema` (and optional scoped form), with a
   short example.
6. **Behavior differences** — a condensed version of the §4 table (human vs
   agent) so integrators know what changes.
7. **CHANGELOG** entry + version bump per repo convention.

## 12. Open Questions

1. **Generic `AGENT` detector** — include by default (matches `pup`) or make it
   opt-in given CI false-positives? Recommendation: include but document loudly;
   revisit if noisy.
2. **`data` nesting vs top-level** — should agent success wrap results under
   `data`, or keep the current top-level JSON and only add sibling metadata?
   Recommendation: nest under `data` for a uniform envelope (success and error
   share one shape), accepting that agents parse `.data`.
3. **Human-mode stdout→stderr error fix** — ship unconditionally (cleaner, but a
   stream-level behavior change) or gate to agent mode only in Phase 1?
   Recommendation: ship unconditionally with a clear CHANGELOG note; it's the
   correct behavior and low-risk.
4. **Auto-approve semantics for destructive actions** — confirm that all
   destructive operations already require an explicit flag (so auto-answering
   `GetBoolArg`'s default is always safe). Needs a quick audit of destructive
   commands during Phase 2.
5. **Envelope versioning** — do we need an explicit `schema_version` field for
   future-proofing agent consumers? Recommendation: defer; add only if the shape
   changes post-GA.

## Reference

- Datadog `pup` CLI — Agent Mode: <https://docs.datadoghq.com/cli/>
- Datadog `pup` repository: <https://github.com/DataDog/pup>
