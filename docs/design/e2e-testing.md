# Design: End-to-End (E2E) Testing for `idsec-cli-golang`

> Status: Proposal / Design (no code changes yet). All Go snippets, `.txtar`
> scripts, and YAML are illustrative. This document defines the target
> architecture and decisions; it is intentionally not a full implementation.

## 1. Overview & Goals

### Motivation

`idsec` is a Go/Cobra binary with a large amount of *binary-level* behavior that
unit tests cannot exercise: the custom `os.Args` reroute that turns
`idsec pcloud safes list` into `idsec exec pcloud safes list`, the pre-execution
path validation, the custom help/services rendering, config-file precedence,
profile/cache file side effects, exit codes, and stdout/stderr discipline. All
of this lives in `cmd/idsec/idsec.go` and the `pkg/actions/*` command wiring and
is only ever observable when the *compiled binary* runs as a subprocess with a
real argv, environment, working directory, and filesystem.

Today the repo is **unit-only** (table-driven `*_test.go`, `t.Parallel()`,
`success_/error_/edge_case_` case names, shared helpers in
`pkg/actions/testutils/`). There is no test that builds `idsec` and runs it.
Regressions in argv routing, help text, exit codes, or config side effects can
ship undetected.

We want an **E2E test suite** that treats the built `idsec` binary as a black
box — feed it args/env/stdin, assert on exit code, stdout, stderr, and
filesystem side effects — split into a **hermetic tier** that runs on every PR
with no credentials, and a **live tier** that is opt-in and gated behind real
`IDSEC_*` credentials.

### Goals

1. **Test the real binary.** Exercise the compiled artifact end to end (argv →
   exit code + stdout + stderr + files), not Go functions in-process.
2. **Credential-free by default.** The default CI/PR run needs no secrets, no
   network to CyberArk, and is fast and deterministic.
3. **Cover the routing/help/error surface** that unit tests structurally cannot
   (`os.Args` mutation, reroute-to-exec, path pre-validation, custom help).
4. **House-consistent.** Reuse the repo's conventions: copyright/style,
   `success_/error_/edge_case_` case names, table-driven Go, and the
   `{{namespace}}` / `($ENV_VAR)` interpolation spirit of the team's Terraform
   `test_cases.yaml` acceptance convention where it adds value.
5. **Deterministic & isolated.** Every test gets its own `HOME`/config dir, temp
   CWD, and scoped env; output is normalized before comparison so version,
   timestamps, durations, and temp paths never cause flakes.
6. **Live tests never run by accident.** They are behind a build tag **and** an
   env gate, run nightly/manual only.

### Non-goals

- Replacing or reducing unit-test coverage. E2E complements units; business
  logic stays unit-tested.
- Testing the CyberArk backend itself, or SDK service correctness (the SDK repo
  owns its own `tests/e2e/`). We test the *CLI's* behavior.
- Contract/mock testing of every service action's HTTP payloads. Hermetic HTTP
  faking is applied where the CLI surface genuinely needs a backend and where
  the SDK makes it feasible (see §7), not as a universal mock of every endpoint.
- GUI/interactive `survey` prompt flows beyond asserting that non-interactive
  invocations (closed stdin) fail fast rather than hang.

### In-scope vs out-of-scope (quick reference)

| In scope (E2E) | Out of scope (E2E) |
|---|---|
| `--help`, `--version`, `version --silent` | Unit-level function behavior |
| Arg/flag parsing, unknown-command errors, exit codes | SDK service HTTP correctness |
| Exec reroute (`idsec <svc> …` → `exec <svc> …`) | Real MFA/interactive login UX |
| `configure` / `profiles` / `cache` local file ops | Backend data correctness |
| Output formats (`--json`/raw), stdout/stderr split | Load/perf testing |
| Config-file precedence + `--config` | Keyring OS-secure-store internals |
| Docker image smoke (`ENTRYPOINT`) | Windows-only GUI concerns |
| Live: real `login` + a few read-only actions (gated) | Destructive live mutations by default |

## 2. Current-State Analysis (verified in-repo)

| Concern | Where it lives today | Relevance to E2E |
|---|---|---|
| Entry + argv reroute | `cmd/idsec/idsec.go` → `main`, `setupDefaultRouting`, `routeToExec`, `rerouteHelpToExecIfNeeded`, `validateCommandPathBeforeExecution`, `handleCommandExecution` | Mutates `os.Args`, prepends `exec`, re-executes root. Only observable via subprocess. **Prime E2E target.** |
| Error/exit behavior | `handleCommandExecution` | Errors printed via `fmt.Println(err)` (→ **stdout**) then `os.Exit(1)`. E2E must assert exit code + which stream. (Note: agent-mode design proposes moving these to stderr — E2E goldens should be authored to tolerate/track that.) |
| Custom help + services list | `setupCustomHelp` | Appends "Available services" by walking the `exec` subcommands. E2E asserts help contains services, normalized. |
| Command registration | `registerActions` | `profiles`, `cache`, `configure`, `login`, `exec`, `upgrade`, `version`, plus k8s `kubectl-login`/`generate-kubeconfig`. Fixed top-level surface to enumerate. |
| Dynamic service tree | `pkg/registry/init.go` (`RegisterCLIAction`) | Services: `sia`(`dpa`), `cmgr`(`cm`,`connectormanager`), `pcloud`(`pc`,`privilegecloud`), `identity`(`id`,`idaptive`), `policy`(`acp`,`accesspolicies`), `sca`(`asca`,`accesssca`), `sechub`(`sh`,`secretshub`), `sm`(`sessionmonitoring`). Aliases are E2E routing cases. |
| Feature gating | `pkg/registry.releasedFeaturesOnly` ldflag (build.sh / goreleaser / Dockerfile) | The visible action set depends on this build flag. E2E must pin it so goldens are stable (recommend `RELEASED_FEATURES_ONLY=false` for the dev E2E build, matching PR builds). |
| CLI config file | `pkg/config/config_file.go` | Loads `~/.idsec/config.yaml` early (before Cobra), sets `IDSEC_*` env vars if unset. Honors `--config`, `IDSEC_CONFIG_FILE`. Only `IDSEC_*` + standard proxy keys accepted; others warn. **Rich hermetic surface** (precedence, warnings). |
| Env surface | `docs/config/environment.md` | `IDSEC_PROFILE`, `IDSEC_LOG_LEVEL`, `IDSEC_DISABLE_CERTIFICATE_VERIFICATION`, `IDSEC_DISABLE_TELEMETRY_COLLECTION`, `IDSEC_BASIC_KEYRING`, `IDSEC_KEYRING_FOLDER`, `IDSEC_SUPPRESS_UPGRADE_CHECK`, proxy vars. Docker sets `IDSEC_PROFILES_FOLDER`, `IDSEC_KEYRING_FOLDER`. |
| Upgrade check | `pkg/common/idsec_upgrader.go` | Reads `GITHUB_URL` env → sets `config.EnterpriseBaseURL = https://<GITHUB_URL>/api/v3/`. **This is the one clean HTTP override we can point at `httptest`** for a hermetic upgrade test. Also `IDSEC_SUPPRESS_UPGRADE_CHECK=true` to silence the nag for stable goldens. |
| Backend URL resolution | SDK `pkg/common/isp/idsec_isp_service_client.go` → `resolveServiceURL` | Service base URL is derived from JWT claims (`subdomain`, `platform_domain`) and the `DEPLOY_ENV`-selected root domain (`pkg/models/common/idsec_env.go`). **There is no first-class `--base-url`/`IDSEC_API_BASE_URL` override.** This constrains hermetic HTTP faking of *service* calls (see §7). |
| Build | `scripts/build.sh` (`make all`), `scripts/build_goreleaser.sh` (`make goreleaser-build`), `.goreleaser.yaml` | Cross-compiles darwin/linux/windows (+ freebsd/arm in goreleaser). ldflags stamp `version`, `buildDate`, `gitCommit`, etc. Binaries land in `bin/` (build.sh) or `dist/` (goreleaser). |
| Docker | `docker/Dockerfile` | Multi-stage, distroless-ish alpine, non-root `idsec-cli`, `ENTRYPOINT ["idsec"]`, `CMD ["--help"]`, sets profile/keyring folders. Good target for a container smoke test. |
| Unit tests | `pkg/**/**_test.go`, `pkg/actions/testutils/` | `make unit-test` = `go test … | grep -v -E '(examples|testutil)'`. `testutils` has `CaptureOutput`, `SetEnvVar`, `MockProfileLoader`, profile/command builders. E2E should live *outside* this filter path. |
| CI | `Jenkinsfile` | Stages: validate-prepare, lint, docker+snyk, unit-test-all, build, release. `nimbus-go-agent`. **New E2E stage slots after unit tests.** |
| SDK prior art | SDK `tests/e2e/` (+ `framework/`, `tools/gene2e`) | SDK's E2E is **in-process SDK calls** gated by `//go:build e2e` and `IDSEC_E2E_*` env (`IDSEC_E2E_SKIP`, `IDSEC_E2E_ISP_*`, `IDSEC_E2E_AUTH_EXPECT`), with a provider registry and `MustLoadConfig(t)` skip-on-missing pattern. We mirror its **tagging, env-gating, and skip semantics**, but our subject is the *binary*, not the SDK. |

**Key takeaways for the design:**

1. The most valuable, currently-untested surface (argv reroute, path
   validation, help, exit codes, config side effects) is **entirely hermetic** —
   no backend needed. This is where E2E pays off immediately.
2. The **only** clean HTTP override the CLI exposes today is `GITHUB_URL` for the
   upgrade check. Faking *service* backends at the HTTP layer is not currently
   supported by a base-URL override; the URL is computed from JWT claims +
   `DEPLOY_ENV`. So hermetic HTTP faking is scoped to `upgrade` (and any future
   base-URL override), and everything else in the hermetic tier is designed to
   need **no** network. Real service calls belong in the **live tier**.
3. We should reuse the SDK's `IDSEC_E2E_*` env-gate and `//go:build e2e`
   conventions for a familiar developer experience across the two repos.

## 3. Two-Tier Model

E2E is split into two clearly separated tiers so PRs stay fast, deterministic,
and credential-free while real integration coverage still exists.

### Tier 1 — Hermetic / offline E2E (default; runs on every PR)

- **Guarantee:** no CyberArk network, no credentials, no reliance on machine
  state. Fully deterministic and fast (target: whole hermetic suite < ~30s).
- **Build tag:** `//go:build e2e` (see §6/§7 — hermetic tests are the default
  `e2e` set; they must not require creds).
- **Covers:**
  - `--help` (root + per-command), `--version`, `version --silent`.
  - Arg/flag parsing, unknown command/flag → correct message + **exit code 1**.
  - Exec reroute: `idsec pcloud …` behaves like `idsec exec pcloud …`; aliases
    (`pc`, `dpa`, `acp`, …) route; `--help` reroute for service paths.
  - Pre-execution path validation (`unknown command "x" for "idsec exec …"`).
  - `configure` / `profiles` / `cache` local file operations against a temp
    `HOME`/config dir (create, list, show, delete, clear).
  - Config-file precedence: `--config`, `IDSEC_CONFIG_FILE`, `~/.idsec/config.yaml`;
    env-over-config; ignored-key warnings.
  - Output discipline: which stream (stdout vs stderr), exit codes, `--json`/raw
    shapes where a command can render without a backend.
  - `upgrade` behavior with a local `httptest` server via `GITHUB_URL` (the one
    supported HTTP override), plus `IDSEC_SUPPRESS_UPGRADE_CHECK` behavior.
- **Backend:** none, except the `httptest`-backed upgrade case. Commands that
  *require* a live backend are **not** in this tier.

### Tier 2 — Live / integration E2E (opt-in; nightly/manual)

- **Guarantee:** never runs by default. Requires **both** a build tag and an env
  gate to execute.
- **Build tag:** `//go:build e2e_live` (a strict superset gate distinct from
  hermetic `e2e`), **and** honors the SDK-style `IDSEC_E2E_*` env with
  skip-on-missing (`framework`-style `MustLoad…(t)` → `t.Skip`).
- **Covers (small, mostly read-only set):**
  - Real `idsec login` against a real tenant (ISP identity) using
    `IDSEC_E2E_*` creds → assert success, profile/token side effects.
  - A handful of **read-only** service actions end to end through the binary,
    e.g. `idsec sca cloud-access list-targets --json`, `idsec pcloud safes list --json`
    → assert exit 0 and JSON parses to the expected shape.
  - Optional: one create→read→delete round-trip on a safe resource, guarded by
    an explicit `IDSEC_E2E_ALLOW_MUTATION=true` and `{{namespace}}`-scoped names
    with best-effort cleanup (mirroring SDK `TrackResource`/cleanup pattern).
- **Credentials:** via `IDSEC_E2E_*` env only, never committed. Reuse the SDK's
  variable names where sensible (`IDSEC_E2E_ISP_USERNAME`, `IDSEC_E2E_ISP_SECRET`,
  `IDSEC_E2E_ISP_IDENTITY_URL`, `IDSEC_E2E_ISP_IDENTITY_TENANT_SUBDOMAIN`,
  `IDSEC_E2E_SKIP`, `IDSEC_E2E_AUTH_EXPECT`).

```
                         go test -tags=e2e ./tests/e2e/...        (PRs, default)
   HERMETIC  ─────────►  no creds · no CyberArk net · deterministic · fast
                         (help/version/routing/config/cache/errors/httptest-upgrade)

                         go test -tags=e2e_live ./tests/e2e/... + IDSEC_E2E_* creds
   LIVE      ─────────►  real login + read-only actions · nightly/manual · skip-if-unset
```

## 4. Framework Choice

### Options evaluated

**(a) `os/exec` + a Go golden-file harness (in-repo helper package).**
Build the binary once, run it with `exec.Command`, capture `stdout`/`stderr`/exit
code, normalize, and compare to `testdata/*.golden` with a `-update` flag. Tests
are ordinary table-driven Go (`success_/error_/edge_case_`), so they slot
directly into the existing convention and tooling (`go test`, coverage-free but
familiar), and Go code can assert on filesystem side effects, spin up `httptest`
servers, and set per-test `HOME`/env trivially.

- **Pros:** zero new deps; maximal control (side effects, `httptest`, stdin,
  timeouts to prove no-hang); identical style to current unit tests; trivial to
  gate by build tag; easy cross-repo mental model with SDK's Go E2E.
- **Cons:** we write a small harness (~150 LOC) and golden-diff plumbing
  ourselves; scenarios are more verbose than a script DSL.

**(b) `rogpeppe/go-internal/testscript` (`.txtar` scripts).**
The de-facto CLI-testing tool in the Go/cobra ecosystem (used by Go itself, goreleaser, etc.). You register the `idsec` binary as a command and write
`.txtar` scripts: run a command, assert `stdout`/`stderr`/exit via
`! `/`cmp`/`stdout <re>`, with a fresh `$WORK` dir and env per script, plus
built-in `env`, `exec`, `cp`, `exists`, `grep` primitives and testdata archives.

- **Pros:** purpose-built for CLIs; extremely concise per-scenario; per-script
  isolation (`$WORK`, `$HOME`) is built in; golden files embed in the archive;
  battle-tested; great fit for the routing/help/exit-code matrix.
- **Cons:** new dependency and a second DSL to learn; asserting rich JSON shapes
  or standing up an `httptest` server mid-script requires custom `Cmds`/`Setup`
  Go glue anyway; less natural for the live tier (auth, cleanup, SDK types);
  normalization of dynamic output needs custom conditions/regex.

**(c) YAML-driven runner mirroring the TF `test_cases.yaml` convention.**
A house-style runner reading `test_cases.yaml` with `steps`, `set_input`,
`expect_error`, `{{namespace}}` and `($ENV_VAR)` interpolation, `success_/error_/edge_case_` names.

- **Pros:** maximal consistency with the team's Terraform acceptance convention;
  non-Go contributors can add cases; declarative and reviewable.
- **Cons:** **we would have to build and maintain the runner** (arg tokenization,
  env/HOME isolation, stream+exit assertions, normalization, `httptest` hooks,
  golden updates) — non-trivial and now a bespoke test framework to own; the TF
  convention is modeled on *provider CRUD steps*, not *process stdout/exit*, so
  the mapping is loose; slower to get value than (a)/(b).

### Recommendation

**Adopt (a) — a thin in-repo `os/exec` golden-file harness in Go — as the
primary framework, and borrow the *ergonomics* of (c) without building a runner:
support `{{namespace}}` and `($ENV_VAR)`-style interpolation inside the harness
and keep `success_/error_/edge_case_` case names.** Revisit `testscript` (b) as
an *optional* add-on later for the pure routing/help matrix if the golden tables
become verbose.

Rationale:

- **Consistency now, lowest cost.** (a) is idiomatic to this repo's existing
  Go table-driven style; contributors need to learn nothing new, and it drops
  straight into `go test` + build tags + the Jenkins stage.
- **Both tiers, one tool.** The same harness serves hermetic *and* live tests
  (the live tier needs Go anyway for auth setup, SDK types, and cleanup).
  A YAML runner or `testscript` would still require Go glue for the live tier,
  so we'd end up maintaining two things.
- **Control where it matters.** Proving "no hang on closed stdin" (a timeout
  around the subprocess), spinning `httptest` for `upgrade`, and asserting
  filesystem side effects are all first-class in Go and awkward in a pure DSL.
- **House-convention fit without a bespoke framework.** We get the *feel* of the
  TF `test_cases.yaml` convention (namespaces, env interpolation, snake_case
  case names) as harness features, without owning a YAML engine. If a
  declarative surface is later desired, the harness can grow a thin YAML loader
  that feeds the same runner — an additive step, not a rewrite.

Trade-off accepted: we hand-write a small harness and golden plumbing instead of
getting `testscript`'s conciseness for free. Given the need for `httptest`,
side-effect assertions, and a shared hermetic+live tool, that control is worth
more than the DSL brevity.

## 5. Directory & File Layout

```
tests/
  e2e/
    README.md                  # how to run, add cases, update goldens, live gate
    harness/                   # the shared Go harness (build-tag-free lib)
      binary.go                # locate/build binary-under-test (once per run)
      run.go                   # Run(t, RunSpec) -> Result{Stdout,Stderr,Exit}
      isolate.go               # temp HOME/config/CWD, scoped env, RRunSpec builder
      golden.go                # golden compare + -update flag
      normalize.go             # output normalization rules (see §9)
      interpolate.go           # {{namespace}} + ($ENV_VAR) expansion
      httpfake.go              # httptest helpers (e.g. fake GitHub for upgrade)
    hermetic/                  # //go:build e2e
      help_test.go             # success_root_help_lists_services, ...
      version_test.go          # success_version_semver, success_version_silent_bare
      routing_test.go          # success_service_reroutes_to_exec, error_unknown_command_exit1
      configure_test.go        # success_configure_writes_config_file, ...
      profiles_test.go         # success_profiles_add_list_delete, ...
      cache_test.go            # success_cache_clear_empties_dir, ...
      config_file_test.go      # success_config_flag_overrides_home, edge_case_unknown_key_warns
      upgrade_test.go          # success_upgrade_check_hits_fake_github (httptest)
      testdata/
        golden/                # *.golden files (normalized expected output)
        config/                # sample config.yaml fixtures
    live/                      # //go:build e2e_live
      login_test.go            # success_login_isp_writes_profile (gated, skip-if-unset)
      sca_list_targets_test.go # success_sca_cloud_access_list_targets_json
      pcloud_safes_test.go     # success_pcloud_safes_list_json
      framework.go             # IDSEC_E2E_* loader + MustLoad(t)/Skip (SDK-style)
    main_test.go               # TestMain: build binary once; honor IDSEC_E2E_SKIP
```

Conventions:

- **Location:** top-level `tests/e2e/` (mirrors the SDK repo's `tests/e2e/`),
  *outside* the `pkg/**` tree so `make unit-test`'s `grep -v -E '(examples|testutil)'`
  filter and coverage remain unaffected, and so the `e2e`/`e2e_live` build tags
  keep these files out of normal `go build`/`go test` and `make lint`
  (`--tests=false` already excludes test files).
- **Package names:** `hermetic`, `live` (or a shared `e2e` package per dir).
  Files end `_test.go`; case (subtest) names are snake_case
  `success_* / error_* / edge_case_*` exactly as unit tests do.
- **Golden files:** `tests/e2e/hermetic/testdata/golden/<test>_<case>.golden`,
  containing **normalized** expected stdout (and a parallel `.stderr.golden`
  where stderr matters). Updated via `go test -tags=e2e ./tests/e2e/hermetic/ -update`.
- **Per-test isolation** (harness-provided, see §9): unique temp `HOME` and
  `IDSEC_CONFIG_FILE`/profiles/keyring dirs, temp CWD, a **scoped env** that
  starts from an allowlist (never the ambient shell), and a per-test
  `{{namespace}}` = short unique id (e.g. `e2e-<test>-<rand>`), so parallel
  tests never collide on files or resource names.

## 6. Binary / Build Strategy

### Obtaining the binary under test

**Decision: build the binary once per `go test` invocation in `TestMain`, via
`go build` with the repo's ldflags stubbed to deterministic values, and hand its
path to every test.** Rebuilding per test is too slow; `go run` per test
recompiles each time and muddies timing.

```go
// tests/e2e/harness/binary.go (illustrative)
// Build once; stamp deterministic version info so goldens are stable.
func Build(t *testing.T) string {
    bin := filepath.Join(t.TempDir(), "idsec"+exeSuffix())
    ld := strings.Join([]string{
        "-X 'github.com/cyberark/idsec-sdk-golang/pkg/config.version=e2e-test'",
        "-X 'github.com/cyberark/idsec-sdk-golang/pkg/config.buildNumber=0'",
        "-X 'github.com/cyberark/idsec-sdk-golang/pkg/config.buildDate=1970-01-01'",
        "-X 'github.com/cyberark/idsec-sdk-golang/pkg/config.gitCommit=0000000'",
        "-X 'github.com/cyberark/idsec-cli-golang/pkg/registry.releasedFeaturesOnly=false'",
    }, " ")
    cmd := exec.Command("go", "build", "-ldflags", ld, "-o", bin, "./cmd/idsec")
    // ... run, fail test on error ...
    return bin
}
```

- **Deterministic version stamping.** Stamping `version=e2e-test` (plus fixed
  build date/commit) means `idsec --version` output is stable across machines,
  so its golden never drifts. (Alternatively, normalize the version out — see
  §9 — but a fixed stamp is simpler and also stabilizes the upgrade-check
  comparison logic.)
- **Pin `releasedFeaturesOnly=false`** so the visible service/action set matches
  PR builds and the help/services golden is stable regardless of release branch.
- **Env override to reuse a prebuilt binary.** Honor `IDSEC_E2E_BINARY=/path/to/idsec`
  to skip building and test a **specific artifact** (e.g. the goreleaser
  snapshot or the release binary) — this lets the same tests validate the exact
  shipped binary in a release pipeline.

### Running against the goreleaser artifact / release binary

For a release-gate run, set `IDSEC_E2E_BINARY` to the goreleaser snapshot
(`make goreleaser-build` → `dist/…/idsec-<os>`) so E2E asserts the *actual*
artifact (correct ldflags, real `--version`) rather than a fresh `go build`. In
that mode, version-sensitive goldens are compared after normalization (§9).

### Docker image smoke test

Add one hermetic-ish container smoke test (opt-in via `IDSEC_E2E_DOCKER=true`,
skipped when Docker is unavailable) that runs the built image and asserts the
`ENTRYPOINT`/`CMD` contract:

```
docker run --rm <image> --version        # exit 0, prints version
docker run --rm <image>                   # default CMD ["--help"], exit 0, lists services
docker run --rm <image> profiles list     # exits cleanly with empty profiles dir
```

This validates the `docker/Dockerfile` wiring (non-root user, `idsec` on PATH,
`IDSEC_PROFILES_FOLDER`/`IDSEC_KEYRING_FOLDER`). It stays out of the default PR
gate (Docker may be unavailable on some agents) and runs where Docker exists.

### Cross-OS considerations

- **Path/config dirs:** never hard-code `/home/...`; derive from the per-test
  temp dir and pass via `HOME` (POSIX) and the profiles/keyring/config env vars.
  On Windows the CLI resolves `os.UserHomeDir()`; the harness sets `USERPROFILE`
  and `HOME` and points `IDSEC_CONFIG_FILE`/`IDSEC_PROFILES_FOLDER`/
  `IDSEC_KEYRING_FOLDER` explicitly to sidestep OS differences.
- **Line endings:** normalize `\r\n` → `\n` before golden comparison (§9) so
  Windows runs match the same goldens.
- **Exe suffix:** harness appends `.exe` on `GOOS=windows`.
- **Primary CI matrix:** Linux `amd64` on `nimbus-go-agent` for the PR gate;
  optionally add macOS/Windows in the nightly matrix. Goldens are authored on
  Linux and must pass on all three purely via normalization.

## 7. Backend Faking Strategy

### The constraint (verified)

The SDK computes each service's base URL inside `resolveServiceURL`
(`pkg/common/isp/idsec_isp_service_client.go`) from the JWT's `subdomain` /
`platform_domain` claims and the `DEPLOY_ENV`-selected `RootDomain`
(`pkg/models/common/idsec_env.go`), producing
`https://<subdomain>-<service>.<platformDomain>`. **There is no
`--base-url`/`IDSEC_API_BASE_URL` override.** So we cannot simply point service
calls at `http://127.0.0.1:<port>` today. This is *the* reason the hermetic tier
avoids real service HTTP and pushes real service calls into the live tier.

### What we *can* fake hermetically today

1. **Upgrade check → `httptest`.** `idsec_upgrader.go` reads `GITHUB_URL` and
   sets `config.EnterpriseBaseURL = https://<GITHUB_URL>/api/v3/`. Point it at a
   local `httptest.Server` and serve a canned releases payload:

```go
// tests/e2e/harness/httpfake.go (illustrative)
srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    // emulate GitHub Enterprise releases API used by the upgrader
    _ = json.NewEncoder(w).Encode(map[string]any{"tag_name": "v99.0.0"})
}))
// GITHUB_URL is host[:port] (upgrader builds https://<GITHUB_URL>/api/v3/)
// For plain-HTTP httptest, pair with IDSEC_DISABLE_CERTIFICATE_VERIFICATION and,
// if needed, a host rewrite; otherwise use httptest.NewTLSServer + trusted cert.
env["GITHUB_URL"] = strings.TrimPrefix(srv.URL, "http://")
```

   This yields real hermetic coverage of the "newer version available" nag and
   the `IDSEC_SUPPRESS_UPGRADE_CHECK=true` suppression path.

2. **Everything that needs no backend.** Help, version, routing, path
   validation, config-file precedence, `configure`/`profiles`/`cache` file ops,
   and all argv/exit-code/error-message cases are faked implicitly — they never
   open a socket. This is the bulk of the hermetic value.

### Recommended SDK enhancement (unblocks hermetic service faking)

To make **service-action** HTTP hermetically fakeable (a big future win), the
SDK should grow a *test-only* base-URL override honored by `resolveServiceURL` /
`NewIdsecISPServiceClient`, e.g.:

- `IDSEC_API_BASE_URL` (or per-service `IDSEC_<SVC>_BASE_URL`): when set, short-
  circuit URL resolution and use it verbatim (`http://127.0.0.1:<port>/...`),
  and skip the JWT-derived host. Combined with `IDSEC_DISABLE_CERTIFICATE_VERIFICATION`
  for plain-HTTP `httptest`, and a way to inject a fake/pre-seeded token so
  `login` can be bypassed (e.g. a test auth profile whose token is a locally
  minted JWT with `subdomain`/`platform_domain` claims).

This is called out as a **dependency/opportunity**, not a prerequisite: the
hermetic tier delivers value without it; when it lands, `tests/e2e/hermetic/`
can add `httptest`-backed service-action cases (e.g. `pcloud safes list` against
a fake API) using the same harness (`httpfake.go`).

### Seeding fixtures / recorded responses

- Canned JSON responses live in `tests/e2e/hermetic/testdata/http/<name>.json`
  and are served by small `http.HandlerFunc`s (route → fixture) — no live
  recording needed initially.
- If richer fidelity is wanted later, record real responses once (in the live
  tier) and replay via `go-vcr`-style cassettes; deferred until the SDK base-URL
  override exists.
- Never commit tokens/secrets in fixtures; fake JWTs are locally minted at test
  time with non-sensitive claims.

## 8. CI Integration

### Makefile targets (new)

```make
# Hermetic E2E: build tag e2e; no creds; PR gate.
e2e:
	@echo "Running hermetic E2E tests..."
	@go test -tags=e2e -count=1 ./tests/e2e/hermetic/... 

# Update golden files for hermetic E2E.
e2e-update:
	@go test -tags=e2e -count=1 ./tests/e2e/hermetic/... -update

# Live E2E: build tag e2e_live; requires IDSEC_E2E_* creds; nightly/manual.
e2e-live:
	@echo "Running live E2E tests (requires IDSEC_E2E_* credentials)..."
	@go test -tags=e2e_live -count=1 -timeout=20m ./tests/e2e/live/...

# Optional container smoke (requires Docker + built image).
e2e-docker:
	@IDSEC_E2E_DOCKER=true go test -tags=e2e -count=1 -run Docker ./tests/e2e/hermetic/...
```

- `-count=1` disables test caching so E2E always actually runs the binary.
- Hermetic uses `-tags=e2e`; live uses `-tags=e2e_live` (a distinct tag so
  `make e2e` can **never** pick up live tests, even accidentally).
- Files carry `//go:build e2e` (hermetic) or `//go:build e2e_live` (live); the
  shared `harness/` package has **no** build tag so it compiles for both.

### Build tags (summary)

| Tag | Files | Runs when | Needs creds |
|---|---|---|---|
| `e2e` | `tests/e2e/hermetic/**` | `make e2e` (PR gate) | No |
| `e2e_live` | `tests/e2e/live/**` | `make e2e-live` (nightly/manual) | Yes (`IDSEC_E2E_*`) |
| _(none)_ | `tests/e2e/harness/**` | compiled by both | No |

### Jenkins

- **PR / all branches:** add a **"Hermetic E2E"** stage right after
  `Unit Tests`, running `make e2e`. It's credential-free and fast, so it belongs
  on every build. Archive golden diffs on failure for triage.

```groovy
stage("Hermetic E2E") {
    steps { sh "make e2e" }
    post { always { archiveArtifacts artifacts: 'tests/e2e/**/testdata/golden/**', allowEmptyArchive: true } }
}
```

- **Live E2E:** a **separate scheduled/nightly** pipeline (or a manual
  `parameters` toggle like the existing `SKIP_SNYK`), running `make e2e-live`
  with `IDSEC_E2E_*` injected from Conjur (as the SDK live tests already do). It
  must **not** run on PRs. Use `IDSEC_E2E_SKIP=true` as the safety default so a
  misconfigured job skips rather than fails.
- **Docker smoke:** optionally run `make e2e-docker` in the existing
  Docker-build stage context where an image/daemon is available.

Keeping the PR gate to hermetic-only preserves current PR speed and the
no-credentials guarantee, while live coverage runs on a cadence.

## 9. Test Taxonomy & Coverage Matrix

Case names follow `success_*`, `error_*`, `edge_case_*`. Prioritized P0
(foundational, implement first), P1 (broad coverage), P2 (nice-to-have / needs
SDK support or live tenant).

### Hermetic (Tier 1)

| Priority | Command / area | Case (subtest) | Asserts |
|---|---|---|---|
| P0 | version | `success_version_prints_semver` | stdout matches version line; exit 0 |
| P0 | version | `success_version_silent_prints_bare` | `version --silent` bare version, no upgrade hint; exit 0 |
| P0 | help | `success_root_help_lists_services` | `--help` shows commands + "Available services" (all registry services, normalized); exit 0 |
| P0 | help | `success_service_help_reroutes_to_exec` | `idsec pcloud --help` shows exec/service help; exit 0 |
| P0 | routing | `success_service_reroutes_to_exec` | `idsec pcloud safes list` == `idsec exec pcloud safes list` (same normalized behavior) |
| P0 | routing | `success_alias_routes` | `idsec pc …`, `idsec dpa …`, `idsec acp …` resolve like canonical names |
| P0 | errors | `error_unknown_command_exit1` | `idsec bogus` → "unknown command" message; **exit 1** |
| P0 | errors | `error_unknown_subcommand_under_service` | `idsec pcloud bogus` → `unknown command "bogus" for "idsec exec pcloud"`; exit 1 |
| P0 | errors | `error_unknown_flag_exit1` | `idsec --bogus` → unknown-flag error + help/services; exit 1 |
| P0 | no-args | `success_no_args_shows_help` | bare `idsec` prints help; exit 0 |
| P1 | configure | `success_configure_writes_config_file` | writes `config.yaml` in temp config dir with expected keys |
| P1 | configure | `edge_case_configure_respects_config_flag` | `--config <tmp>` writes there, not `$HOME/.idsec` |
| P1 | profiles | `success_profiles_add_list_delete` | add → list shows it → delete removes it; files reflect state |
| P1 | profiles | `error_profiles_show_missing_exit1` | show nonexistent profile → error; exit 1 |
| P1 | cache | `success_cache_clear_empties_dir` | cache clear removes cache files; exit 0 |
| P1 | config file | `success_config_flag_overrides_home` | `--config` beats `IDSEC_CONFIG_FILE` beats `~/.idsec/config.yaml` |
| P1 | config file | `success_env_overrides_config_value` | ambient `IDSEC_*` wins over config-file value (precedence) |
| P1 | config file | `edge_case_unknown_key_warns_not_fatal` | non-`IDSEC_` key → warning on stderr, exit 0 |
| P1 | upgrade | `success_upgrade_check_hits_fake_github` | with `GITHUB_URL`→httptest serving newer tag, nag appears; exit 0 |
| P1 | upgrade | `success_suppress_upgrade_check_silences_nag` | `IDSEC_SUPPRESS_UPGRADE_CHECK=true` → no nag |
| P1 | streams | `success_errors_go_to_expected_stream` | error text stream + exit code (track stdout/stderr per current/agent-mode behavior) |
| P2 | no-hang | `edge_case_prompted_command_closed_stdin_no_hang` | a prompt-requiring exec with closed stdin returns within timeout, nonzero exit (proves no hang) |
| P2 | output | `success_json_flag_shapes_output` | `--json`/raw for a command renderable without backend produces valid JSON |
| P2 | docker | `success_docker_entrypoint_help` | (opt-in) `docker run <img>` → help + services; `--version` exit 0 |
| P2 | service (needs SDK base-url override) | `success_pcloud_safes_list_httptest` | fake API via `IDSEC_API_BASE_URL` → JSON list; exit 0 |

### Live (Tier 2, gated; skip-if-unset)

| Priority | Command / area | Case | Asserts |
|---|---|---|---|
| P0 | login | `success_login_isp_writes_profile` | real ISP login with `IDSEC_E2E_ISP_*` → profile/token side effects; exit 0 |
| P1 | sca | `success_sca_cloud_access_list_targets_json` | `idsec sca cloud-access list-targets --json` → exit 0, JSON parses |
| P1 | pcloud | `success_pcloud_safes_list_json` | `idsec pcloud safes list --json` → exit 0, JSON array |
| P1 | auth | `error_action_without_login_exit1` | run a service action with no/expired auth → clear error; exit 1 |
| P2 | round-trip | `success_pcloud_safe_create_get_delete` | guarded by `IDSEC_E2E_ALLOW_MUTATION`; `{{namespace}}`-scoped safe; best-effort cleanup |

## 10. Conventions

### Copyright / headers

- Every new `*.go` file starts with a `//go:build` tag line (for `hermetic`/`live`)
  followed by the same license/copyright header block used elsewhere in the repo
  (match an existing `pkg/**` file header exactly). Harness files omit the build
  tag but keep the header.

### Naming

- Test functions: `TestE2E_<Area>` (e.g. `TestE2E_Routing`). Subtests
  (table rows) use snake_case `success_* / error_* / edge_case_*`, matching unit
  tests, so `go test -run 'TestE2E_Routing/success_alias_routes'` reads naturally.
- Golden files named `<area>_<case>.golden` (and `.stderr.golden` when needed).

### Output normalization (before every golden compare)

The harness applies, in order, a documented, ordered set of substitutions so
dynamic content never causes flakes:

1. `\r\n` → `\n` (Windows line endings).
2. Trailing whitespace per line stripped; final newline normalized.
3. **Version/build info** → `<VERSION>` (matches the stamped `e2e-test` or a
   semver regex), so `--version` and upgrade text are stable.
4. **Timestamps/dates/durations** (RFC3339, `... in 1.23s`, build dates) → `<TIME>` / `<DURATION>`.
5. **Temp paths** → `<TMP>` (replace the per-test `HOME`/config/CWD roots).
6. **Absolute binary path** → `<IDSEC>`.
7. ANSI color codes stripped (color is off in non-TTY, but strip defensively).
8. **Namespace ids** (`{{namespace}}` values) → `<NS>`.

Normalization rules live in one place (`harness/normalize.go`) and are listed in
`tests/e2e/README.md` so golden authors know exactly what is canonicalized.

### Interpolation (house-convention ergonomics)

- `{{namespace}}` in a spec expands to the per-test unique id (isolation +
  deterministic-after-normalization resource names).
- `($ENV_VAR)` expands from the scoped test env (live tier: `($IDSEC_E2E_ISP_USERNAME)`),
  mirroring the TF `test_cases.yaml` convention so the two suites feel related.

### Flakiness avoidance

- **No real network in hermetic** (except localhost `httptest`); a stray real
  request should fail fast — set `HTTP(S)_PROXY` to an unreachable sink or assert
  no external host is contacted.
- **Always bound subprocess time** with a per-run timeout (context) so a hang
  fails as a test error, never a stuck CI job — this is also how the no-hang
  case is asserted.
- **Suppress the upgrade nag** (`IDSEC_SUPPRESS_UPGRADE_CHECK=true`) in every
  test except the upgrade-specific cases, so unrelated goldens don't depend on
  release state.
- Stamp deterministic version/build info (§6) rather than relying solely on
  normalization for the version.

### Parallelization safety

- Every test calls `t.Parallel()`; isolation (unique temp `HOME`/config/keyring,
  temp CWD, scoped env, unique namespace) guarantees no shared mutable state, so
  parallel runs are safe — the same discipline the unit suite already follows.
- The binary is built once (read-only afterward) and shared; `httptest` servers
  are per-test and closed via `t.Cleanup`.
- The scoped env is constructed from an allowlist (`PATH`, `HOME`/`USERPROFILE`,
  the test's `IDSEC_*`, `GOCACHE`, etc.) — never inherited wholesale — so the
  developer's ambient `IDSEC_*`/`CURSOR_AGENT`/etc. can't leak into results.

## 11. Illustrative Example (one hermetic test)

A concrete P0 case: `idsec <service>` must route through the exec engine exactly
like `idsec exec <service>`. Two equivalent expressions are shown — the
recommended Go harness style, and (for comparison) a `.txtar` sketch had we
chosen `testscript`.

### Recommended: Go harness style

```go
//go:build e2e

package hermetic

import (
    "testing"

    "github.com/cyberark/idsec-cli-golang/tests/e2e/harness"
)

func TestE2E_Routing(t *testing.T) {
    t.Parallel()
    bin := harness.SharedBinary(t) // built once in TestMain

    t.Run("success_service_reroutes_to_exec", func(t *testing.T) {
        t.Parallel()
        iso := harness.NewIsolation(t) // temp HOME/config/CWD + scoped env + namespace

        // Same normalized behavior whether or not "exec" is explicit.
        direct := harness.Run(t, bin, iso, harness.Spec{Args: []string{"pcloud", "safes", "--help"}})
        viaExec := harness.Run(t, bin, iso, harness.Spec{Args: []string{"exec", "pcloud", "safes", "--help"}})

        harness.RequireExit(t, direct, 0)
        harness.RequireExit(t, viaExec, 0)
        harness.RequireEqualNormalized(t, direct.Stdout, viaExec.Stdout)
    })

    t.Run("error_unknown_subcommand_under_service", func(t *testing.T) {
        t.Parallel()
        iso := harness.NewIsolation(t)

        res := harness.Run(t, bin, iso, harness.Spec{Args: []string{"pcloud", "bogus"}})

        harness.RequireExit(t, res, 1) // handleCommandExecution -> os.Exit(1)
        harness.RequireGolden(t, "routing_error_unknown_subcommand", res.Stdout)
        // golden (normalized): unknown command "bogus" for "idsec exec pcloud"
    })
}
```

```go
// tests/e2e/harness/run.go (illustrative core)
type Spec struct {
    Args  []string
    Stdin string
    Env   map[string]string // merged over the isolation's scoped env
}
type Result struct{ Stdout, Stderr string; Exit int }

func Run(t *testing.T, bin string, iso *Isolation, s Spec) Result {
    t.Helper()
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second) // no-hang guard
    defer cancel()
    cmd := exec.CommandContext(ctx, bin, s.Args...)
    cmd.Dir = iso.CWD
    cmd.Env = iso.EnvWith(s.Env)               // scoped allowlist + IDSEC_SUPPRESS_UPGRADE_CHECK=true
    cmd.Stdin = strings.NewReader(s.Stdin)     // closed/empty stdin by default -> proves no prompt hang
    var out, errb bytes.Buffer
    cmd.Stdout, cmd.Stderr = &out, &errb
    err := cmd.Run()
    if ctx.Err() == context.DeadlineExceeded {
        t.Fatalf("command hung: %v", s.Args)
    }
    return Result{Stdout: out.String(), Stderr: errb.String(), Exit: exitCode(err)}
}
```

### For comparison: `.txtar` (if `testscript` were chosen)

```
# tests/e2e/hermetic/testdata/routing.txtar  (illustrative, NOT the chosen approach)
# idsec <service> routes like idsec exec <service>
exec idsec pcloud safes --help
cp stdout direct.txt
exec idsec exec pcloud safes --help
cmp stdout direct.txt

# unknown subcommand under a service -> exit 1 with a specific message
! exec idsec pcloud bogus
stdout 'unknown command "bogus" for "idsec exec pcloud"'
```

The Go version is chosen because it also carries the no-hang timeout, scoped-env
isolation, and (in other cases) `httptest`/filesystem assertions in one place.

## 12. Migration / Rollout Plan

### Phase 0 — Harness + one vertical slice (foundation)
- Add `tests/e2e/harness/**` (build binary once, run+capture, isolation,
  normalize, golden `-update`, interpolation).
- Add `tests/e2e/main_test.go` (`TestMain` builds binary; honors `IDSEC_E2E_SKIP`).
- Land P0 `version`, `help`, and `routing` cases in `tests/e2e/hermetic/`.
- Add `make e2e` / `make e2e-update`; wire the **Hermetic E2E** Jenkins stage.
- Effort: ~2–3 days. Outcome: green PR gate proving the model works.

### Phase 1 — Broaden hermetic coverage (P0 + P1)
- Complete P0 error/exit/no-args cases; add `configure`/`profiles`/`cache`,
  config-file precedence, and the `httptest`-backed `upgrade` cases.
- Write `tests/e2e/README.md` (run, add cases, update goldens, normalization
  list, live gate).
- Effort: ~3–4 days.

### Phase 2 — Live tier (gated)
- Add `tests/e2e/live/**` with the SDK-style `IDSEC_E2E_*` loader + skip-if-unset,
  `e2e_live` tag, `make e2e-live`, and a nightly/manual Jenkins pipeline pulling
  creds from Conjur. Land `login` + read-only `sca`/`pcloud` list cases.
- Effort: ~3–4 days (plus tenant/creds setup).

### Phase 3 — Extended surface (P2 + hardening)
- Docker smoke (`make e2e-docker`), cross-OS matrix (macOS/Windows nightly),
  no-hang closed-stdin case, `--json` shape cases.
- **SDK dependency:** pursue the `IDSEC_API_BASE_URL` override (§7); once it
  lands, add `httptest`-backed hermetic service-action cases.
- Optional: evaluate adding `testscript` for the pure routing/help matrix if
  golden tables get verbose.
- Effort: ~3–5 days, partly gated on SDK work.

### Risks & mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Goldens drift on version/date/paths | Flaky PRs | Deterministic version stamping (§6) + strict normalization (§9); `-update` workflow documented |
| No SDK base-URL override | Service actions can't be faked hermetically | Scope hermetic to no-backend surface + `httptest` upgrade; push service calls to live tier; request SDK override (§7) |
| Live tests run on PRs by accident | Secrets/flakiness on PRs | Separate `e2e_live` tag **and** env gate; `IDSEC_E2E_SKIP=true` default; distinct pipeline |
| `releasedFeaturesOnly` changes visible actions | Help/services golden mismatch | Pin `releasedFeaturesOnly=false` in the E2E build (§6) |
| Error stream may move stdout→stderr (agent-mode design) | Golden churn | Assert exit code primarily; keep stream-specific goldens small and update alongside that change |
| Windows path/HOME differences | Cross-OS failures | Explicit `HOME`/`USERPROFILE` + `IDSEC_*` folder env; line-ending + path normalization; Windows in nightly only |
| Ambient dev env leaks (`IDSEC_*`, `CURSOR_AGENT`) | Non-deterministic local runs | Scoped allowlist env, never inherit wholesale (§10) |
| Binary build slows the suite | Slower CI | Build once in `TestMain`; support `IDSEC_E2E_BINARY` to reuse an artifact |

### Open questions

1. **Adopt `testscript` later?** Keep the Go harness as primary; revisit
   `testscript` only if the routing/help golden tables become unwieldy.
   Recommendation: defer.
2. **Error stream contract.** Should E2E encode today's `fmt.Println(err)` (→
   stdout) behavior, or wait for the agent-mode stdout→stderr fix and encode
   that? Recommendation: assert **exit codes** now and keep stream goldens
   minimal until that change lands, then update in the same PR.
3. **SDK base-URL override ownership.** Who lands `IDSEC_API_BASE_URL` in the
   SDK, and on what timeline? Determines when hermetic service-action tests are
   possible.
4. **Live mutation policy.** Do we allow any create/delete round-trips in the
   live tier (guarded by `IDSEC_E2E_ALLOW_MUTATION` + namespacing + cleanup), or
   keep it strictly read-only? Recommendation: read-only first; add one guarded
   round-trip in Phase 3.
5. **Cross-OS scope.** Is Linux-only sufficient for the PR gate with
   macOS/Windows nightly, or do we need all three on PRs? Recommendation:
   Linux PR gate, tri-OS nightly.

## Reference

- Existing design style: `docs/design/agent-mode.md`.
- SDK E2E prior art: `idsec-sdk-golang/tests/e2e/` (framework, env gating) and
  `idsec-sdk-golang/tools/gene2e`.
- `rogpeppe/go-internal/testscript`: <https://pkg.go.dev/github.com/rogpeppe/go-internal/testscript>
- Team Terraform acceptance convention: `test_cases.yaml` (`steps`, `set_input`,
  `expect_error`, `{{namespace}}`, `($ENV_VAR)`, `success_/error_/edge_case_`).
