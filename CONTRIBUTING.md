# Contributing

Thank you for considering contributing to "idsec-cli-golang"! We welcome opening issues and requests to improve this project. For general contributions and community guidelines, please see the [repo](https://github.com/cyberark/community/).

## General Steps for opening issues

1. Open a new issue under "issues"
2. Pick the relevant issue type (Bug, Feature, Epic, etc.)
3. Fill in the issue template with as much detail as possible. This includes:
   - A clear description of the problem or feature request
   - Steps to reproduce the issue (if applicable)
   - Any relevant logs or screenshots
   - Your environment details (OS, version, etc.)

From here, your issue will be reviewed, and once you've responded to all feedback, we will provide the relevant code changes required.

## Development

### Prerequisites

- Go 1.25 or later
- `golangci-lint` for linting
- `goreleaser` for release builds

### Building

```bash
# Build the CLI binary
make all

# Prepare code (tidy, format, vendor)
make prepare
```

### Code Generation

New service CLI action files can be scaffolded automatically using the `gensvccli` tool:

```bash
# Generate a new service CLI action
make gensvccli SERVICE=<name> RESOURCE=<name>

# Preview generated output without writing files
make gensvccli-preview SERVICE=<name> RESOURCE=<name>

# Examples:
make gensvccli SERVICE=pcloud RESOURCE=vaults
make gensvccli SERVICE=sia RESOURCE=certificates
```

### Unit Testing

We use comprehensive unit testing to ensure code quality and reliability. Follow these guidelines when writing tests:

#### Test File Organization
- Create test files alongside your source code using the convention `filename_test.go`
- Place package-specific test utilities, mocks, and fixtures in a `testutils` directory within your package
- For shared test resources across multiple packages, use the `testutils` directory in the appropriate parent package

#### Test Utilities Structure (`testutils`)
Organize your test utilities in a dedicated `testutils` directory within each package that requires testing support:

```
pkg/actions/
├── idsec_action.go
├── idsec_action_test.go
└── testutils/
    ├── shared_mocks.go      # Mock implementations for external dependencies
    ├── test_helpers.go      # Helper functions for test setup and validation
    └── test_fixtures.go     # Test data, constants, and sample inputs
```

**File Purposes:**
- **`shared_mocks.go`** - Mock implementations of interfaces and external dependencies
- **`test_helpers.go`** - Utility functions for test setup, teardown, and common operations
- **`test_fixtures.go`** - Test data, sample inputs, expected outputs, and constants

**Usage in Tests:**
```go
import (
    "github.com/cyberark/idsec-cli-golang/pkg/actions/testutils"
)

func TestExample(t *testing.T) {
    // Use test fixtures
    profile := testutils.CreateTestProfile("my-profile")

    // Use test helpers
    cmd := testutils.CreateTestCommand()

    // Use shared mocks
    mockLoader := &testutils.MockProfileLoader{}

    // ... rest of test
}
```

**Naming Conventions:**
- Use snake_case for test case names (e.g., `"success_case_normal_input"`, `"error_invalid_parameter"`)
- Prefix mock types with `Mock` (e.g., `MockProfileLoader`, `MockHTTPClient`)
- Prefix helper functions with descriptive verbs (e.g., `CreateTestProfile()`, `SetupTestCommand()`)
- Use clear, descriptive names for test fixtures (e.g., `ValidProfileData`, `InvalidAuthMethod`)

#### Writing Tests
- Write tests using Go's [Table-Driven Tests](https://go.dev/wiki/TableDrivenTests) pattern for each function
- Include test cases for both success and failure scenarios
- Test edge cases and boundary conditions
- Use descriptive test names that clearly indicate what is being tested

#### Running Tests

```bash
# Run all unit tests with coverage reporting
make unit-test-all

# Run tests for specific packages
go test ./pkg/actions/...

# Run tests with verbose output
go test -v ./...
```

#### Coverage Analysis
```bash
# Generate and view HTML coverage report
go tool cover -html=coverage.out
```

#### Test Requirements
- All new code must include comprehensive unit tests
- Maintain or improve overall test coverage
- Tests must pass before submitting pull requests
- Mock external dependencies appropriately

### Function Documentation

All exported functions, types, constants, and variables must have comprehensive documentation comments following Go's documentation standards.

#### Documentation Format
Follow this structured format for all exported functions:

```go
// FunctionName describes what the function does in one line.
//
// Provide a detailed description of the function's behavior, including any important
// details about its implementation or usage patterns.
//
// Parameters:
//   - param1: Description of the parameter and its expected values
//   - param2: Description of the parameter and its constraints
//   - param3: Optional parameter description (use "nil for no limit" style)
//
// Returns description of what the function returns, including error conditions.
//
// Example:
//   result, err := FunctionName(
//       "example input",
//       42,
//       &optionalParam,
//   )
//   if err != nil {
//       // handle error
//   }
func FunctionName(param1 string, param2 int, param3 *int) (ResultType, error) {
```

#### Documentation Requirements
- **Start with the exact name**: Begin comments with the exact name of the item being documented
- **One-line summary**: First line should be a complete sentence describing what the function does
- **Detailed description**: Provide context about behavior, implementation details, or usage patterns
- **Parameter documentation**: Document all parameters with their types, constraints, and expected values
- **Return value documentation**: Explain what is returned, including all error conditions
- **Examples**: Include usage examples for complex functions
- **Consistent terminology**: Use the same terms throughout the codebase

#### Package Documentation
- Add package documentation at the top of the main package file
- Start with "Package [name] provides..."
- Describe the main purpose and functionality

#### Documentation Best Practices
- Use complete sentences with proper punctuation
- Explain what the function does, not how it works (unless the how is important)
- Be specific about constraints and expected inputs
- Document any side effects or state changes
- Include examples that can be copy-pasted and run
- Keep documentation up-to-date with code changes

### Enable Attribute

The `Enabled` field on `IdsecServiceCLIActionDefinition` controls whether a CLI command is registered and exposed to users. Use it to hide work-in-progress commands from release builds.

#### When to Use the Enable Attribute

- New commands that are not ready for production
- Experimental subcommands that need more testing
- Features waiting for approval or documentation

#### How to Disable a CLI Action to Omit it from the Release Build

Set `Enabled` to `false` in the action definition. The action will be filtered out of release builds.

```go
var CLIAction = &actions.IdsecServiceCLIActionDefinition{
    IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
        ActionName: "experimental-action",
        Enabled:    boolPtr(false),  // Will be filtered out in release builds
    },
}
```

The same attribute applies to subcommands — disabled subactions are pruned recursively when the release flag is active.

#### Build Flag

The `Enabled` attribute filtering is controlled by a build-time ldflags variable. By default, filtering is OFF and all actions are registered.

**Default build (filtering OFF):**
```bash
go build ./...
```

**Release build (filtering ON):**
```bash
go build -ldflags "-X github.com/cyberark/idsec-cli-golang/pkg/registry.releasedFeaturesOnly=true" ./...
```

When filtering is ON, actions with `Enabled: false` are excluded from the command registry.

#### Best Practices

1. Default is enabled. Omit the field or set it to `nil` for normal behavior.
2. Remove the attribute when the feature is ready. Do not leave disabled attributes in production code.
3. The `Enabled` check happens at startup during action registration. It cannot be changed at runtime.
4. Use the build flag to enable filtering for release builds (handled automatically by `make goreleaser-release`).

## Releases

**Maintainers only** should create releases. Follow these steps to prepare for a release:

### Pre-requisites

- Review recent commits and ensure the changelog includes all relevant changes, with references to GitHub issues or PRs when applicable.
- Verify that any updated dependencies are accurately reflected in the `NOTICES.md`.
- Confirm that the required documentation is complete and has been approved.
- Ensure `make validate-prepare` passes (tidy, format, and vendor are all committed).

### Release Process

```bash
# Bump the version (patch / minor / major)
make bump-version BUMP_TYPE=patch

# Commit the version bump, then trigger the release via goreleaser
make goreleaser-release
```

Snapshot builds (non-`main`/`master`/`release/*` branches) are released automatically as snapshots without a tag.

### Legal

Any submission of work, including any issue, request, modification of, or addition to, an existing work ("Contribution") to "idsec-cli-golang" shall be governed by and subject to the terms of the Apache License 2.0 (the "License") and to the following complementary terms. In case of any conflict or inconsistency between the provision of the License and the complementary terms, the complementary terms shall prevail. By submitting the Contribution, you represent and warrant that the Contribution is your original creation and you own all right, title and interest in the Contribution. You represent that you are legally entitled to grant the rights set out in the License and herein, without violation of, or conflict with, the rights of any other party. You represent that your Contribution includes complete details of any third-party license or other restriction associated with any part of your Contribution of which you are personally aware.
