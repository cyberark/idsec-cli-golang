---
title: Version
description: Version Command
---

# Version

Use the `version` command to print the Idsec CLI version and build metadata embedded into the binary at build time.

## Running
```shell linenums="0"
idsec version
```

The default output prints a multi-line block of build metadata, for example:
```text linenums="0"
Idsec v0.3.1
Build Number: 3
Build Date: 2026-05-20T13:31:52Z
Git Commit: 8e682dc6b01ac408b1e66f0162809bd877a496cc
Git Branch: main
```

For machine-readable output (raw semantic version only, without the `Idsec ` or leading `v` prefix), suitable for shell scripting:
```shell linenums="0"
idsec version --silent
```

Which prints just the bare version, e.g.:
```text linenums="0"
0.3.1
```


## Usage
```shell
Print the Idsec CLI version

Usage:
  idsec version [flags]

Flags:
  -h, --help     help for version
  -s, --silent   Print only the raw semantic version, without the 'Idsec ' or leading 'v' prefix
```
