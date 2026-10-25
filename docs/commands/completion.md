---
title: Completion
description: Completion Command
---

# Completion

Use the `completion` command to generate a shell autocompletion script for Idsec CLI.
Once installed, pressing `Tab` after `idsec` will suggest commands, subcommands, and service names.

> **Note:** The `completion` command is provided automatically by the CLI framework and requires no additional setup beyond the one-time shell configuration below.

## Running
```shell linenums="0"
idsec completion [shell]
```

## Usage
```shell
Generate the autocompletion script for idsec for the specified shell.
See each sub-command's help for details on how to use the generated script.

Usage:
  idsec completion [command]

Available Commands:
  bash        Generate the autocompletion script for bash
  fish        Generate the autocompletion script for fish
  powershell  Generate the autocompletion script for powershell
  zsh         Generate the autocompletion script for zsh

Flags:
  -h, --help   help for completion

Use "idsec completion [command] --help" for more information about a command.
```

## Shell Setup

### Zsh

**Load for the current session only:**
```shell
source <(idsec completion zsh)
```

**Load permanently (execute once):**

On Linux:
```shell
idsec completion zsh > "${fpath[1]}/_idsec"
```

On macOS:
```shell
idsec completion zsh > $(brew --prefix)/share/zsh/site-functions/_idsec
```

> If you use **Oh My Zsh**, the custom completions path must be added to `fpath` _before_ Oh My Zsh is sourced in `~/.zshrc`:
> ```shell
> # Add this BEFORE the `source $ZSH/oh-my-zsh.sh` line
> fpath=(~/.zsh/completions $fpath)
> ```
> Then generate the script into that directory:
> ```shell
> mkdir -p ~/.zsh/completions
> idsec completion zsh > ~/.zsh/completions/_idsec
> ```

---

### Bash

Requires the `bash-completion` package. Install via your OS package manager if not present.

**Load for the current session only:**
```shell
source <(idsec completion bash)
```

**Load permanently (execute once):**

On Linux:
```shell
idsec completion bash > /etc/bash_completion.d/idsec
```

On macOS:
```shell
idsec completion bash > $(brew --prefix)/etc/bash_completion.d/idsec
```

---

### Fish

**Load for the current session only:**
```shell
idsec completion fish | source
```

**Load permanently (execute once):**
```shell
idsec completion fish > ~/.config/fish/completions/idsec.fish
```

---

### PowerShell

**Load for the current session only:**
```powershell
idsec completion powershell | Out-String | Invoke-Expression
```

**Load permanently:** Add the command above to your PowerShell profile file.

---

## What Gets Completed

After setup, `Tab` completion works at every level of the command hierarchy:

| What you type | What gets completed |
|---|---|
| `idsec <Tab>` | Built-in commands (`cache`, `login`, …) and all available services (`pcloud`, `sia`, …) |
| `idsec pcloud <Tab>` | Service subcommands (`accounts`, `safes`, …) |
| `idsec pcloud safes <Tab>` | Actions (`list`, `create`, `delete`, …) |
| `idsec exec pcloud safes list --<Tab>` | All flags (`--dry-run`, `--profile-name`, `--query`, `--request-file`, …) |
