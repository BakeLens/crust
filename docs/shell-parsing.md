# Shell Command Parsing Workflow

The extractor processes Bash tool calls through a multi-stage pipeline that combines AST analysis with interpreter dry-run for accurate path extraction.

Source: `internal/rules/extractor.go`

## Pipeline

```text
extractBashCommand (entry point)
 │
 ├─ A. Collect command strings from all knownCommandFields
 │     (command, cmd, commandline, script, shellcommand, shell)
 │
 └─ B. For each command string:
      │
      ├─ 1. IsSuspiciousInput(raw cmd)
      │     Checks BEFORE parsing — AST printer strips null bytes
      │     and normalizes control chars, so post-parse checks miss evasion.
      │
      ├─ 2. syntax.Parse → AST
      │
      ├─ 3. syntax.Simplify
      │     Strips redundant parens, unnecessary quotes, duplicate subshells.
      │
      ├─ 4. minPrinter.Print(AST) → info.Command
      │     Canonical minified string for match.command rule matching.
      │     Captures full syntax including non-executed branches (e.g.,
      │     "false && rm -rf /" is visible even though Runner skips rm).
      │
      └─ 5. runShellFile(AST) → []parsedCommand, symtab
           │  interp.Runner in dry-run mode:
           │  - CallHandler: captures all commands (builtins + externals)
           │  - ExecHandler: no-op (prevents actual execution)
           │  - OpenHandler: captures redirect paths (fires before CallHandler)
           │  - ReadDirHandler2/StatHandler: disabled (no filesystem access)
           │  - Env seeded with process env + parent symtab
           │
           └─ extractFromParsedCommandsDepth (semantic extraction)
                For each parsedCommand:
                ├─ Mark evasive if HasSubst ($() or backticks)
                ├─ resolveCommand: strip wrappers (sudo, env, timeout...)
                ├─ Shell interpreter + -c flag → recursive parseShellCommandsExpand
                ├─ Command DB lookup → extract paths by positional index / flags
                ├─ Interpreter code via CommandInfo.CodeFlag (python -c, perl -e) → string literal path extraction
                └─ Redirect paths → info.Paths (write for >/>>; read for <)
```

## Why two views

The pipeline produces two representations of the same command, serving different security purposes:

- **minPrint** (step 4): Conservative full-syntax view for `match.command` rules. Captures intent — including commands in non-executed branches like `false && rm -rf /`. Used for rule matching and pre-filter.

- **Runner** (step 5): Execution-path view for path extraction. Only captures commands that would actually execute, with variables fully expanded. Used to populate `info.Paths`, `info.Hosts`, and `info.Operation`.

Eliminating minPrint in favor of reconstructing `info.Command` from Runner output would create a detection gap: commands behind short-circuited `&&`/`||` would become invisible to `match.command` rules.

## Key types

| Type | Purpose |
|------|---------|
| `ExtractedInfo` | Output: paths, hosts, operation, command string, evasion flags |
| `parsedCommand` | Intermediate: single command with name, args, redirect paths, subst flag |
| `CommandInfo` | Config: maps command names to operations, path argument positions, and interpreter code flags (`CodeFlag`) |

## Recursion

`sh -c`, `bash -c`, etc. trigger recursive parsing up to `maxShellRecursionDepth` (3). The parent's symbol table propagates to the child via `mergeEnvArgs` + `parseShellCommandsExpand`, so `env F=/etc/passwd sh -c 'cat $F'` correctly extracts `/etc/passwd`.

## Command Database

The command database (`defaultCommandDB()` in `command_db.go`) is the **single source of truth** for command metadata: operation type, path argument positions, path flags, skip flags, and interpreter code flags. All extraction logic looks up commands in this DB rather than maintaining separate maps.

### Interpreter Code Flags (`CodeFlag`)

Interpreter commands like `python`, `node`, `ruby`, `perl`, and `php` accept inline code via a flag (`-c`, `-e`, `-r`). The `CodeFlag` field in `CommandInfo` tells the extractor which flag carries inline code:

| Interpreter | CodeFlag | Example |
|-------------|----------|---------|
| python, python2, python3 | `-c` | `python3 -c 'open("/etc/shadow")'` |
| node | `-e` | `node -e 'require("fs").readFileSync("/etc/shadow")'` |
| ruby | `-e` | `ruby -e 'File.read("/etc/shadow")'` |
| perl | `-e` | `perl -e 'system("cat /etc/shadow")'` |
| php | `-r` | `php -r 'file_get_contents("/etc/shadow");'` |

When `CodeFlag` is set, `extractInterpreterAndRedirects` scans the flag's argument for embedded paths, URLs, and shell commands using string literal extraction + shell parsing. If file paths are found, the operation is forced to `OpRead` (overriding `OpExecute`) so file-protection rules fire.

To add a new interpreter, add a single entry to `defaultCommandDB()` with the `CodeFlag` field set. No other maps or code changes are needed.

**Note:** Shell interpreters (`bash`, `sh`, `zsh`, `dash`, `ksh`, `su`) use a different mechanism (`shellInterpreters` map + recursive shell parsing via `-c`) because their inner code is a full shell script, not interpreter-specific code. Do not add shell interpreters to `CodeFlag`.

## Environment

The Runner is seeded with the real process environment (`os.Environ()`) so variables like `$HOME` resolve to actual values at extraction time. For testing, `NewExtractorWithEnv` accepts a custom environment map.

## Windows Shell Coverage

On Windows, `Bash` tool calls may contain commands targeting any of the three shell environments: PowerShell, cmd.exe, or bash-on-Windows (MSYS2/Git Bash, WSL). Crust handles all three:

| Shell | How extracted |
|-------|--------------|
| **[PowerShell](https://learn.microsoft.com/en-us/powershell/)** (`pwsh.exe` / `powershell.exe`) | Dual-parse: bash AST + pwsh worker pool (see below) |
| **[cmd.exe](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd)** (`cmd /c <inner>`) | Recursive parse: inner command string re-parsed as bash |
| **[WSL](https://learn.microsoft.com/en-us/windows/wsl/)** (`wsl <cmd>`) | Wrapper stripping: `wsl cat /etc/passwd` → extracts `cat /etc/passwd` |
| **[Batch files](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/windows-commands)** (`.bat` / `.cmd`) | Detected and flagged as `OpExecute`; no inner parse |
| **[Invoke-Item](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/invoke-item) / ii** | PS cmdlet for shell-open; path extracted as `OpExecute` |

### Windows Path Normalization

Before bash parsing, `normalizeWinPaths` converts Windows-style backslash paths to forward slashes so the POSIX bash parser doesn't treat `\` as an escape character:

- `C:\Users\user\.env` → `C:/Users/user/.env`
- `\\server\share\file` → `//server/share/file`
- `%USERPROFILE%\.env` → `%USERPROFILE%/.env` (cmd.exe `%VAR%` syntax)

This runs universally — not just for PowerShell-looking commands — before the bash parse step. The pwsh worker receives the original (un-normalized) command so backslash paths are preserved for PS AST resolution.

## PowerShell (Windows 10/11)

On Windows 10/11, `Bash` tool calls may contain PowerShell commands. The bash parser handles many PS cmdlets correctly (they look like POSIX commands), but fails on PS-specific syntax: `$var="value"` assignments, `C:\path\with\backslashes`, and `\\UNC\paths`.

Crust uses a **dual-parse** strategy on Windows:

```text
extractBashCommand (Windows path)
 │
 ├─ 1. looksLikePowerShell? (psVarAssignRe / PS cmdlet names)
 │
 ├─ 2. syntax.Parse (bash AST)
 │     ├─ Success → extract paths via Runner (step 5 above)
 │     │             + if looksLikePowerShell: pwsh worker augments results
 │     │
 │     └─ Failure → pwsh worker as authoritative PS parser
 │                   ├─ PS parse OK → extract from PS AST
 │                   └─ PS parse error / crash → Evasive = true
 │
 └─ 3. Results merged: paths/hosts union, highest-severity operation wins
```

**pwsh worker pool** (`pwsh/pool.go`, `pwsh/worker.go`): a pool of `pwsh.exe` (PS 7+, preferred) or `powershell.exe` (5.1) subprocesses — up to `min(GOMAXPROCS, 4)` workers for concurrent parsing. The bootstrap script uses `[System.Management.Automation.Language.Parser]::ParseInput()` — a pure AST parser, never executes commands. JSON over stdin/stdout; workers auto-restart on crash. `$env:VAR` references in both quoted and unquoted arguments are resolved via `[System.Environment]::GetEnvironmentVariable`.

**Fallback** (no pwsh worker): heuristic `substitutePSVariables` + `normalizeWinPaths` pre-processing before bash parsing, gated behind `ShellEnvironment().HasPwsh()` (native Windows and MSYS2/Git Bash).

**Evasion**: a PS-looking command that crashes or times out a pool worker is blocked as evasive (fail-closed). A command with PS parse errors but valid bash syntax is allowed — bash extraction stands.
