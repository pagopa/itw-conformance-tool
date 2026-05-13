# ITW Conformance CLI

This CLI is a headless wrapper.
It does not implement protocol logic.
It does not replace Vitest tests.

It does three things:

1. Reads runtime configuration (defaults, JSON file, CLI flags).
2. Builds the correct Nx command for the requested flow.
3. Executes the command and returns the exit code and JSON logs.

If the Nx target fails, the CLI fails.
If the Nx target passes, the CLI passes.

## What it actually does

- Issuance command: delegates to itw-credential-issuer:<target>
- Presentation command: delegates to itw-relying-party:<target>
- Help command: prints usage and options

## What it does NOT do

- It does not directly execute custom tests.
- It does not validate remote endpoints.
- It does not generate its own conformance reports.
- It does not fix Nx target configuration problems.

## Prerequisites

- Run from the itw-conformance-tool workspace root
- Node 22
- pnpm 10.30.3

Recommended in CI/non-interactive environments:

- CI=1
- NX_TUI=false

## Available commands

From the workspace root:

- pnpm conformance help
- pnpm conformance issuance [options]
- pnpm conformance presentation [options]

Root shortcuts:

- pnpm conformance:issuance -- [options]
- pnpm conformance:presentation -- [options]

## CLI options

- -c, --config <file>
  - Runtime JSON config file
- -e, --endpoint <url>
  - Endpoint override
- --credential-types <csv>
  - Comma-separated credential types, for example PID,MDL
- --unsafe-tls
  - Disable TLS certificate verification (sets NODE_TLS_REJECT_UNAUTHORIZED=0)
- --tls-ca-file <path>
  - Custom CA file path
- --log-level <debug|info|warn|error>
  - Minimum log threshold (debug shows everything, error shows only errors)
- --target <test|serve>
  - Nx target to execute
- --skip-nx-cache
  - Adds --skip-nx-cache to the Nx command
- --dry-run
  - Prints the final config and Nx command without executing
- -h, --help
  - Show help

## Temporary migration note

This CLI already validates and accepts all runtime options, but some of them are not yet wired into the delegated
issuer/relying-party flow behavior in this migration phase.

- `--endpoint`, `--credential-types`, and `--tls-ca-file` are currently exported as `ITW_CT_*` environment variables.
- At the moment, delegated targets do not consume these variables yet, so they do not change flow behavior by themselves.
- `--target` and `--skip-nx-cache` already affect the delegated Nx command.

These runtime options are intentionally kept now to preserve the CLI contract while migration of downstream consumers is completed.

## Configuration priority

Actual merge order:

1. Internal defaults
2. JSON file passed with --config
3. CLI flags

CLI flags always take precedence.

## JSON config file format

Example:

{
  "endpoint": "https://issuer.example.org",
  "credentialTypes": ["PID", "MDL"],
  "logLevel": "info",
  "target": "test",
  "tls": {
    "unsafe": false,
    "caFile": "./certs/ca.pem"
  },
  "nx": {
    "skipCache": true,
    "extraArgs": ["--verbose"]
  }
}

Supported fields:

- endpoint: string
- credentialTypes: string[]
- logLevel: debug|info|warn|error
- target: test|serve
- tls.unsafe: boolean
- tls.caFile: string
- nx.skipCache: boolean
- nx.extraArgs: string[]

## Practical examples

Help:

pnpm conformance help

Dry-run issuance:

pnpm conformance issuance --dry-run --endpoint https://issuer.example.org --credential-types PID,MDL --skip-nx-cache

Dry-run presentation:

pnpm conformance presentation --dry-run --target serve --log-level debug

Actual issuance run:

pnpm conformance issuance --target test

Actual presentation run:

pnpm conformance presentation --target test

## Output and exit codes

The CLI writes JSON logs to stdout and captures Nx output as structured JSON events:

- cli.runtime_config_resolved
- cli.nx_command
- cli.dry_run_summary
- cli.nx_output
- cli.flow_completed
- cli.flow_failed
- cli.unhandled_error

Levels are assigned per event and filtered by --log-level:

- cli.runtime_config_resolved: debug
- cli.nx_command: debug
- cli.dry_run_summary: info (always emitted when `--dry-run` is set)
- cli.nx_output (stdout): info
- cli.nx_output (stderr): error
- cli.flow_completed: info
- cli.flow_failed: error
- cli.unhandled_error: error

This keeps the JSON stream parseable in CI because the delegated Nx output is no longer emitted as raw mixed stdout/stderr text.
The CLI also forces JSON logger output regardless of `NODE_ENV`, so logs are not pretty-printed when running local development commands.

Exit codes:

- 0: successful execution
- != 0: error (parse, config, or delegated Nx target failure)

## Environment variables exported by the CLI

Before delegating to Nx, the CLI exports:

- ITW_CT_FLOW
- ITW_CT_ENDPOINT
- ITW_CT_CONFIG_FILE (if present)
- ITW_CT_CREDENTIAL_TYPES
- ITW_CT_UNSAFE_TLS
- ITW_CT_TLS_CA_FILE (if present)
- ITW_CT_LOG_LEVEL

## Relationship with pnpm test

This CLI does not replace pnpm test.

- pnpm test = Vitest pipeline for configured projects
- pnpm conformance ... = runtime orchestration of a flow through an Nx target

## Common errors and root cause

- "This command must be run from the itw-conformance-tool workspace root"
  - You are running the CLI from the wrong folder
- "Unknown option"
  - Unsupported flag or typo
- "Invalid target"
  - Target different from test or serve
- "Invalid config ..."
  - Invalid value in the JSON file
- flow_failed
  - The delegated Nx target failed; this is not a hidden CLI error
