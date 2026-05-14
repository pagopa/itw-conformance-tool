# ITW Conformance CLI

Local orchestrator for `itw-credential-issuer` and `itw-relying-party`.

## Commands

From workspace root:

- `pnpm conformance:init`
- `pnpm conformance:start`
- `pnpm conformance:start:issuer`
- `pnpm conformance:start:rp`

Via Nx:

- `pnpm nx run itw-conformance-cli:run --args="init"`
- `pnpm nx run itw-conformance-cli:run --args="start --all"`

## Behavior

- `init`: creates `data_dir` (`~/.itw-conformance-tool` by default) and writes `config.ini` in current directory.
- `start`: reads `config.ini` (or `--config <path>`). If missing, starts with defaults and logs a warning.
- service ports:
  - issuer default `3000`
  - rp default `8080`
- child Nx output is forwarded directly (`stdio: inherit`) to preserve ANSI/formatting.

## Main flags

- `-c, --config <path>`
- `--all`, `--issuer`, `--rp`
- `--force`
- `--log-level <debug|info|warn|error>`
- `--skip-nx-cache`
- `--unsafe-tls`
- `--tls-ca-file <path>`
- `--dry-run`
