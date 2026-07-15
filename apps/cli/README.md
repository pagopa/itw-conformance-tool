# ITW Conformance CLI

Local CLI for the `itw-conformance-tool` monorepo. It supports the following workflows:

- `init`, to generate the local configuration and key material
- `start`, to launch the trust anchor, issuer, and relying party services through Nx
- `test`, to run conformance matrix specs (`WP_*`) through Vitest
- `report:list`, to list all available conformance run reports
- `report:create`, to generate an HTML or PDF report for a given run

## Installation (global binary)

To make `itw-conformance-tool` and `itwct` available as global commands in the terminal:

```sh
# From the project root
pnpm i
pnpm nx build itw-conformance-cli   # compiles the CLI and generates dist/main.js
cd apps/cli
pnpm link --global                  # registers the bin entries in the global PATH
```

To uninstall:

```sh
pnpm unlink --global itw-conformance-cli
```

## Entry Points

You can run the CLI either through the exported binary (after `pnpm link --global`) or through the root workspace scripts without installing globally.

Direct CLI usage:

- `itw-conformance-tool init`
- `itw-conformance-tool start`
- `itw-conformance-tool test`
- `itw-conformance-tool report:list`
- `itw-conformance-tool report:create <uuid> [format]`
- `itwct init`
- `itwct start`
- `itwct test`
- `itwct report:list`
- `itwct report:create <uuid> [format]`

From the workspace root through Nx-backed scripts:

- `pnpm itw-conformance-tool --args="init"`
- `pnpm itw-conformance-tool --args="init --force"`
- `pnpm itw-conformance-tool --args="start --all"`
- `pnpm itw-conformance-tool --args="start --issuer"`
- `pnpm itw-conformance-tool --args="start --rp"`
- `pnpm itw-conformance-tool --args="start --trust-anchor"`
- `pnpm itw-conformance-tool --args="test"`
- `pnpm itw-conformance-tool --args="report:list"`
- `pnpm itw-conformance-tool --args="report:create <uuid>"`
- `pnpm itw-conformance-tool --args="report:create <uuid> pdf"`

Root shortcuts:

- `pnpm itw-conformance-tool:init`
- `pnpm itw-conformance-tool:start`
- `pnpm itw-conformance-tool:start:issuer`
- `pnpm itw-conformance-tool:start:rp`
- `pnpm itw-conformance-tool:start:trust-anchor`
- `pnpm itw-conformance-tool:test` (legacy shortcut)

## Supported Commands

- `init`
- `start`
- `test`
- `report:list`
- `report:create`
- `help`
- `version`

## Supported Options

- `-c, --config <path>`: path to the configuration file. Supported by `start`, `test`, `report:list`, and `report:create`
- `--all`: start the trust anchor, issuer, and relying party services. This is the default for `start`
- `--issuer`: start only the issuer service
- `--rp`: start only the relying party service
- `--trust-anchor`: start only the trust anchor service
- `-f, --force`: overwrite generated files during `init`
- `-h, --help`: print the CLI help
- `-v, --version`: print the CLI version

The parser also supports inline config assignment:

- `--config=/absolute/path/config.ini`
- `-c=./config.ini`

## Current Behavior

### `init`

`init` prepares the local runtime material used by the conformance services.

When executed, it:

- determines the target config file path
- creates the data directory
- creates the `issuer` and `rp` subdirectories
- generates issuer signing keys
- generates relying party authentication keys
- generates the IACA certificate and private key
- generates a self-signed TLS certificate and private key **only if `https = true`** in the config
- creates or overwrites the config file when needed

Generated structure:

- `<data_dir>/issuer/iaca-cert.pem`
- `<data_dir>/issuer/iaca-key.pem`
- `<data_dir>/rp/auth-request-key.jwk.json`
- `<data_dir>/rp/auth-response-key.jwk.json`
- `<data_dir>/rp/federation-key.jwk.json`
- `<data_dir>/rp/x5c-cert.pem` — self-signed X.509 certificate chain used in the JWT `x5c` header
- `<data_dir>/trust-anchor/federation-key.jwk.json`
- `<data_dir>/trust-anchor/federation-cert.pem` — self-signed X.509 certificate generated from the federation key
- `<data_dir>/tls-cert.pem` — generated only when `https = true` (self-signed, RSA 2048, 825-day validity, `localhost`)
- `<data_dir>/tls-key.pem` — generated only when `https = true`

Default locations:

- config file: `<project-root>/config.ini`
- data directory: `<project-root>/.itw-conformance-tool`

If a config file already exists and `--force` is not used, `init` reuses the configured `global.data_dir` and does not overwrite existing generated files unless required.

Wallet URL behavior during `init`:

- `init` does not require `global.wallet_provider_backend_url` to be already populated.
- This allows first-time bootstrap (`config.ini` creation) and `init --force` overwrite flows.

### `start`

`start` resolves runtime configuration, validates that the required key material exists, and then delegates service startup to Nx.

Service selection:

- default or `--all`: starts `itw-trust-anchor`, `itw-credential-issuer`, and `itw-relying-party` (each spawned individually via `nx run <project>:serve`)
- `--issuer`: `nx run itw-credential-issuer:serve`
- `--rp`: `nx run itw-relying-party:serve`
- `--trust-anchor`: `nx run itw-trust-anchor:serve`

Before launching Nx, the CLI checks that the required files exist in the resolved data directory. If any required file is missing, the CLI throws and exits before starting the services.

In addition, `start` requires `global.wallet_provider_backend_url` to be present and a valid URL in the resolved config.
If the field is missing, empty, or invalid, startup fails before launching Nx.

When `https = true` in the `[global]` config section, the CLI additionally verifies that `<data_dir>/tls-cert.pem` and `<data_dir>/tls-key.pem` exist. If either is missing, startup fails with an explicit error message.

### `report:list`

`report:list` prints a formatted table of all conformance sessions stored in the configured data directory, sorted by start date (most recent first).

Columns printed: `RUN ID`, `STARTED AT`, `CLOSED AT`, `STATUS`, `CHECKS`.

Optional flag:

- `-c, --config <path>`: load configuration from the given file to resolve the data directory

Example:

```sh
itwct report:list
itwct report:list --config ./ci/config.ini
```

### `test`

`test` launches Vitest on the conformance test matrix profile.

The command:

- spawns a child process running `pnpm vitest run --config vitest.conformance-test.config.mts`
- reads runtime configuration from `config.ini`
- stores conformance sessions in `<data_dir>/itw.db`, so they can later be listed by `report:list` and rendered by `report:create`

`test` requires `global.wallet_provider_backend_url` in config, with the same validation rules used by `start`.

Examples:

```sh
itwct test
itwct test --config ./ci/config.ini
pnpm itw-conformance-tool --args="test"
```

### `report:create`

`report:create` generates a formatted report for a specific conformance run.

```sh
itwct report:create <uuid> [format]
```

- `<uuid>`: the run identifier, as returned by `report:list`
- `[format]`: output format — `html` (default) or `pdf`

The report is saved as `conformance-report-<uuid>.<format>` in the **current working directory**.

Optional flag:

- `-c, --config <path>`: load configuration from the given file to resolve the data directory

Examples:

```sh
itwct report:create 24f860b1-a98b-406b-b6d9-893c3aa12f4c
itwct report:create 24f860b1-a98b-406b-b6d9-893c3aa12f4c pdf
itwct report:create 24f860b1-a98b-406b-b6d9-893c3aa12f4c html --config ./ci/config.ini
```

## Configuration Resolution

The CLI resolves configuration in this order:

1. If `--config` is provided and the file exists, it loads that file.
2. If `--config` is provided but the file does not exist, it falls back to the default runtime configuration.
3. If `--config` is not provided, it looks for `<project-root>/config.ini`.
4. If no config file exists, it falls back to built-in defaults.

## HTTPS Configuration

By default, all services run over plain HTTP. HTTPS can be enabled by setting `https = true` in the `[global]` section of `config.ini`:

```ini
[global]
https = true
; TLS files will be generated at <data_dir>/tls-cert.pem and <data_dir>/tls-key.pem
```

When `https = true`, `itw-conformance-tool init` generates a self-signed certificate valid for `localhost` at `<data_dir>/tls-cert.pem` and `<data_dir>/tls-key.pem`. The certificate uses RSA 2048 and is valid for 825 days.

`start` additionally verifies that those files exist before launching services. If either is missing, startup fails with an explicit error message.

> The self-signed certificate is intended for local development and conformance testing only. Do not use it in production.

## Deferred Batch Credential Issuance

By default, batch (multi-proof) credential requests are issued immediately, just like single-proof requests. Deferred issuance can be enabled by setting `batch_issuance_by_deferred = true` in the `[credential-issuer]` section of `config.ini`:

```ini
[credential-issuer]
batch_issuance_by_deferred = true
```

When `batch_issuance_by_deferred = true`, only requests carrying **multiple proofs** are affected: the Credential Endpoint responds with `202 Accepted` and a `transaction_id`/`interval` (or `lead_time`) instead of the issued credentials. Clients must then poll the Deferred Endpoint (`POST /deferred`) with that `transaction_id` to retrieve the credentials once ready.

Single-proof requests are always issued immediately, regardless of this flag.

## Path Resolution

This CLI treats `~` as the project root, not as the operating system home directory.

Examples, assuming the workspace root is `/workspace/itw-conformance-tool`:

- `~/.itw-conformance-tool` resolves to `/workspace/itw-conformance-tool/.itw-conformance-tool`
- `~/custom-config.ini` resolves to `/workspace/itw-conformance-tool/custom-config.ini`

Quoted paths are also supported for config arguments.

## Passing Arguments Through the Root Script

The root `pnpm itw-conformance-tool` script delegates to the Nx `run` target for the CLI project. To pass runtime CLI arguments, use the `--args="..."` form.

Examples:

- `pnpm itw-conformance-tool --args="init"`
- `pnpm itw-conformance-tool --args="start --config ./ci/config.ini --all"`
- `pnpm itw-conformance-tool --args="start --config ./ci/config.ini --issuer"`
- `pnpm itw-conformance-tool --args="test --config ./ci/config.ini"`
- `pnpm itw-conformance-tool --args="report:list --config ./ci/config.ini"`
- `pnpm itw-conformance-tool --args="report:create <uuid> html --config ./ci/config.ini"`

This format is required because Nx forwards the CLI payload through its own `--args` option.
