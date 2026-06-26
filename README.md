# ITW Conformance Tool

An open-source conformance testing suite to verify that Wallet Solution implementations comply with the [Italian IT Wallet ecosystem](https://italia.github.io/eid-wallet-it-docs/versione-corrente/en).

## Overview

The tool operates by running a Credential Issuer or Relying Party instance that executes complete **OpenID4VCI** and **OpenID4VP** flows against a Wallet Solution. It observes the protocol exchange, produces **pass/fail verdicts** for each requirement defined in the Technical Rules, and generates both machine-readable and human-readable reports — each verdict traceable back to the specific section of the reference specification.

## Key Goals

- ✅ **Automate Conformance Testing**: Run tests defined by the official Italian technical rules to ensure compliance.
- ✅ **Improve Development Cycles**: Increase implementation quality and efficiency by catching errors early.
- ✅ **Support the Ecosystem**: Provide a reliable tool for both developers integrating with the IT Wallet and regulatory bodies certifying the solutions.

## Key Features

- 💻 **Headless CLI**: A powerful command-line interface perfect for server and development environments.
- 🌐 **Open Source**: Fully open-source and ready for community contributions.
- 📄 **Detailed Reports**: Generates clear reports on test outcomes (success, failure, not applicable) to quickly identify issues.
- 🐛 **Verbose Debugging**: Offers advanced technical output to simplify debugging and integration.
- 👥 **For Integrators & Certifiers**: Built to serve both entities building solutions and those who verify them.
- 🔒 **Optional HTTPS (CLI)**: `init` can generate a self-signed TLS certificate/key and `start` can validate their presence when HTTPS is enabled.

## Prerequisites

| Tool    | Version                |
| ------- | ---------------------- |
| Node.js | see [`.nvmrc`](.nvmrc) |
| pnpm    | `10.30.3`              |

## Getting Started

Install dependencies:

```bash
pnpm install
```

Build all packages:

```bash
pnpm build
```

Run type-checking, linting, and tests:

```bash
pnpm typecheck
pnpm lint
pnpm test
```

Start the full conformance stack via CLI (recommended):

```bash
# First run: initialize data directory, keys, and config template
pnpm itw-conformance-tool:init

# Start both services
pnpm itw-conformance-tool:start

# Run CLI-driven conformance tests
pnpm itw-conformance-tool:test
```

Or install the CLI globally and run it directly:

```bash
pnpm nx build itw-conformance-cli
cd apps/cli && pnpm link --global

itw-conformance-tool init
itw-conformance-tool start --all
```

### Configuration

The generated `config.ini` also supports the Wallet Provider backend URL used by conformance tests:

```ini
; Wallet provider backend URL (used for conformance tests)
; Default: https://127.0.0.1:8080
wallet_provider_backend_url = https://127.0.0.1:8080
```

### Conformance Test Profiles

Conformance suites are now split into root-level Vitest profiles with dedicated configs:

- `vitest.issuance.config.mts` -> issuance conformance
- `vitest.presentation.config.mts` -> presentation conformance
- `vitest.wallet-provider-backend.config.mts` -> wallet provider backend matrix conformance

Run them from the workspace root:

```bash
pnpm test:issuance
pnpm test:presentation
pnpm test:wallet
```

The wallet provider backend suite executes the matrix spec in `packages/conformance/src/tests/matrix/wallet-provider-backend.test.ts`.

### Runtime Environment Overrides (Conformance)

For conformance runs, the following environment variables are supported:

 - `ITW_CT_DATA_DIR`: SQLite/report data directory used by the Vitest conformance reporter (required when running `pnpm test:*` profiles)
 - `ITW_CT_WALLET_PROVIDER_BACKEND_URL`: overrides `global.wallet_provider_backend_url` for wallet backend matrix tests (required by `pnpm test:wallet` unless you run via the CLI, which exports it from `config.ini`)

`ITW_CT_CONFIG_FILE` is used by the runnable apps (issuer/RP) to choose the config file, but the wallet backend matrix test does not currently read it.

### External Wallet Provider Conformance Tests

The Wallet Provider conformance suite is opt-in.

- Default run (`pnpm test`): standard project tests via Nx targets.
- Explicit run (wallet backend profile):

```bash
pnpm test:wallet
```

Or via CLI command mode:

```bash
pnpm itw-conformance-tool --args="test:wallet --config ./config.ini"
```

Conformance checks are persisted in SQLite during the Vitest run and are available to `report:list` and `report:create`.

Once a conformance flow has completed, generate a report:

```bash
# List all recorded runs
itwct report:list

# Generate a report (html or pdf)
itwct report:create <run_id> [html|pdf]
```

> See [apps/cli/README.md](apps/cli/README.md) for full CLI usage.

## Commands

All commands are run from the workspace root. Root-level scripts delegate to **Nx** where applicable and operate on projects that expose the requested target.

### Root-level `pnpm` scripts

| Command                                  | Description                                                                                                                          |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `pnpm build`                             | Build all projects with a `build` target                                                                                             |
| `pnpm start`                             | Serve all runnable apps with a `serve` target                                                                                        |
| `pnpm itw-conformance-tool`              | Run the local conformance CLI (`init`, `start`, `test:wallet`, `test:issuance`, `test:presentation`, `report:list`, `report:create`) |
| `pnpm itw-conformance-tool:init`         | Initialize local data directory and config template                                                                                  |
| `pnpm itw-conformance-tool:start`        | Start both services via CLI (`start --all`)                                                                                          |
| `pnpm itw-conformance-tool:start:issuer` | Start only the issuer service via CLI                                                                                                |
| `pnpm itw-conformance-tool:start:rp`     | Start only the relying-party service via CLI                                                                                         |
| `pnpm issuer`                            | Serve `itw-credential-issuer`                                                                                                        |
| `pnpm rp`                                | Serve `itw-relying-party`                                                                                                            |
| `pnpm test`                              | Run Vitest for projects with a `test` target                                                                                         |
| `pnpm test:issuance`                     | Run issuance conformance profile (`vitest.issuance.config.mts`)                                                                      |
| `pnpm test:presentation`                 | Run presentation conformance profile (`vitest.presentation.config.mts`)                                                              |
| `pnpm test:wallet`                       | Run wallet provider backend matrix profile (`vitest.wallet-provider-backend.config.mts`)                                             |
| `pnpm typecheck`                         | Type-check projects with a `typecheck` target                                                                                        |
| `pnpm lint`                              | Lint projects with a `lint` target                                                                                                   |
| `pnpm format`                            | Format JavaScript, TypeScript, JSON, and Markdown files with Prettier                                                                |
| `pnpm clean`                             | Run project clean targets, then remove root `node_modules` and `.nx`                                                                 |
| `pnpm pre-commit`                        | Run lint and type-check on affected projects                                                                                         |

### Targeting a single project with Nx

Use `pnpm nx run <project>:<target>` to execute a target on a specific project:

```bash
# Build only the credential issuer app
pnpm nx run itw-credential-issuer:build

# Run credential issuer tests
pnpm nx run itw-credential-issuer:test

# Serve the credential issuer locally
pnpm nx run itw-credential-issuer:serve

# Serve the relying party locally
pnpm nx run itw-relying-party:serve
```

### Headless Conformance CLI

All CLI details are documented in [apps/cli/README.md](apps/cli/README.md).

Current workspace projects include:

| Project                          | Path                         | Common targets                                |
| -------------------------------- | ---------------------------- | --------------------------------------------- |
| `itw-credential-issuer`          | `apps/itw-credential-issuer` | `build`, `serve`, `test`, `typecheck`, `lint` |
| `itw-relying-party`              | `apps/itw-relying-party`     | `build`, `serve`, `test`, `typecheck`, `lint` |
| `itw-conformance-cli`            | `apps/cli`                   | `build`, `run`, `test`, `typecheck`, `lint`   |
| `@itw-conformance-tool/config`   | `packages/config`            | `build`, `test`, `typecheck`, `lint`          |
| `@itw-conformance-tool/database` | `packages/database`          | `build`, `test`, `typecheck`, `lint`          |
| `@itw-conformance-tool/issuer`   | `packages/issuer`            | `build`, `typecheck`, `lint`                  |
| `@itw-conformance-tool/rp`       | `packages/rp`                | `build`, `test`, `typecheck`, `lint`          |
| `@itw-conformance-tool/logger`   | `packages/logger`            | `build`, `typecheck`, `lint`                  |

### Nx cache

Nx caches build and test outputs automatically. To force a clean run without cache, append `--skip-nx-cache`:

```bash
pnpm nx run itw-credential-issuer:build --skip-nx-cache
```

To wipe the full Nx cache:

```bash
pnpm clean
```

## Repository Structure

This is a **pnpm + Nx monorepo**.

```
itw-conformance-tool/
├── apps/          # Runnable applications (test runner, CLI, …)
├── packages/      # Shared libraries and conformance modules
├── nx.json        # Nx workspace configuration
└── pnpm-workspace.yaml
```

## Core Dependencies

The suite is built on PagoPA's own wallet protocol libraries:

| Package                            | Purpose                                   |
| ---------------------------------- | ----------------------------------------- |
| `@pagopa/io-wallet-oid4vci`        | OpenID for Verifiable Credential Issuance |
| `@pagopa/io-wallet-oid4vp`         | OpenID for Verifiable Presentations       |
| `@pagopa/io-wallet-oauth2`         | OAuth 2.0 flows                           |
| `@pagopa/io-wallet-oid-federation` | OpenID Federation / Trust Chain           |
| `@pagopa/io-wallet-utils`          | Shared utilities                          |

## Specifications

- [IT-Wallet Technical Rules](https://italia.github.io/eudi-wallet-it-docs/)
- [Architecture Reference Framework (ARF)](https://eu-digital-identity-wallet.github.io/eudi-doc-architecture-and-reference-framework/)
- [OpenID4VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
- [OpenID4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)

## Git Hooks

This repository uses [Husky](https://typicode.github.io/husky/) to run automated checks before commits are recorded.

| Hook         | Command           | What it does                                          |
| ------------ | ----------------- | ----------------------------------------------------- |
| `pre-commit` | `pnpm pre-commit` | Runs lint and type-check on Nx-affected projects only |

Hooks are installed automatically during `pnpm install` via the `prepare` lifecycle script. No manual setup is required.

## Contributing

Contributions are welcome. Please open an issue or a pull request. See [CODEOWNERS](CODEOWNERS) for maintainers.
