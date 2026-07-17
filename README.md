# ITW Conformance Tool

An open-source conformance testing suite to verify that Wallet Solution implementations comply with the [Italian IT Wallet ecosystem](https://italia.github.io/eid-wallet-it-docs/versione-corrente/en).

---

## Overview

The tool operates by running a Credential Issuer or Relying Party instance that executes complete **OpenID4VCI** and **OpenID4VP** flows against a Wallet Solution. It observes the protocol exchange, produces **pass/fail verdicts** for each requirement defined in the Technical Rules, and generates both machine-readable and human-readable reports — each verdict traceable back to the specific section of the reference specification.

---

## Key Goals

- ✅ **Automate Conformance Testing**: Run tests defined by the official Italian technical rules to ensure compliance.
- ✅ **Improve Development Cycles**: Increase implementation quality and efficiency by catching errors early.
- ✅ **Support the Ecosystem**: Provide a reliable tool for both developers integrating with the IT Wallet and regulatory bodies certifying the solutions.

---

## Key Features

- 💻 **Headless CLI**: A powerful command-line interface perfect for server and development environments.
- 🌐 **Open Source**: Fully open-source and ready for community contributions.
- 📄 **Detailed Reports**: Generates clear reports on test outcomes (success, failure, not applicable) to quickly identify issues.
- 🐛 **Verbose Debugging**: Offers advanced technical output to simplify debugging and integration.
- 👥 **For Integrators & Certifiers**: Built to serve both entities building solutions and those who verify them.
- 🔒 **Optional HTTPS (CLI)**: `init` can generate a self-signed TLS certificate/key and `start` can validate their presence when HTTPS is enabled.

---

## Prerequisites

| Tool    | Version                |
| ------- | ---------------------- |
| Node.js | see [`.nvmrc`](.nvmrc) |
| pnpm    | `10.30.3`              |

---

## Getting Started

Install dependencies:

```bash
pnpm install
```

Build all the packages:

```bash
pnpm build
```

If you want to run the CLI from any directory, link the CLI package globally:

```bash
# From /apps/cli
pnpm link --global
```

After that, you can use `itwct` or `itw-conformance-tool` from anywhere. If you prefer to stay inside the workspace, run:

```bash
pnpm itw-conformance-tool
```

Initialize the local environment, start the services, and run the tests:

```bash
# First run: create the data directory, keys, and config template
pnpm itw-conformance-tool:init
# or, if you link the CLI globally
itwct init
```

`itwct init` is idempotent by default: if `config.ini` or any key/certificate file already exists, it is left untouched. Pass `--force` to overwrite everything:

```bash
itwct init --force
```

With `--force`, `init`:

- Overwrites `config.ini` with a fresh template
- Re-creates the data directory
- Regenerates all keys and certificates (IACA, issuer signing keys, RP keys, x5c certificate, and, if HTTPS is enabled, the TLS certificate/key)

> ⚠ Using `--force` is destructive: existing keys will be permanently replaced. Only use it when you deliberately want a clean environment.

```bash
# Start both services
pnpm itw-conformance-tool:start
# or, if you link the CLI globally
itwct start
```

---

## Configuration

### config.ini Structure

The `config.ini` file contains global settings for the conformance tool. Below is the structure with available options:

```ini
[global]
; Local directory for keys, certificates, and generated data
; Default: ~/.itw-conformance-tool
data_dir = ~/.itw-conformance-tool

; Logging level: debug | info | warn | error
; Default: info
log_level = info

; Enable HTTPS mode (CLI generates/checks local TLS cert/key and forwards ITW_CT_HTTPS) (true | false)
; Default: true
https = true

; Mandatory Wallet Provider Backend URL (used for conformance tests)
wallet_provider_backend_url =
```

Behavior notes:

- All values in `[global]` are optional except `wallet_provider_backend_url`, which is **mandatory** for `start` and `test` commands.
- If `wallet_provider_backend_url` is missing, empty, or not a valid URL, both `itwct start` and `itwct test` fail with an explicit configuration error.
- `itwct init` generates a fresh `config.ini` from a template, so you can bootstrap first and fill in values before running services/tests.

### Data Directory Structure

When you run `itwct init`, the tool creates the following directory structure under `data_dir`:

```
<data_dir>/
├── itw.db                    # SQLite database (conformance runs, checksums, session data)
├── issuer/
│   ├── iaca-cert.pem         # Mock IACA certificate
│   ├── iaca-key.pem          # Mock IACA private key
│   └── signing-keys.jwks.json # Issuer signing keys (JWKS format)
├── rp/
│   ├── auth-request-key.jwk.json  # RP authentication request key
│   ├── auth-response-key.jwk.json # RP authentication response key
│   ├── federation-key.jwk.json    # RP OpenID Federation key
│   └── x5c-cert.pem               # RP x5c certificate (self-signed)
├── tls-cert.pem              # TLS certificate (if https=true)
├── tls-key.pem               # TLS private key (if https=true)
└── logs/
    └── *.log                 # Application logs
```

**Key files explained:**

| File                            | Purpose                                                                             |
| ------------------------------- | ----------------------------------------------------------------------------------- |
| `itw.db`                        | SQLite database that stores conformance run results, check outcomes, and audit logs |
| `issuer/iaca-cert.pem`          | Mock Italian Authorities Certification Authority (IACA) certificate for testing     |
| `issuer/signing-keys.jwks.json` | JSON Web Key Set used by the Credential Issuer to sign credentials                  |
| `rp/*.jwk.json`                 | RP keys for authorization requests, responses, and OpenID Federation trust chain    |
| `rp/x5c-cert.pem`               | X.509 certificate included in the RP's authentication proofs                        |
| `tls-cert.pem` / `tls-key.pem`  | TLS certificates for HTTPS communication (created only if `https=true`)             |

All keys and certificates are generated during `itwct init`. Use `itwct init --force` to regenerate them.

---

## Conformance Tests

The conformance test suite runs the matrix spec in `packages/conformance/src/tests/matrix/**/*.test.ts`. Before running tests, ensure the services are initialized and started.

### Running Conformance Tests

You can run conformance tests with:

```bash
# Run the conformance matrix
pnpm itw-conformance-tool:test
# or, if the CLI is linked globally
itwct test
```

> Execute the conformance test matrix and record results to the database.
>
> Note: `wallet_provider_backend_url` must be set in `config.ini` before running tests. See [Configuration](#configuration) for details.

### Generating Reports

When a conformance flow completes, you can list and generate reports:

**List all recorded runs:**

```bash
itwct report:list
```

The command prints a formatted table of all recorded conformance runs:

```
RUN ID                                    STARTED AT                  CLOSED AT                   STATUS      CHECKS
03a6aa68-2bf5-439a-b3e9-5c257e88bc89      2026-07-17T10:00:00.000Z    2026-07-17T10:05:32.000Z    closed      42
```

Each row contains:

| Column       | Description                                                 |
| ------------ | ----------------------------------------------------------- |
| `RUN ID`     | UUID of the conformance run (use for `report:create`)       |
| `STARTED AT` | ISO timestamp when the run started                          |
| `CLOSED AT`  | ISO timestamp when the run ended (`-` if still in progress) |
| `STATUS`     | Current run state (e.g. `closed`)                           |
| `CHECKS`     | Total number of checks recorded in that run                 |

**Generate an HTML or PDF report:**

```bash
itwct report:create <run-id> [html|pdf]

# Example
itwct report:create 03a6aa68-2bf5-439a-b3e9-5c257e88bc89 html
```

The report is written to the current working directory as `conformance-report-<run-id>.<format>`.

---

### Unit Tests

Running `pnpm test` executes the **unit tests** of all workspace projects via `nx run-many -t test`. This does not run conformance tests.

```bash
pnpm test
```

---

## Commands

All commands are run from the workspace root. Root-level scripts delegate to **Nx** where applicable and operate on projects that expose the requested target.

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

### Nx cache

Nx caches build and test outputs automatically. To force a clean run without cache, append `--skip-nx-cache`:

```bash
pnpm nx run itw-credential-issuer:build --skip-nx-cache
```

To wipe the full Nx cache:

```bash
pnpm clean
```

### Headless Conformance CLI

All CLI details are documented in [apps/cli/README.md](apps/cli/README.md).

#### Workspace projects

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
