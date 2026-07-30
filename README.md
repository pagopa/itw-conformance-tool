# IT Wallet Conformance Tool

An open-source conformance suite for exercising a Wallet Solution against the [Italian IT Wallet technical documentation](https://italia.github.io/eid-wallet-it-docs/versione-corrente/en). It provides local OpenID4VCI and OpenID4VP counterparties, protocol-event collection, requirement verdicts, and shareable HTML/PDF reports.

Use it to validate a Wallet Provider Backend or Wallet Instance during development, before integration, or as evidence for a conformance assessment.

> [!IMPORTANT]
> This project is a **local conformance environment**, not a production Credential Issuer, Relying Party, or Trust Anchor. It generates local key material and uses locally generated TLS certificates. Do not expose it to untrusted networks or reuse generated keys outside testing.

## What it does

The tool runs the following local services and observes the protocol traffic they produce:

| Component           | Role                                                                                           | Main protocols                |
| ------------------- | ---------------------------------------------------------------------------------------------- | ----------------------------- |
| Credential Issuer   | Issues representative IT Wallet credentials and exposes issuer federation metadata             | OpenID4VCI, OpenID Federation |
| Relying Party       | Creates and validates presentation requests and responses                                      | OpenID4VP, OpenID Federation  |
| Trust Anchor        | Serves federation trust-chain material                                                         | OpenID Federation             |
| Wallet Provider     | Publishes local Wallet Provider federation metadata for Wallet Instance infrastructure         | OpenID Federation             |
| CLI (`itwct`)       | Initializes local state, orchestrates matrix runs, and produces reports                        | —                             |
| Conformance package | Defines scenarios, captures/redacts events and artifacts, evaluates rules, and renders reports | —                             |

A conformance run starts only the local services required by the selected category, gives the tester the required wallet action and QR/deep-link payload when applicable, captures the observed exchange, and stores the result in a local SQLite database. Every completed run can be rendered later as a report.

## Local federation endpoints

The tool starts local HTTPS services that publish the OpenID Federation metadata required by the selected conformance category. The Trust Anchor is the root of trust for the local Credential Issuer, Relying Party, and Wallet Provider helper. The Wallet Provider Backend under test remains external and is never replaced by the local helper.

| Service                | Default listening URL    | Default entity ID            | Purpose                                                                             |
| ---------------------- | ------------------------ | ---------------------------- | ----------------------------------------------------------------------------------- |
| Trust Anchor           | `https://127.0.0.1:3001` | `https://localhost:3001`     | Publishes the Trust Anchor entity configuration and resolves federation statements. |
| Credential Issuer      | `https://127.0.0.1:3000` | Configured from its base URL | Issues representative credentials and publishes issuer federation metadata.         |
| Relying Party          | `https://127.0.0.1:3002` | `https://127.0.0.1:3002`     | Creates presentation requests and publishes Relying Party federation metadata.      |
| Wallet Provider helper | `https://127.0.0.1:3003` | `https://127.0.0.1:3003`     | Publishes Wallet Provider entity configuration for Wallet Instance scenarios.       |

### Local DNS for named endpoints

The generated configuration uses `127.0.0.1` and `localhost`, so it requires no DNS setup. If the Wallet Solution requires stable named local endpoints, each configured hostname must resolve to `127.0.0.1` on the machine running the services and tests. Add the names to the system hosts file, for example:

127.0.0.1 trust-anchor.wct.example.org credential-issuer.wct.example.org relying-party.wct.example.org wallet-provider.wct.example.org

Use the same hostname and explicit local port consistently in the corresponding `url`, `entity_id`, and `trust_anchor_url` settings. The services bind to the host and port in each `url`; they do not listen on HTTPS port 443 by default. For example:

```ini
[credential-issuer]
url = https://credential-issuer.wct.example.org:3000

[relying-party]
url = https://relying-party.wct.example.org:3002

[trust-anchor]
url = https://trust-anchor.wct.example.org:3001
```

The generated TLS certificate is valid only for `localhost`, `127.0.0.1`, and `::1`. Named endpoints therefore require the Wallet Solution's explicitly test-only unsafe-TLS mode; they are not suitable for production use.

## Prerequisites

| Requirement                                    | Supported version / purpose                                                       |
| ---------------------------------------------- | --------------------------------------------------------------------------------- |
| Node.js                                        | **22.x** (see [`.nvmrc`](.nvmrc))                                                 |
| pnpm                                           | **11.13.1**, pinned by [`package.json`](package.json)                             |
| Git                                            | Clone the source repository                                                       |
| A reachable Wallet Provider Backend            | Required for meaningful conformance runs; configure its HTTPS URL in `config.ini` |
| A desktop wallet or Wallet Instance under test | Required for scenarios that require a tester action                               |

On Linux, interactive scenarios can copy deep links to the clipboard when `wl-copy`, `xclip`, or `xsel` is installed. macOS and Windows use their native clipboard tools.

## Quick start: run a conformance category

Run the commands from the repository root.

```sh
# 1. Install the pinned package manager and dependencies.
corepack enable
corepack prepare pnpm@11.13.1 --activate
pnpm install --frozen-lockfile

# 2. Create config.ini and local keys/certificates under .itw-conformance-tool/.
pnpm run init

# 3. Edit config.ini. At minimum, replace the remote Wallet Provider Backend URL.
#    [wallet-provider]
#    url = https://wallet-provider-backend.example.com
#    local_url = https://127.0.0.1:3003
# 4. Execute one category. The CLI builds what it needs and manages local services.
pnpm test:issuance
```

During an interactive scenario, follow the terminal instructions: use the displayed QR code/deep link with the Wallet Solution, complete the requested wallet operation, and leave the process running until it records a verdict. Issuance scenarios that use a Credential Offer also open the local Credential Offer page in the default browser for each scenario, using that scenario's current `issuer_state`.

> [!TIP]
> The generated `config.ini` and `.itw-conformance-tool/` directory contain environment-specific settings, private keys, certificates, a local database, and captured data. Both are ignored by Git. Never commit or share them as a default troubleshooting artifact.

## End-user guide

### 1. Initialize or refresh local state

```sh
pnpm run init
# or, explicitly overwrite generated configuration and key material
pnpm run init:force
```

`init` creates `config.ini` if it does not already exist, creates the configured data directory, and provisions the local key and certificate material used by the services:

```text
.itw-conformance-tool/
├── itw.db                         # conformance sessions, events, and artifacts
├── issuer/
│   ├── jwks.json                  # issuer signing/encryption keys
│   ├── jwks-intermediate.json     # issuer intermediate-CA key
│   ├── intermediate-cert.pem      # issuer intermediate certificate
│   └── cert.pem                   # issuer leaf certificate chain
├── rp/
│   ├── jwks.json                  # relying-party keys
│   └── cert.pem                   # relying-party certificate
├── trust-anchor/
│   ├── federation-key.jwk.json
│   └── federation-cert.pem
└── wallet-provider/
    ├── jwks.json                  # Wallet Provider attestation signing key
    ├── jwks-intermediate.json     # Wallet Provider intermediate-CA key
    ├── intermediate-cert.pem      # Wallet Provider intermediate certificate
    └── cert.pem                   # Wallet Provider leaf certificate
```

The Credential Issuer and Wallet Provider both use the local Trust Anchor as their root. For the Wallet Provider, `cert.pem` is the Wallet Instance Attestation leaf certificate, `intermediate-cert.pem` is signed by `trust-anchor/federation-cert.pem`, and the attestation JWT `x5c` header contains `[leaf, intermediate]` without duplicating the root Trust Anchor certificate.

Without `--force`, existing generated files are retained unless a dependent artifact is missing. Use `--force` only when rotating all local test material is intended; it rotates the Trust Anchor, issuer, and Wallet Provider chains and invalidates state that depends on the replaced keys.

Each running service also creates an in-memory, localhost TLS configuration. The endpoints in the default configuration use `https://127.0.0.1` and `https://localhost`; their certificates are not trusted by default, so use a Wallet Solution's explicitly test-only unsafe-TLS mode where supported.

### 2. Configure the environment

`config.ini` is always read from the **current working directory**. The CLI creates it in the repository root when invoked there. Relative `data_dir` values resolve from that directory; `~` and `~/…` resolve from the operating-system home directory.

Start from the template generated by `pnpm init`. The following table documents every supported setting.

| Section               | Key                               | Required / accepted values                           | Effect                                                                                                                                                 |
| --------------------- | --------------------------------- | ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `[global]`            | `organization_name`               | Non-empty text                                       | Identifies the organization in reports.                                                                                                                |
| `[global]`            | `data_dir`                        | Writable path                                        | Stores generated keys, certificates, SQLite data, and artifacts. Default: `.itw-conformance-tool`.                                                     |
| `[global]`            | `log_level`                       | `debug`, `info`, `warn`, `error`                     | Controls application log verbosity.                                                                                                                    |
| `[global]`            | `trust_anchor_certificate`        | Empty, base64 DER, or quoted PEM text                | Production Trust Anchor X.509 certificate obtained out-of-band by the Wallet Instance.                                                                 |
| `[wallet]`            | `wallet_name`                     | Non-empty text                                       | Identifies the Wallet Solution in reports.                                                                                                             |
| `[wallet]`            | `wallet_version`                  | Non-empty text                                       | Identifies the Wallet Solution version in reports.                                                                                                     |
| `[wallet-provider]`   | `url`                             | Absolute HTTPS URL                                   | Remote Wallet Provider Backend under test. Replace the generated placeholder before running the `wallet-provider` matrix.                              |
| `[wallet-provider]`   | `local_url`                       | Absolute HTTPS URL                                   | Local Wallet Provider helper base URL and Entity ID. The CLI starts it for Wallet Instance and all-category runs. Default: `https://127.0.0.1:3003`.   |
| `[credential-issuer]` | `url`                             | Absolute HTTPS URL                                   | Base URL on which the local Credential Issuer listens.                                                                                                 |
| `[credential-issuer]` | `auth_flow`                       | `direct`, `l2plus`, `l3`                             | Issuer authorization flow exercised by the local issuer.                                                                                               |
| `[credential-issuer]` | `credential_types`                | Comma-separated `pid`, `mdl`, `badge`, and/or `eaa`  | Enables representative credential types exposed by the issuer.                                                                                         |
| `[credential-issuer]` | `credential_identifiers`          | Empty or comma-separated supported configuration IDs | Enables the issuer's `/credential-offer` QR/deep-link page. IDs must be unique and match its published `credential_configurations_supported` metadata. |
| `[credential-issuer]` | `batch_issuance_by_deferred`      | `true` or `false`                                    | Makes multi-proof batch requests return a deferred transaction. Single-proof requests remain immediate.                                                |
| `[credential-issuer]` | `trusted_wallet_provider_issuers` | Comma-separated absolute HTTPS URLs                  | Allowlist used to verify issuer claims in credential proof key attestations. Matching is exact; paths, ports, and trailing slashes matter.             |
| `[credential-issuer]` | `trust_anchor_url`                | Absolute HTTPS URL                                   | Trust Anchor entity ID referenced by issuer federation metadata.                                                                                       |
| `[relying-party]`     | `url`                             | Absolute HTTPS URL                                   | Base URL on which the local Relying Party listens.                                                                                                     |
| `[relying-party]`     | `entity_id`                       | Absolute HTTPS URL                                   | Relying Party OpenID Federation leaf entity ID.                                                                                                        |
| `[relying-party]`     | `trust_anchor_url`                | Absolute HTTPS URL                                   | Trust Anchor entity ID used for federation validation and authority hints.                                                                             |
| `[trust-anchor]`      | `url`                             | Absolute HTTPS URL                                   | Base URL on which the local Trust Anchor listens.                                                                                                      |
| `[trust-anchor]`      | `entity_id`                       | Absolute HTTPS URL                                   | Trust Anchor OpenID Federation entity ID.                                                                                                              |

Example minimal customization:

```ini
[global]
organization_name = Example Wallet Provider
log_level = info

[wallet]
wallet_name = Example Wallet
wallet_version = 1.0.0

[wallet-provider]
# Remote Wallet Provider Backend under test
url = https://wallet-provider.example.test
# Local helper started only for Wallet Instance infrastructure
local_url = https://127.0.0.1:3003
```

> [!CAUTION]
> The default `trusted_wallet_provider_issuers` values are examples. Replace them with the exact entity identifiers trusted in your test environment. Do not use a broad production allowlist merely to make a test pass.

### 3. Run conformance tests

The CLI command is `itwct`; the root scripts below are the recommended way to invoke it from a checkout.

| Command                     | Runs                                            | Local services managed by the CLI                               |
| --------------------------- | ----------------------------------------------- | --------------------------------------------------------------- |
| `pnpm test:all`             | Every matrix category, in a deterministic order | Trust Anchor, Credential Issuer, Relying Party, Wallet Provider |
| `pnpm test:issuance`        | Credential issuance scenarios                   | Trust Anchor, Credential Issuer                                 |
| `pnpm test:presentation`    | Credential presentation scenarios               | Trust Anchor, Relying Party                                     |
| `pnpm test:wallet-instance` | Wallet Instance scenarios                       | Trust Anchor, Credential Issuer, Relying Party, Wallet Provider |
| `pnpm test:wallet-provider` | Remote Wallet Provider Backend scenarios        | None                                                            |

Equivalent CLI invocations:

```sh
pnpm nx run itw-conformance-cli:run --args test
pnpm nx run itw-conformance-cli:run --args="test issuance"
pnpm nx run itw-conformance-cli:run --args="test presentation"
pnpm nx run itw-conformance-cli:run --args="test wallet-instance"
pnpm nx run itw-conformance-cli:run --args="test wallet-provider"
```

The test command owns its children: it starts the minimal service set, waits for service readiness, runs the selected sequential Vitest matrix, and stops services on success, failure, interruption, or timeout. Do **not** separately start the same local services for a CLI-managed test run.

The presentation category runs one interactive flow per scenario: a happy path, a cross-device variant that retrieves the Request Object with a POST, and one negative flow per wallet-side validation (Trust Chain, Trust Marks, `request_uri`, Request Object signature and `client_id` consistency, malformed Request Object, `response_uri`, `redirect_uri`). To run a subset — for example a single scenario while iterating — set `ITWCT_PRESENTATION_SCENARIO_IDS` to a comma-separated list of scenario IDs:

```sh
ITWCT_PRESENTATION_SCENARIO_IDS=WP_RP_HAPPY,WP_085 pnpm test:presentation
```

Each negative flow serves one deliberately defective artifact from the local Relying Party and passes when the wallet stops instead of continuing; see [docs/rp-fault-profile-lifecycle.md](docs/rp-fault-profile-lifecycle.md).

Test results are printed to the terminal and stored in `<data_dir>/itw.db`. A failed check is evidence for investigation, not a claim that a production implementation is certified or non-compliant in all circumstances; review the technical report and captured protocol evidence.

### 4. Inspect and export reports

List local runs:

```sh
pnpm nx run itw-conformance-cli:run --args="report list"
# `report ls` is an alias
```

Render a run ID from that list—or the newest run—to an HTML or PDF file in the current directory:

```sh
# All views, HTML
pnpm nx run itw-conformance-cli:run --args="report create latest html"

# Technical evidence only, PDF
pnpm nx run itw-conformance-cli:run --args="report create <run-id> pdf --view technical"

# Executive summary only, HTML
pnpm nx run itw-conformance-cli:run --args="report create <run-id> html --view executive"
```

`report create` accepts `html` and `pdf` formats. Its `--view` option accepts `both` (default), `executive`, or `technical`. Output names follow `conformance-report-<run-id>.<format>`.

### 5. Use the local services while integrating

For manual debugging, first initialize the workspace, then run one service directly through Nx:

```sh
pnpm run init
pnpm nx run itw-credential-issuer:serve
pnpm nx run itw-relying-party:serve
pnpm nx run itw-trust-anchor:serve
pnpm nx run itw-wallet-provider:serve

# Or run every project with a serve target.
pnpm start
```

The default endpoints are:

| Service                | Default URL              | Useful endpoint                                             |
| ---------------------- | ------------------------ | ----------------------------------------------------------- |
| Credential Issuer      | `https://127.0.0.1:3000` | `GET /health`; interactive API documentation at `/api/docs` |
| Trust Anchor           | `https://localhost:3001` | `GET /health`; interactive API documentation at `/api/docs` |
| Relying Party          | `https://127.0.0.1:3002` | `GET /health`; interactive API documentation at `/api/docs` |
| Wallet Provider helper | `https://127.0.0.1:3003` | `GET /health`; `GET /.well-known/openid-federation`         |

If `credential_identifiers` is populated, the Credential Issuer serves `https://127.0.0.1:3000/credential-offer` as a manual static Credential Offer page with a scannable QR code and copyable URI. The issuer does not open this page automatically on startup; CLI-managed issuance tests open a scenario-specific page when each Credential Offer stimulus is shown.

## CLI reference

Build the CLI before installing it globally:

```sh
pnpm nx build itw-conformance-cli
pnpm add --global ./apps/cli

itwct --help
itwct init
itwct test issuance
itwct report list
itwct report create latest html --view both
```

The supported commands are:

| Command                                                                                | Purpose                                                                                        |
| -------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `itwct init [--force]`                                                                 | Create or refresh `config.ini` and local cryptographic material.                               |
| `itwct test [category]`                                                                | Run all categories or one of `issuance`, `presentation`, `wallet-instance`, `wallet-provider`. |
| `itwct report list` / `itwct report ls`                                                | List recorded conformance runs.                                                                |
| `itwct report create <run-id\|latest> <html\|pdf> [--view both\|executive\|technical]` | Generate an exported report.                                                                   |
| `itwct --help`                                                                         | Show command help.                                                                             |

Remove the global package with:

```sh
pnpm remove --global itw-conformance-cli
```

## Developer guide

### Workspace architecture

This repository is a pnpm + Nx TypeScript monorepo.

```text
apps/
├── cli/ # itwct command and service supervision
├── itw-credential-issuer/ # Fastify OpenID4VCI service
├── itw-relying-party/ # Fastify OpenID4VP service
├── itw-trust-anchor/ # Fastify federation trust-anchor service
└── itw-wallet-provider/ # Fastify local Wallet Provider federation helper
packages/
├── config/ # INI parsing, defaults, and validation
├── conformance/ # scenarios, events, artifacts, verdicts, reports
├── crypto/ # local crypto, certificates, and TLS helpers
├── database/ # SQLite client and persistence
├── ipc/ # CLI-to-service lifecycle signaling
├── logger/ # shared structured logger
└── utils/ # shared types and utilities
```

The conformance package is the core testing pipeline:

1. Matrix tests select scenario definitions for the requested category.
2. The runner provides tester instructions and a wallet stimulus such as a QR/deep link.
3. Fastify instrumentation records relevant protocol events and redacts supported sensitive fields before persistence.
4. The verdict engine evaluates observed events and artifacts against scenario rules.
5. Session data is stored locally and rendered by terminal, HTML, and PDF reporters.

### Install and build

```sh
corepack enable
corepack prepare pnpm@11.13.1 --activate
pnpm install --frozen-lockfile
pnpm build
```

Nx targets can be invoked per project when iterating:

```sh
pnpm nx run itw-conformance-cli:build
pnpm nx run itw-conformance-cli:test
pnpm nx run itw-credential-issuer:serve
pnpm nx run itw-relying-party:serve
pnpm nx run itw-trust-anchor:serve
```

### Quality checks

```sh
# All workspace projects
pnpm test
pnpm typecheck
pnpm lint
pnpm format:check

# Apply formatting
pnpm format
```

`pnpm test` runs the ordinary Vitest unit-test targets; it does not run external Wallet Solution conformance traffic. The pre-commit command checks formatting and runs lint/type-check on affected projects:

```sh
pnpm pre-commit
```

For direct matrix development, build first because the conformance Vitest configuration imports built reporters. The configuration runs files sequentially and supplies Node's experimental SQLite flag to forked workers:

```sh
pnpm build
pnpm vitest run --config vitest.conformance.config.mts
```

To target one matrix file directly, append its path, for example:

```sh
pnpm vitest run --config vitest.conformance.config.mts packages/conformance/src/tests/matrix/issuance.test.ts
```

### Implementation conventions

- TypeScript is strict ESM with NodeNext resolution. Preserve `.js` extensions in relative runtime imports.
- Keep application code inside each project's `src/`; reuse the local Fastify route/plugin structure rather than adding a second pattern.
- Use package imports such as `@itw-conformance-tool/conformance` for cross-workspace dependencies.
- Use Vitest in the Node environment. Place focused tests alongside code as `*.test.ts` or `*.spec.ts`; conformance matrices live in `packages/conformance/src/tests/matrix`.
- Prettier requires two-space indentation, semicolons, single quotes, no trailing commas, and a 120-column print width. ESLint also enforces Nx module boundaries and ordered imports.
- Treat protocol events, artifacts, local databases, key files, certificates, reports, `config.ini`, and `.itw-conformance-tool/` as potentially sensitive local data.

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
