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

## Prerequisites

| Tool | Version |
|------|---------|
| Node.js | see [`.node-version`](.node-version) |
| pnpm | `10.30.3` |

## Getting Started

Install dependencies:

```bash
pnpm install
```

Build all packages:

```bash
pnpm build
```

Run tests:

```bash
pnpm test
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

| Package | Purpose |
|---------|---------|
| `@pagopa/io-wallet-oid4vci` | OpenID for Verifiable Credential Issuance |
| `@pagopa/io-wallet-oid4vp` | OpenID for Verifiable Presentations |
| `@pagopa/io-wallet-oauth2` | OAuth 2.0 flows |
| `@pagopa/io-wallet-oid-federation` | OpenID Federation / Trust Chain |
| `@pagopa/io-wallet-utils` | Shared utilities |

## Specifications

- [IT-Wallet Technical Rules](https://italia.github.io/eudi-wallet-it-docs/)
- [Architecture Reference Framework (ARF)](https://eu-digital-identity-wallet.github.io/eudi-doc-architecture-and-reference-framework/)
- [OpenID4VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
- [OpenID4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)

## Contributing

Contributions are welcome. Please open an issue or a pull request. See [CODEOWNERS](CODEOWNERS) for maintainers.