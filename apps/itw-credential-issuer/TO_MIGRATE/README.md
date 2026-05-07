# EUDIW IT Issuer - PID and (Q)EAA Provider Service

This package contains the Azure Functions backend used to issue mocked
European Digital Identity Wallet (EUDIW) credentials inside the
`io-wallet-demo` monorepo. It implements the Person Identification Data
(PID) and Qualified/Enhanced Attestation of Attributes (Q/EAA) Provider
service, aligned with
[OpenID for Verifiable Credential Issuance (draft 15)](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
and the
[Italian technical specifications](https://italia.github.io/eid-wallet-it-docs/versione-corrente/en/pid-eaa-issuance.html).

## Overview

The issuer currently supports these credential families:

- Person Identification Data (PID)
- European Disability Card
- (Q)EAA credentials such as age-over-18 pseudonym
- mDL (mobile Driving License)
- Badge Access

By default, the service supports `mso_mdoc` and `SD-JWT-VC` credential
formats and exposes the OpenID4VCI draft 15 endpoints needed for:

- Authorization Code Flow
- Pushed Authorization Requests
- Token issuance
- Credential issuance
- Nonce and DPoP handling

## Supported Features

### Supported Credential Formats

| Credential/Attestation                     | Format    |
| ------------------------------------------ | --------- |
| **PID**                                    | SD-JWT-VC |
| **European Disability Card** (Planned)     | SD-JWT-VC |
| **PID** (Planned)                          | mso_mdoc  |
| **Badge Access**                           | mso_mdoc  |
| **mDL**                                    | mso_mdoc  |
| **(Q)EAA age-over-18 pseudonym** (Planned) | mso_mdoc  |

### Authentication Methods

- OAuth2 integration
- Local username/password form for testing

### OpenID4VCI Coverage

| Feature                                      | Coverage                                          |
| -------------------------------------------- | ------------------------------------------------- |
| **Authorization Code flow**                  | ✅ Support for credential configuration ID, scope |
| **Credential Offer**                         | ❌ Planned for a future release                   |
| **Dynamic Credential Request**               | ✅                                                |
| **mso_mdoc format**                          | ✅                                                |
| **SD-JWT-VC format**                         | ✅                                                |
| **W3C VC DM**                                | ❌                                                |
| **Token Endpoint**                           | ✅                                                |
| **Credential Endpoint**                      | ✅ Includes proofs and repeatable invocations     |
| **Credential Issuer Metadata**               | ✅ openid-federation                              |
| **Batch Endpoint**                           | ❌                                                |
| **Deferred Endpoint**                        | ❌                                                |
| **Proof**                                    | ✅ JWT, ❌ CWT                                    |
| **Credential response encryption**           | ❌                                                |
| **Notification Endpoint**                    | ❌                                                |
| **Nonce Endpoint**                           | ✅                                                |
| **Pushed authorization request**             | ✅                                                |
| **Wallet authentication**                    | ✅ Public client                                  |
| **Demonstrating Proof of Possession (DPoP)** | ✅                                                |
| **PKCE**                                     | ✅                                                |

## Requirements

- Node.js 22 or newer
- pnpm 10.30.3 or newer
- Azure Functions Core Tools

If you need Azure Storage locally, you can also install Azurite.

## Installation

From the monorepo root:

```bash
pnpm install
```

To run the Azure Functions host locally, install
[Azure Functions Core Tools](https://github.com/Azure/azure-functions-core-tools).

Optional Azurite setup:

```bash
npm install -g azurite
azurite --silent --location c:\\azurite --debug c:\\azurite\\debug.log
```

## Usage

Run these commands from the monorepo root.

### Development

Start the issuer in watch mode:

```bash
nx run itw-credential-issuer:start 
```

Start the issuer in watch mode with HTTPS enabled:

```bash
nx run itw-credential-issuer:start:https
```

These commands rebuild on file changes and start the Azure Functions host
after each successful build.

### Build and Host Commands

```bash
nx run itw-credential-issuer:build
nx run itw-credential-issuer:build:watch
nx run itw-credential-issuer:func
nx run itw-credential-issuer:func:https
nx run itw-credential-issuer:clean
```

### Quality and Tests

```bash
nx run itw-credential-issuer:lint
nx run itw-credential-issuer:lint:fix
nx run itw-credential-issuer:typecheck
nx run itw-credential-issuer:format
nx run itw-credential-issuer:test
nx run itw-credential-issuer:test:coverage
nx run itw-credential-issuer:test:e2e
```

## End-to-End Testing

The end-to-end suite exercises the full issuing flow based on the
`credential_configuration_id` configured in `tests/full-flow.e2e.spec.ts`.
To test a different credential, change that value to one exposed in
`credential_configurations_supported`.

For local HTTPS flows, start the Functions host with:

```bash
nx run itw-credential-issuer:start:https
```
