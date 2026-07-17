# itw-credential-issuer

Credential Issuer service for IT Wallet conformance testing. This service implements OpenID4VCI (Verifiable Credential Issuance) to issue credentials to a Wallet following the Italian IT Wallet technical specifications.

When used in conformance mode via `itwct start`, this service works alongside the Relying Party to test complete OID4VCI flows.

## Configuration

The Credential Issuer service is primarily configured via the CLI, which reads from `config.ini` and exports environment variables to the service.

When **launched via CLI** (`itwct start`), the following environment variables are automatically set from `config.ini`:

| Environment Variable                 | Source (config.ini)                        | Purpose                              |
| ------------------------------------ | ------------------------------------------ | ------------------------------------ |
| `ITW_CT_DATA_DIR`                    | `[global] data_dir`                        | Data directory for keys/certs        |
| `ITW_CT_LOG_LEVEL`                   | `[global] log_level`                       | Log level (debug, info, warn, error) |
| `ITW_CT_HTTPS`                       | `[global] https`                           | Enable HTTPS mode                    |
| `ITW_CT_ISSUER_PORT`                 | `[itw-credential-issuer] port`             | HTTP listen port                     |
| `ITW_CT_ISSUER_CREDENTIAL_TYPES`     | `[itw-credential-issuer] credential_types` | Exported by CLI (not currently consumed by the issuer app) |
| `ITW_CT_ISSUER_AUTH_FLOW`            | `[itw-credential-issuer] auth_flow`        | Authorization flow type                                    |
| `ITW_CT_WALLET_PROVIDER_BACKEND_URL` | `[global] wallet_provider_backend_url`     | Exported by CLI for conformance tests (not consumed by the issuer app) |

### config.ini Example

```ini
[global]
; Data directory for keys and certificates
; Default: ~/.itw-conformance-tool
data_dir = ~/.itw-conformance-tool

; Logging level: debug | info | warn | error
; Default: info
log_level = info

; Enable HTTPS mode
; Default: true
https = false

; Wallet provider backend URL (mandatory for conformance tests)
wallet_provider_backend_url = https://127.0.0.1:8080

[itw-credential-issuer]
; HTTP port for the credential issuer service
; Default: 3000
port = 3000

; Enabled credential types (comma-separated)
; Options: pid, mdl, badge, eaa
; Default: pid,mdl,badge,eaa
credential_types = pid,mdl,badge,eaa

; Authentication flow
; Options: direct, l2plus, l3
; Default: direct
auth_flow = direct
```

### Standalone Usage (Without CLI)

If you run the service directly (not through `itwct start`), you can override TLS paths:

| Environment Variable   | Purpose                 | Default                   |
| ---------------------- | ----------------------- | ------------------------- |
| `ITW_CT_TLS_CERT_PATH` | Path to TLS certificate | `{DATA_DIR}/tls-cert.pem` |
| `ITW_CT_TLS_KEY_PATH`  | Path to TLS private key | `{DATA_DIR}/tls-key.pem`  |
| `ITW_CT_DATA_DIR`      | Data directory for keys | `./.itw-conformance-tool` |
| `ITW_CT_HTTPS`         | Enable HTTPS mode       | `false`                   |

## Runtime Notes

When launched through the conformance CLI (`itwct start` / `itwct test`):

- The CLI generates issuer signing keys and IACA certificates during `itwct init`
- These artifacts are stored in `{DATA_DIR}/issuer/`
- The service loads them automatically at startup

## Endpoints

### Authorization Endpoint

**GET /authorize**

Initiates an OpenID4VCI authorization flow.

Query parameters:

- `client_id` (string): Credential Wallet client identifier
- `request_uri` (string): URI to the OpenID4VCI authorization request object

Response: Redirect to authorization server with auth code

### Token Endpoint

**POST /token**

Exchanges an authorization code for an access token (OID4VCI token endpoint).

Request body:

```json
{
  "grant_type": "authorization_code",
  "code": "auth_code_123",
  "client_id": "wallet_client",
  "client_assertion": "..."
}
```

Response:

```json
{
  "access_token": "token_xyz...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "c_nonce": "nonce_abc...",
  "c_nonce_expires_in": 300
}
```

### Credential Endpoint

**POST /credential**

Requests the issuance of credentials (OID4VCI credential endpoint).

Request body:

```json
{
  "credential_type": "urn:pid:it",
  "proof": {
    "proof_type": "jwt",
    "jwt": "eyJ..."
  }
}
```

Response:

```json
{
  "credential": "eyJ...",
  "credential_type": "urn:pid:it",
  "c_nonce": "nonce_def...",
  "c_nonce_expires_in": 300
}
```

### Batch Credential Endpoint

**POST /batch_credential**

This endpoint is not implemented in this service; use `POST /credential` instead.

### Deferred Credential Endpoint

**POST /deferred_credential**

Retrieves a previously deferred credential using an acceptance token.

Request body:

```json
{
  "acceptance_token": "token_123..."
}
```

Response: Credential if ready, or deferred status if not yet available

### OpenID Federation Metadata

**GET /.well-known/openid-federation**

Serves the Issuer's OpenID Federation metadata (Entity Configuration).

Response: JWT entity configuration

### Credential Offer

**POST /offers**

This endpoint is not implemented in this service.

### Pushed Authorization Requests (PAR)

**POST /par**

OpenID4VCI PAR endpoint for pushing authorization request parameters (RFC 9126).

Request body:

```json
{
  "client_id": "wallet_client",
  "credential_type": "urn:pid:it",
  "wallet_issuer": "https://wallet.example.com",
  "scope": "openid credential"
}
```

Response:

```json
{
  "request_uri": "urn:ietf:params:oauth:request_uri:bwc4cObhNYhWQyNEtfal",
  "expires_in": 900
}
```

### Non-Repudiation Endpoint

**POST /nonce**

Generates a nonce for proof-of-possession in credential requests.

Response:

```json
{
  "c_nonce": "nonce_12345"
}
```

### Mock IDP Callback

**GET /idp-callback**

Mock Identity Provider callback for testing authorization flows (non-production).

### Health Check

**GET /health**

Simple health check endpoint.

Response:

```json
{
  "status": "ok"
}
```

### Credential Status List

**GET /statuslist**

Serves StatusList2021Entry credential status information.

## Credential Types

The issuer can issue the following credential types (controlled by `CREDENTIAL_TYPES`):

| Type  | Identifier     | Description                        |
| ----- | -------------- | ---------------------------------- |
| PID   | `urn:pid:it`   | Personal Identification Data       |
| MDL   | `urn:mdl:it`   | Mobile Driver License              |
| Badge | `urn:badge:it` | Professional/Educational Badge     |
| EAA   | `urn:eaa:it`   | European Attestation of Attributes |

## Development

### Running Locally

From the repository root:

```bash
# Serve with live reload
pnpm nx serve itw-credential-issuer

# Run tests
pnpm nx run itw-credential-issuer:test

# Build for production
pnpm nx run itw-credential-issuer:build

# Type check
pnpm nx run itw-credential-issuer:typecheck

# Lint
pnpm nx run itw-credential-issuer:lint
```

### Testing

```bash
# Run all tests
pnpm nx run itw-credential-issuer:test

# Run tests in watch mode
pnpm nx run itw-credential-issuer:test -- --watch

# Run with coverage
pnpm nx run itw-credential-issuer:test -- --coverage
```

## Architecture

The Credential Issuer service is built with **Fastify** and consists of:

- **Plugins**: Configuration, database, key management, security (CORS, helmet, rate limiting), Swagger
- **Routes**: HTTP endpoints for OpenID4VCI flows (authorize, token, credential, batch_credential, etc.)
- **Use Cases**: Business logic for credential issuance and OID4VCI protocol compliance
- **Hooks**: Conformance-specific behavior, logging, and error handling

The service uses OpenID4VCI libraries from `@pagopa/io-wallet-*` packages to handle protocol compliance with the Italian IT Wallet specifications.

## Conformance Testing

When used in conformance mode:

1. The service issues test credentials (PID, MDL, Badge, EAA) following the technical rules
2. Proofs are verified using wallet-provided proof objects
3. Credentials are signed with issuer signing keys from `{DATA_DIR}/issuer/signing-keys.jwks.json`
4. Non-repudiation logs and audit trails are stored in the database
5. Status checks and credential revocation follow the technical specifications

For detailed conformance flows, see the main project [README](../../README.md).
