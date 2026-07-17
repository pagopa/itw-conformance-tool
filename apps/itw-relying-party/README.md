# itw-relying-party

Relying Party (RP) service for IT Wallet conformance testing. This service implements OpenID4VP (Verifiable Presentations) to request credentials from a Wallet and validate authorization responses.

When used in conformance mode via `itwct start`, this service works alongside the Credential Issuer to test complete OID4VP flows.

## Configuration

The RP service is primarily configured via the CLI, which reads from `config.ini` and exports environment variables to the service.

When **launched via CLI** (`itwct start`), the following environment variables are automatically set from `config.ini`:

| Environment Variable         | Source (config.ini)     | Purpose                              |
| ---------------------------- | ----------------------- | ------------------------------------ |
| `ITW_CT_DATA_DIR`            | `[global] data_dir`     | Data directory for keys/certs        |
| `ITW_CT_LOG_LEVEL`           | `[global] log_level`    | Log level (debug, info, warn, error) |
| `ITW_CT_HTTPS`               | `[global] https`        | Enable HTTPS mode                    |
| `ITW_CT_RP_PORT`             | `[rp] port`             | HTTP listen port                     |
| `ITW_CT_RP_BASE_URL`         | Derived from port       | RP base URL (https://127.0.0.1:PORT) |
| `ITW_CT_RP_TRUST_ANCHOR_URL` | `[rp] trust_anchor_url` | Trust Anchor URL for Federation      |

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

[rp]
; HTTP port for the RP service
; Default: 8080
port = 8080

; RP OpenID Federation Entity ID (leaf entity)
; This must be a valid URL or URI
; Example: https://rp.example.org
entity_id = https://rp.example.org

; Trust Anchor URL for OpenID Federation validation (mandatory)
; Example: https://trust-anchor.example.com/.well-known/openid-federation
; Default: /.well-known/openid-federation
trust_anchor_url = https://trust-anchor.example.com/.well-known/openid-federation

; Path to the x5c certificate chain PEM file (mandatory)
; Default: ~/.itw-conformance-tool/rp/x5c-cert.pem
x5c_cert_path = ~/.itw-conformance-tool/rp/x5c-cert.pem
```

### Standalone Usage (Without CLI)

If you run the service directly (not through `itwct start`), you can override TLS paths and data directory:

| Environment Variable | Purpose                 | Default                   |
| -------------------- | ----------------------- | ------------------------- |
| `ITW_CT_DATA_DIR`    | Data directory for keys | `./.itw-conformance-tool` |
| `ITW_CT_HTTPS`       | Enable HTTPS mode       | `false`                   |

## Endpoints

### Authorization Request Initiation

**POST /request-object**

Initiates an OpenID4VP authorization request. Accepts a DCQL (Distributed Credential Query Language) query or credential request payload.

Request body example:

```json
{
  "dcqlQuery": {
    "credentials": [
      {
        "claims": [
          {
            "path": ["given_name"],
            "values": ["John"]
          }
        ]
      }
    ]
  }
}
```

Response:

```json
{
  "state": "abc123...",
  "redirect_uri": "https://wallet.example.com/authorize?client_id=rp&request_uri=..."
}
```

### Authorization Request Object

**GET /auth/request/:state**

Serves the signed OpenID4VP authorization request object (JWT) for a given state.

Parameters:

- `state` (string): Session state identifier

Response: JWT authorization request object

### Authorization Response

**POST /auth/response**

Verifies and processes the wallet's authorization response (JARM - JWT Authorization Response Mode).

Request body: OpenID4VP authorization response JWT

Response:

```json
{
  "status": "verified",
  "values": [...]
}
```

### Status Polling

**GET /status/:state**

Polls the presentation status for a given state. Returns `redirect_uri` and optional credential values.

Parameters:

- `state` (string): Session state identifier

Response format varies by status:

| Status   | Response                                                        |
| -------- | --------------------------------------------------------------- |
| pending  | `{"redirect_uri":"?response_code=pending"}`                     |
| checking | `{"redirect_uri":"?response_code=checking"}`                    |
| verified | `{"redirect_uri":"<success-url>","values":[...]}`               |
| rejected | `{"redirect_uri":"rejected-error.html?response_code=rejected"}` |
| denied   | `{"redirect_uri":"error.html?response_code=denied"}`            |
| expired  | `{"redirect_uri":"timeout.html?response_code=expired"}`         |

### OpenID Federation Metadata

**GET /.well-known/openid-federation**

Serves the RP's OpenID Federation metadata (Entity Configuration).

Response: JWT entity configuration

### Health Check

**GET /health**

Simple health check endpoint.

Response:

```json
{
  "status": "ok"
}
```

### Data Erasure

**POST /erasure**

Initiates erasure of presentation data for compliance purposes.

## Development

### Running Locally

From the repository root:

```bash
# Serve with live reload
pnpm nx serve itw-relying-party

# Run tests
pnpm nx run itw-relying-party:test

# Build for production
pnpm nx run itw-relying-party:build

# Type check
pnpm nx run itw-relying-party:typecheck

# Lint
pnpm nx run itw-relying-party:lint
```

### Testing

```bash
# Run all tests
pnpm nx run itw-relying-party:test

# Run tests in watch mode
pnpm nx run itw-relying-party:test -- --watch
```

## Architecture

The RP service is built with **Fastify** and consists of:

- **Plugins**: Configuration, database, key management, security (CORS, helmet, rate limiting)
- **Routes**: HTTP endpoints for authorization flows
- **Use Cases**: Business logic for OID4VP flows
- **Hooks**: Conformance-specific behavior and logging

The service uses OpenID4VP libraries from `@pagopa/io-wallet-*` packages to handle protocol compliance.
