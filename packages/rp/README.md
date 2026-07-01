# @itw-conformance-tool/rp

IT Wallet Relying Party (RP) domain layer package.

## Overview

This package provides the domain layer for the Relying Party component, including:

- **Configuration management** (`config.ts`) - Load and manage RP configuration
- **Domain models** (`models/`) - Core domain entities
  - `PresentationSession` - Represents a VP presentation flow
  - `RequestObject` - OpenID4VP authorization request
  - `AuthResponse` - Authorization response with error handling
- **Services** (`services/`) - Business logic use cases
  - `SessionService` - Manage presentation sessions
  - `RequestObjectService` - Validate and decode request objects
- **Repository interfaces** (`repositories.ts`) - Wiring contracts for dependency injection

## Structure

```
src/
├── config.ts                    # Configuration loading & defaults
├── repositories.ts              # DI contracts
├── index.ts                     # Public API (use this!)
├── models/
│   ├── index.ts                 # Models export
│   ├── presentation-session.ts  # Session domain model
│   ├── request-object.ts        # Request object model
│   └── auth-response.ts         # Response model
├── services/
│   ├── index.ts                 # Services export
│   ├── session-service.ts       # Session management
│   └── request-object-service.ts # Request validation
└── __tests__/
    ├── *.test.ts                # Unit tests for all modules
    ├── models/
    ├── services/
```

## Usage

### Import from the public API

```typescript
import {
  // Configuration
  loadRpConfig,
  deriveBaseUrl,

  // Models & types
  PresentationSession,
  createPresentationSession,
  RequestObject,
  AuthResponse,

  // Services
  SessionService,
  RequestObjectService,

  // Wiring contracts
  type SessionRepository,
  type NonceRepository
} from '@itw-conformance-tool/rp';
```

### Setup with Fastify

```typescript
import { deriveBaseUrl, loadRpConfig, SessionService } from '@itw-conformance-tool/rp';

const { config, configFileFound } = loadRpConfig({ configFilePath: './config.ini' });
const baseUrl = deriveBaseUrl({ host: config.host, port: config.port });

// Implement your repository
class MySessionRepository implements SessionRepository {
  // ...
}

const sessionService = new SessionService(new MySessionRepository());

app.decorate('rp', {
  sessionService,
  clientId: config.host,
  baseUrl
});
```

### Using SessionService

```typescript
// Create a new session
const session = await sessionService.create({
  id: 'random-uuid',
  jwt: requestObjectJwt,
  flowType: 'same-device',
  ttlMs: 300_000 // optional, defaults to 5 minutes
});

// Retrieve session
const session = await sessionService.get(id);

// Update session to verified
await sessionService.update(id, 'verified', {
  redirectUri: 'http://...',
  values: [
    /* presented claims */
  ]
});
```

### Using RequestObjectService

```typescript
const requestObjectService = new RequestObjectService();

try {
  // Decode the JWT header and payload (no signature verification)
  const requestObject = requestObjectService.parse(jwtString);

  // Validate the parsed request object structure
  const isValid = requestObjectService.validate(requestObject);

  console.log(requestObject.nonce); // Use nonce for verification
} catch (error) {
  // Handle InvalidRequestObjectJwtError
}
```

## Configuration

Load configuration from environment variables or ini file:

```typescript
const { config, configFileFound } = loadRpConfig({
  configFilePath: './config.ini',
  env: process.env // optional, defaults to process.env
});

// Supported environment variables take precedence:
// - ITW_CT_RP_PORT (default: 8080)
// - ITW_CT_DATA_DIR (default: "~/.itw-conformance-tool")
// - ITW_CT_RP_TRUST_ANCHOR_URL (required — Trust Anchor URL for Federation validation)
// - ITW_CT_RP_X5C_CERT_PATH (required — path to PEM certificate chain for x5c JWT header)
```

When used through the CLI orchestration (`itwct start` / `itwct test`), the global config must also include `global.wallet_provider_backend_url` as a valid URL.
If that field is missing, empty, or invalid, the CLI fails before service startup.

## Wiring Contracts (Dependency Injection)

Implement these contracts to integrate the domain layer:

```typescript
// Repository for storing/retrieving sessions
interface SessionRepository {
  create(session: PresentationSession): Promise<void>;
  findById(sessionId: string): Promise<PresentationSession | null>;
  update(sessionId: string, state: PresentationSessionState, details?: PresentationSessionDetails): Promise<void>;
  delete(sessionId: string): Promise<void>;
}

// Repository for managing nonces (CSRF protection)
interface NonceRepository {
  store(nonce: string, ttlSeconds: number): Promise<void>;
  consume(nonce: string): Promise<boolean>;
}
```

## Testing

Run tests:

```bash
pnpm test
pnpm nx run @itw-conformance-tool/rp:test
```

Run with coverage:

```bash
pnpm test -- --coverage
```

## API Stability

This package exports a stable public API via `index.ts`. Consumer code should:

✅ Import from `@itw-conformance-tool/rp` (public API)
❌ Avoid importing from internal paths like `./src/services/...` (unstable)

The public API guarantees backward compatibility within semver. Internal paths may change without notice.
