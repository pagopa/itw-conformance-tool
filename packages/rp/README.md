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

const { config } = loadRpConfig({ configFilePath: './config.ini' });
const baseUrl = deriveBaseUrl({ host: config.host, port: config.port, scheme: config.httpsEnabled ? 'https' : 'http' });

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
  values: [/* presented claims */]
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

Load configuration from the shared INI file:

```typescript
const { config } = loadRpConfig({
  configFilePath: './config.ini'
});

// Runtime values are derived from the validated INI config:
// - [rp].port
// - [rp].entity_id
// - [rp].trust_anchor_url
// - [global].data_dir
// - [global].https
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
