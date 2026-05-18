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
import { loadRpConfig, SessionService } from '@itw-conformance-tool/rp';

const { config, baseUrl } = await loadRpConfig();

// Implement your repository
class MySessionRepository implements SessionRepository {
  // ...
}

const sessionService = new SessionService(new MySessionRepository());

app.decorate('rp', {
  sessionService,
  clientId: config.host,
  baseUrl: baseUrl
});
```

### Using SessionService

```typescript
// Create a new session
const sessionId = await sessionService.create({
  sessionId: 'random-uuid',
  ttlSeconds: 300
});

// Retrieve session
const session = await sessionService.get(sessionId);

// Update session to verified
await sessionService.update(sessionId, 'verified', {
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
  const requestObject = requestObjectService.decodeAndValidate(jwtString);
  console.log(requestObject.nonce); // Use nonce for verification
} catch (error) {
  // Handle InvalidRequestObjectJwtError
}
```

## Configuration

Load configuration from environment variables or ini file:

```typescript
const result = await loadRpConfig({
  configFile: './config.ini',
  env: process.env
});

// Environment variables take precedence:
// - ITW_CT_RP_HOST (default: "localhost")
// - ITW_CT_RP_PORT (default: 8080)
// - ITW_CT_RP_BASE_URL (optional, derives from host:port)
// - ITW_CT_DATA_DIR (default: "./data")
```

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
