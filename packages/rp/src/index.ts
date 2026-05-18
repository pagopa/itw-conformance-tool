/**
 * RP Domain Public API
 *
 * This is the primary export point for the Relying Party domain layer.
 * Consumers should import from this index rather than internal paths.
 *
 * @example
 * ```ts
 * import {
 *   loadRpConfig,
 *   SessionService,
 *   PresentationSession,
 *   createPresentationSession
 * } from '@itw-conformance-tool/rp';
 * ```
 */

// Configuration
export {
  DEFAULT_DATA_DIR,
  DEFAULT_HOST,
  DEFAULT_PORT,
  deriveBaseUrl,
  loadRpConfig,
  parseIni,
  rpConfigSchema_export as rpConfigSchema,
  type LoadRpConfigInput,
  type LoadRpConfigResult,
  type RpConfig
} from './config.js';

// Models - Public domain types
export {
  createPresentationSession,
  isExpiredNow,
  isTerminalState,
  mapToDbState,
  parseDetails,
  recordToPresentationSession,
  serializeDetails,
  type PresentationFlowType,
  type PresentationSession,
  type PresentationSessionDetails,
  type PresentationSessionState,
  type PresentationValues
} from './models/presentation-session.js';

export {
  isRequestObjectExpired,
  validateRequestObject,
  requestObjectSchema,
  type RequestObject
} from './models/request-object.js';

export {
  isAuthResponseError,
  isAuthResponseSuccess,
  type AuthResponse,
  type AuthResponseError,
  type AuthResponseErrorCode,
  type AuthResponseSuccess
} from './models/auth-response.js';

// Services - Public use case implementations
export {
  SessionService,
  type CreateSessionInput,
  type SessionUpdateOptions,
  type TransitionalState,
  type SessionRepository
} from './services/session-service.js';

export { InvalidRequestObjectJwtError, RequestObjectService } from './services/request-object-service.js';

// Repository interfaces - Wiring contracts for DI
export {
  type NonceRepository,
  type RequestObjectServiceConfig,
  type SessionRepository as ISessionRepository
} from './repositories.js';
