// Config
export {
  DEFAULT_DATA_DIR,
  DEFAULT_HOST,
  DEFAULT_PORT,
  deriveBaseUrl,
  loadRpConfig,
  resolveHttpsEnabled,
  resolveTlsPaths,
  rpConfigSchema,
  type LoadRpConfigInput,
  type LoadRpConfigResult,
  type RpTlsPaths,
  type RpConfig
} from './config.js';

// Models
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
  type PresentationSessionState,
  type PresentationValues
} from './models/presentation-session.js';
export * from './models/request-object.js';
export * from './models/auth-response.js';

// Services
export {
  SessionService,
  type CreateSessionInput,
  type SessionUpdateOptions,
  type TransitionalState
} from './services/session-service.js';
export { InvalidRequestObjectJwtError, RequestObjectService } from './services/request-object-service.js';

export { type NonceRepository, type RequestObjectServiceConfig, type SessionRepository } from './repositories.js';
