import { createHash, randomUUID } from 'node:crypto';

export type ArtifactKind = 'http-exchange' | 'json' | 'jwt';

export interface ArtifactRef {
  id: string;
  kind: ArtifactKind;
  name: string;
  reportable: boolean;
}

export interface StoreArtifactOptions {
  reportable?: boolean;
  metadata?: Record<string, unknown>;
}

export interface StoreJwtOptions extends StoreArtifactOptions {
  name?: string;
}

export interface RedactedHttpMessage {
  method?: string;
  url?: string;
  statusCode?: number;
  headers?: Record<string, unknown>;
  body?: unknown;
}

export interface RedactedHttpExchange {
  request: RedactedHttpMessage;
  response: RedactedHttpMessage;
}

export interface StoredArtifact {
  ref: ArtifactRef;
  createdAt: string;
  content: unknown;
  metadata?: Record<string, unknown>;
}

export interface ArtifactStore {
  storeHttpExchange(exchange: RedactedHttpExchange): Promise<ArtifactRef>;
  storeJwt(jwt: string, options?: StoreJwtOptions): Promise<ArtifactRef>;
  storeJson(name: string, value: unknown, options?: StoreArtifactOptions): Promise<ArtifactRef>;
  get(ref: ArtifactRef): Promise<StoredArtifact>;
}

interface JwtParts {
  header: unknown;
  payload: unknown;
  signatureSha256: string;
}

function createRef(kind: ArtifactKind, name: string, reportable: boolean): ArtifactRef {
  return { id: randomUUID(), kind, name, reportable };
}

function sha256Base64Url(value: string): string {
  return createHash('sha256').update(value).digest('base64url');
}

function decodeBase64UrlJson(value: string): unknown {
  return JSON.parse(Buffer.from(value, 'base64url').toString('utf-8')) as unknown;
}

async function decodeJwt(jwt: string): Promise<JwtParts> {
  const parts = jwt.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid compact JWT format');
  }

  const [header, payload, signature] = parts as [string, string, string];

  return {
    header: decodeBase64UrlJson(header),
    payload: decodeBase64UrlJson(payload),
    signatureSha256: sha256Base64Url(signature)
  };
}

export function createInMemoryArtifactStore(): ArtifactStore {
  const artifacts = new Map<string, StoredArtifact>();

  function store(ref: ArtifactRef, content: unknown, metadata?: Record<string, unknown>): ArtifactRef {
    artifacts.set(ref.id, {
      ref,
      createdAt: new Date().toISOString(),
      content,
      metadata
    });
    return ref;
  }

  return {
    async storeHttpExchange(exchange) {
      const ref = createRef('http-exchange', 'http-exchange', true);
      return store(ref, exchange);
    },
    async storeJwt(jwt, options = {}) {
      const ref = createRef('jwt', options.name ?? 'jwt', options.reportable ?? true);
      return store(ref, await decodeJwt(jwt), options.metadata);
    },
    async storeJson(name, value, options = {}) {
      const ref = createRef('json', name, options.reportable ?? true);
      return store(ref, value, options.metadata);
    },
    async get(ref) {
      const artifact = artifacts.get(ref.id);
      if (!artifact) throw new Error(`Artifact not found: ${ref.id}`);
      return artifact;
    }
  };
}
