import { NotFoundError } from './errors';
import { DcqlPresentation, FlowType } from './schemas';

export interface RequestObject {
  expiresAt: number;
  // "rejected" indicates that the wallet has declined the request and notified the RP of the error via the response URI endpoint
  // "checking" indicates that the wallet is still processing the request
  flowType: FlowType;
  id: string; // state
  jwt: string;
  redirectUri?: string;
  status: 'checking' | 'denied' | 'expired' | 'pending' | 'rejected' | 'verified';
  values?: Record<string, null | string>[];
}

export interface RequestObjectRepository {
  delete: (id: RequestObject['id']) => Promise<void>;
  get: (id: RequestObject['id']) => Promise<RequestObject>;
  insert: ({
    flowType,
    id,
    jwt
  }: {
    flowType: FlowType;
    id: RequestObject['id'];
    jwt: RequestObject['jwt'];
  }) => Promise<void>;
  update: (
    id: RequestObject['id'],
    status: 'checking' | 'denied' | 'expired' | 'rejected' | 'verified',
    redirectUri?: string,
    values?: Record<string, null | string>[]
  ) => Promise<void>;
}

export const insertRequestObject: (requestObject: {
  flowType: FlowType;
  id: string;
  jwt: string;
}) => (requestObjectRepository: RequestObjectRepository) => Promise<void> =
  (requestObject) => (requestObjectRepository) =>
    requestObjectRepository.insert(requestObject);

export const getRequestObject: (
  id: string
) => (requestObjectRepository: RequestObjectRepository) => Promise<RequestObject> =
  (id) => async (requestObjectRepository) =>
    requestObjectRepository.get(id);

export const deleteRequestObject: (id: string) => (requestObjectRepository: RequestObjectRepository) => Promise<void> =
  (id) => (requestObjectRepository) =>
    requestObjectRepository.delete(id);

export const markRequestObjectAsDenied: (
  id: string
) => (requestObjectRepository: RequestObjectRepository) => Promise<void> = (id) => (requestObjectRepository) =>
  requestObjectRepository.update(id, 'denied');

export const markRequestObjectAsExpired: (
  id: string
) => (requestObjectRepository: RequestObjectRepository) => Promise<void> = (id) => (requestObjectRepository) =>
  requestObjectRepository.update(id, 'expired');

export const markRequestObjectAsChecking: (
  id: string
) => (requestObjectRepository: RequestObjectRepository) => Promise<void> = (id) => (requestObjectRepository) =>
  requestObjectRepository.update(id, 'checking');

export const markRequestObjectAsRejected: (
  id: string
) => (requestObjectRepository: RequestObjectRepository) => Promise<void> = (id) => (requestObjectRepository) =>
  requestObjectRepository.update(id, 'rejected');

export const markRequestObjectAsVerified: (
  id: string,
  redirectUri?: string,
  dcqlPresentation?: DcqlPresentation
) => (requestObjectRepository: RequestObjectRepository) => Promise<void> =
  (id, redirectUri, dcqlPresentation) => (requestObjectRepository) => {
    if (dcqlPresentation) {
      // is the upstream typing correct?
      const values = Object.values(dcqlPresentation).map((entry) => {
        if (typeof entry.claims === 'object' && entry.claims !== null) {
          return Object.fromEntries(
            Object.entries(entry.claims).map(([key, value]) => {
              if (typeof value === 'object' && value !== null) {
                return [key, Object.keys(value)[0]];
              }
              return [key, null]; // fallback
            })
          );
        }
        return {};
      });

      return requestObjectRepository.update(id, 'verified', redirectUri, values);
    }
    return requestObjectRepository.update(id, 'verified', redirectUri);
  };

export async function markAsExpired(requestObjectRepository: RequestObjectRepository): Promise<void> {
  const now = Date.now();
  for (const { expiresAt, id } of requestObjects) {
    if (expiresAt < now) {
      await markRequestObjectAsExpired(id)(requestObjectRepository);
    }
  }
}

// fake dabatase:
export const requestObjects: RequestObject[] = [];

export const requestObjectRepository: RequestObjectRepository = {
  delete: (requestObjectId) => {
    const requestObject = requestObjects.find(({ id }) => id === requestObjectId);
    if (!requestObject) {
      return Promise.reject();
    }
    const index = requestObjects.findIndex((el) => el.id === requestObject.id);
    if (index !== -1) {
      requestObjects.splice(index, 1);
    }
    return Promise.resolve(undefined);
  },
  get: (requestObjectId) => {
    const requestObject = requestObjects.find(({ id }) => id === requestObjectId);
    if (!requestObject) {
      return Promise.reject(new NotFoundError());
    }
    return Promise.resolve(requestObject);
  },
  insert: ({ flowType, id, jwt }) => {
    requestObjects.push({
      expiresAt: Date.now() + 5 * 60 * 1000, // The request object expires after 5 minutes
      flowType,
      id,
      jwt,
      status: 'pending'
    });
    return Promise.resolve(undefined);
  },
  update: (requestObjectId, status, redirectUri, values?: Record<string, null | string>[]) => {
    const requestObject = requestObjects.find(({ id }) => id === requestObjectId);
    if (!requestObject) {
      return Promise.reject();
    }
    requestObject['status'] = status;
    if (status === 'verified' && redirectUri) {
      requestObject['redirectUri'] = redirectUri;
    }
    if (values) {
      requestObject['values'] = values;
    }
    return Promise.resolve(undefined);
  }
};
