type FlowType = 'same-device' | 'cross-device';

export interface RequestObject {
  expiresAt: number;
  flowType: FlowType;
  id: string; // state
  jwt: string;
  sessionId: string;
  redirectUri?: string;
  status: 'checking' | 'denied' | 'expired' | 'pending' | 'rejected' | 'verified';
  values?: Record<string, null | string>[];
}

export class RequestObjectRepository {
  private readonly requestObjects: RequestObject[] = [];

  public list() {
    return this.requestObjects;
  }

  public delete(requestObjectId: string) {
    const requestObject = this.requestObjects.find(({ id }) => id === requestObjectId);
    if (!requestObject) {
      throw new Error(`Request object ${requestObjectId} not found`);
    }
    const index = this.requestObjects.findIndex((el) => el.id === requestObject.id);
    if (index !== -1) {
      this.requestObjects.splice(index, 1);
    }
  }

  public get(requestObjectId: string) {
    const requestObject = this.requestObjects.find(({ id }) => id === requestObjectId);
    if (!requestObject) {
      throw new Error(`Request object ${requestObjectId} not found`);
    }
    return requestObject;
  }

  public getBySessionId(sessionId: string) {
    const requestObject = this.requestObjects.find(({ sessionId: id }) => id === sessionId);
    if (!requestObject) {
      throw new Error(`Request object with responseUriId ${sessionId} not found`);
    }
    return requestObject;
  }

  public insert({ flowType, sessionId, id, jwt }: { flowType: FlowType; sessionId: string; id: string; jwt: string }) {
    this.requestObjects.push({
      expiresAt: Date.now() + 5 * 60 * 1000, // The request object expires after 5 minutes
      flowType,
      id,
      sessionId,
      jwt,
      status: 'pending'
    });
  }

  public update(
    requestObjectId: string,
    status: 'checking' | 'denied' | 'expired' | 'rejected' | 'verified',
    redirectUri?: string,
    values?: Record<string, null | string>[]
  ) {
    const requestObject = this.requestObjects.find(({ id }) => id === requestObjectId);
    if (!requestObject) {
      throw new Error(`Request object ${requestObjectId} not found`);
    }
    requestObject['status'] = status;
    if (status === 'verified' && redirectUri) {
      requestObject['redirectUri'] = redirectUri;
    }
    if (values) {
      requestObject['values'] = values;
    }
  }
}
