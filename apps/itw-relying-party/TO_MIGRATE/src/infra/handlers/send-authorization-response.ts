import { Config } from '@/config';
import type { NonceRepository } from '@/nonce';
import { RequestObjectRepository, markRequestObjectAsRejected } from '@/request-object';
import { ResponseBody } from '@/schemas';
import { baz1 } from '@/use-cases/send-authorization-response';

function isAuthorizationResponse(data: ResponseBody): data is Required<Pick<ResponseBody, 'response'>> {
  return 'response' in data && typeof data.response === 'string';
}

function isAuthorizationErrorResponse(data: ResponseBody): data is Required<Omit<ResponseBody, 'response'>> {
  return 'error' in data && 'error_description' in data && 'state' in data;
}

export const sendAuthorizationResponse: {
  handler: (
    body: ResponseBody
  ) => (dep: {
    config: Config;
    nonceRepository: NonceRepository;
    requestObjectRepository: RequestObjectRepository;
  }) => Promise<{ redirect_uri?: string }>;
  path: string;
} = {
  handler:
    (body) =>
    async ({ config, requestObjectRepository }) => {
      if (isAuthorizationResponse(body)) {
        return baz1(body.response)({
          config,
          nonceRepository,
          requestObjectRepository
        });
      }
      if (isAuthorizationErrorResponse(body)) {
        // what should we do with these errors?
        await markRequestObjectAsRejected(body.state)(requestObjectRepository);
        return {};
      }
      throw new Error();
    },
  path: '/auth/response'
};
