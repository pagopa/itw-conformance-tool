import { RequestObjectRepository, getRequestObject, markRequestObjectAsChecking } from '@/request-object';

export const getAuthorizationRequest: {
  handler: (state: string) => (dep: { requestObjectRepository: RequestObjectRepository }) => Promise<string>;
  path: string;
} = {
  handler:
    (state) =>
    async ({ requestObjectRepository }) => {
      const { jwt } = await getRequestObject(state)(requestObjectRepository);
      await markRequestObjectAsChecking(state)(requestObjectRepository);
      return jwt;
      // add 503 Service Unavailable
    },
  path: '/auth/request/:state'
};
