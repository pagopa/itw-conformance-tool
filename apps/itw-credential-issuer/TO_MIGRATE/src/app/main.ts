import { GetAuthorizationCodeJwtHandler } from '@/adapters/azure/functions/get-authorization-code-jwt';
import { GetAuthorizationResponseHandler } from '@/adapters/azure/functions/get-authorization-response';
import { GetHealthCheckHandler } from '@/adapters/azure/functions/get-health-check';
import { GetStatusListHandler } from '@/adapters/azure/functions/get-status-list';
import { GetWellKnownOpenidFederationHandler } from '@/adapters/azure/functions/get-well-known-openid-federation';
import { PostCredentialResponseHandler } from '@/adapters/azure/functions/post-credential-response';
import { PostNonceResponseHandler } from '@/adapters/azure/functions/post-nonce-response';
import { PostPresentationResponseHandler } from '@/adapters/azure/functions/post-presentation-response';
import { PostPushedAuthorizationRequestHandler } from '@/adapters/azure/functions/post-pushed-authorization-request';
import { PostTokenResponseHandler } from '@/adapters/azure/functions/post-token-response';
import { preInvocationHandler } from '@/app/hooks';
import { app } from '@azure/functions';

app.hook.preInvocation(preInvocationHandler);

app.http('GetHealthCheck', {
  authLevel: 'anonymous',
  handler: GetHealthCheckHandler,
  methods: ['GET'],
  route: 'health'
});

app.http('GetWellKnownOpenidFederation', {
  authLevel: 'anonymous',
  handler: GetWellKnownOpenidFederationHandler,
  methods: ['GET'],
  route: '.well-known/openid-federation'
});

app.http('PostPushedAuthorizationRequest', {
  authLevel: 'anonymous',
  handler: PostPushedAuthorizationRequestHandler,
  methods: ['POST'],
  route: 'as/par'
});

app.http('GetAuthorizationResponse', {
  authLevel: 'anonymous',
  handler: GetAuthorizationResponseHandler,
  methods: ['GET'],
  route: 'authorize'
});

app.http('PostPresentationResponse', {
  authLevel: 'anonymous',
  handler: PostPresentationResponseHandler,
  methods: ['POST'],
  route: 'presentation-response'
});

app.http('GetAuthorizationCode', {
  authLevel: 'anonymous',
  handler: GetAuthorizationCodeJwtHandler,
  methods: ['GET'],
  route: 'authorization-code'
});

app.http('PostTokenResponse', {
  authLevel: 'anonymous',
  handler: PostTokenResponseHandler,
  methods: ['POST'],
  route: 'token'
});

app.http('PostNonceResponse', {
  authLevel: 'anonymous',
  handler: PostNonceResponseHandler,
  methods: ['POST'],
  route: 'nonce'
});

app.http('PostCredentialResponse', {
  authLevel: 'anonymous',
  handler: PostCredentialResponseHandler,
  methods: ['POST'],
  route: 'credential'
});

app.http('GetStatusList', {
  authLevel: 'anonymous',
  handler: GetStatusListHandler,
  methods: ['GET'],
  route: 'statuslist/1'
});
