export {
  Verifier,
  Claims,
  RevokedError,
  parseJWKS,
  fetchJWKS,
  type Action,
  type Actor,
  type Constraints,
  type TimeWindow,
  type RateLimit,
  type VerifierOptions,
} from './verifier.js';
export { RevocationFeed, fetchRevocationFeed, parseRevocationFeed } from './revocation.js';
export { AgentGuard, type TokenSource, type ToolGuardOptions } from './agentguard.js';
export {
  bearerToken,
  authenticate,
  expressAuth,
  expressRequireScope,
  expressRequireAction,
  fastifyAuth,
  fastifyRequireScope,
  fastifyRequireAction,
  mcpToolName,
} from './middleware.js';
