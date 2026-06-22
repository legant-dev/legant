// Resource-server middleware for Express and Fastify. A backend becomes a
// Legant-protected resource server in a few lines: verify the Bearer token, attach
// the verified Claims to the request, and (optionally) authorize a per-request
// Action. This is the delegation-aware analog of a generic OIDC JWT middleware — it
// understands the act chain, the constraint dimensions, RFC 8707 audience
// canonicalization, and the signed revocation feed.
//
// Express and Fastify are NOT dependencies of this package; the request/response
// objects are typed structurally so importing this module pulls in nothing.

import { Verifier, Claims, type Action } from './verifier.js';

/** Extracts the token from an `Authorization: Bearer <token>` header value. */
export function bearerToken(authHeader?: string): string {
  if (!authHeader) throw new Error('missing Authorization header');
  const m = /^Bearer\s+(.+)$/i.exec(authHeader.trim());
  if (!m) throw new Error('Authorization header is not a Bearer token');
  return m[1].trim();
}

/** Verifies the Bearer token from an Authorization header value (throws on failure). */
export function authenticate(verifier: Verifier, authHeader?: string): Claims {
  return verifier.verify(bearerToken(authHeader));
}

// Minimal structural shapes so we depend on neither express nor fastify types.
interface ReqLike {
  headers: Record<string, string | string[] | undefined>;
  legant?: Claims;
}
interface ExpressResLike {
  status(code: number): ExpressResLike;
  set(field: string, value: string): ExpressResLike;
  send(body: string): unknown;
}
type ExpressNext = (err?: unknown) => void;
interface FastifyReplyLike {
  code(statusCode: number): FastifyReplyLike;
  header(name: string, value: string): FastifyReplyLike;
  send(body: string): unknown;
}

function authHeaderOf(req: ReqLike): string | undefined {
  const h = req.headers['authorization'] ?? req.headers['Authorization'];
  return Array.isArray(h) ? h[0] : h;
}

// ---- Express ---------------------------------------------------------------

/**
 * Express middleware that verifies the Bearer token and stores the Claims on
 * `req.legant`. On failure it sends 401 with an RFC 6750 challenge. Revocation
 * behavior follows how the Verifier was built (a revocation feed → revoked tokens
 * 401 here; otherwise revocation is bounded by the token TTL).
 *
 *   app.use(expressAuth(verifier));
 *   app.get('/data', expressRequireScope('data:read'), handler);
 */
export function expressAuth(verifier: Verifier) {
  return (req: ReqLike, res: ExpressResLike, next: ExpressNext): void => {
    try {
      req.legant = authenticate(verifier, authHeaderOf(req));
      next();
    } catch (e) {
      expressChallenge(res, 401, 'invalid_token', errMsg(e));
    }
  };
}

/** Express middleware (mount AFTER expressAuth) requiring the token to carry scope. */
export function expressRequireScope(scope: string) {
  return expressRequireAction(() => ({ scope }));
}

/** Express middleware (mount AFTER expressAuth) authorizing a per-request Action. */
export function expressRequireAction(action: (req: ReqLike) => Action) {
  return (req: ReqLike, res: ExpressResLike, next: ExpressNext): void => {
    const claims = req.legant;
    if (!claims) return void expressChallenge(res, 401, 'invalid_token', 'no verified token (mount expressAuth first)');
    try {
      claims.authorize(action(req));
      next();
    } catch (e) {
      expressChallenge(res, 403, 'insufficient_scope', errMsg(e));
    }
  };
}

function expressChallenge(res: ExpressResLike, code: number, err: string, desc: string): void {
  res
    .status(code)
    .set('WWW-Authenticate', `Bearer error="${err}", error_description="${desc}"`)
    .send(`${err}: ${desc}`);
}

// ---- Fastify ---------------------------------------------------------------

/**
 * Fastify preHandler hook that verifies the Bearer token and stores the Claims on
 * `request.legant`.
 *
 *   fastify.addHook('preHandler', fastifyAuth(verifier));
 *   fastify.get('/data', { preHandler: fastifyRequireScope('data:read') }, handler);
 */
export function fastifyAuth(verifier: Verifier) {
  return async (req: ReqLike, reply: FastifyReplyLike): Promise<void> => {
    try {
      req.legant = authenticate(verifier, authHeaderOf(req));
    } catch (e) {
      fastifyChallenge(reply, 401, 'invalid_token', errMsg(e));
    }
  };
}

/** Fastify preHandler (after fastifyAuth) requiring the token to carry scope. */
export function fastifyRequireScope(scope: string) {
  return fastifyRequireAction(() => ({ scope }));
}

/** Fastify preHandler (after fastifyAuth) authorizing a per-request Action. */
export function fastifyRequireAction(action: (req: ReqLike) => Action) {
  return async (req: ReqLike, reply: FastifyReplyLike): Promise<void> => {
    const claims = req.legant;
    if (!claims) return void fastifyChallenge(reply, 401, 'invalid_token', 'no verified token (add fastifyAuth first)');
    try {
      claims.authorize(action(req));
    } catch (e) {
      fastifyChallenge(reply, 403, 'insufficient_scope', errMsg(e));
    }
  };
}

function fastifyChallenge(reply: FastifyReplyLike, code: number, err: string, desc: string): void {
  reply
    .code(code)
    .header('WWW-Authenticate', `Bearer error="${err}", error_description="${desc}"`)
    .send(`${err}: ${desc}`);
}

// ---- self-hosted MCP server helper -----------------------------------------

/**
 * Extracts the tool name from a JSON-RPC MCP `tools/call` request body, for
 * resource servers that ARE an MCP server. Pair with claims.authorize:
 *
 *   const name = mcpToolName(req.body);
 *   req.legant!.authorize({ scope: toolScopes[name], tool: name });
 */
export function mcpToolName(body: unknown): string {
  const b = typeof body === 'string' ? JSON.parse(body) : (body as { method?: string; params?: { name?: string } });
  if (!b || b.method !== 'tools/call') throw new Error(`not a tools/call (method=${(b as { method?: string })?.method})`);
  const name = b.params?.name;
  if (!name) throw new Error('tools/call missing params.name');
  return name;
}

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
