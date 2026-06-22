// Exercises the Express/Fastify middleware against the shared golden vectors
// (minted by the real Go signer) using fake request/response objects, so the
// integration layer is proven without pulling in express/fastify.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  Verifier,
  parseJWKS,
  expressAuth,
  expressRequireAction,
  fastifyAuth,
  fastifyRequireAction,
  mcpToolName,
  type Action,
} from '../src/index.js';

const v = JSON.parse(readFileSync(resolve(process.cwd(), '../conformance/vectors.json'), 'utf8'));
const keys = parseJWKS(v.jwks);
const verifier = new Verifier(v.issuer, v.audience, keys);

const validToken: string = v.verify.find((x: { valid: boolean }) => x.valid).token;
const allowVec = v.authorize.find((x: { allow: boolean }) => x.allow);
const denyVec = v.authorize.find((x: { allow: boolean }) => !x.allow);

function fakeExpress(authHeader?: string) {
  const res = {
    statusCode: 0,
    headers: {} as Record<string, string>,
    body: '',
    status(c: number) { this.statusCode = c; return this; },
    set(h: string, val: string) { this.headers[h] = val; return this; },
    send(b: string) { this.body = b; return this; },
  };
  const req: { headers: Record<string, string | undefined>; legant?: unknown } = {
    headers: authHeader ? { authorization: authHeader } : {},
  };
  let nexted = false;
  const next = () => { nexted = true; };
  return { req, res, next, wasNexted: () => nexted };
}

test('expressAuth: 401 without a token, attaches claims with one', () => {
  const noTok = fakeExpress();
  expressAuth(verifier)(noTok.req as never, noTok.res as never, noTok.next);
  assert.equal(noTok.res.statusCode, 401);
  assert.match(noTok.res.headers['WWW-Authenticate'] ?? '', /Bearer/);
  assert.equal(noTok.wasNexted(), false);

  const withTok = fakeExpress(`Bearer ${validToken}`);
  expressAuth(verifier)(withTok.req as never, withTok.res as never, withTok.next);
  assert.equal(withTok.wasNexted(), true);
  assert.ok(withTok.req.legant, 'claims attached to req.legant');
});

test('expressRequireAction: allows permitted, 403s denied', () => {
  // Each authorize vector pairs its OWN token with its action.
  const run = (token: string, action: Action) => {
    const f = fakeExpress(`Bearer ${token}`);
    expressAuth(verifier)(f.req as never, f.res as never, f.next);
    let allowed = false;
    expressRequireAction(() => action)(f.req as never, f.res as never, () => { allowed = true; });
    return { allowed, status: f.res.statusCode };
  };
  assert.equal(run(allowVec.token, allowVec.action).allowed, true);
  assert.equal(run(denyVec.token, denyVec.action).status, 403);
});

test('fastifyAuth + fastifyRequireAction', async () => {
  const reply = {
    statusCode: 0,
    headers: {} as Record<string, string>,
    code(c: number) { this.statusCode = c; return this; },
    header(h: string, val: string) { this.headers[h] = val; return this; },
    send() { return this; },
  };
  const req: { headers: Record<string, string>; legant?: unknown } = {
    headers: { authorization: `Bearer ${denyVec.token}` },
  };
  await fastifyAuth(verifier)(req as never, reply as never);
  assert.ok(req.legant, 'claims attached');
  await fastifyRequireAction(() => denyVec.action)(req as never, reply as never);
  assert.equal(reply.statusCode, 403);
});

test('mcpToolName parses tools/call', () => {
  assert.equal(
    mcpToolName({ method: 'tools/call', params: { name: 'kubectl_scale' } }),
    'kubectl_scale',
  );
  assert.throws(() => mcpToolName({ method: 'tools/list' }));
});
