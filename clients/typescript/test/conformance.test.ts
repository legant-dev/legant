// Runs the shared golden vectors (clients/conformance/vectors.json, minted by the
// real Go signer) through the TypeScript SDK. Identical assertions run against
// the Go and Python SDKs, so the three cannot drift. Run from clients/typescript:
//   npm test
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { Verifier, parseJWKS, RevocationFeed, RevokedError } from '../src/index.js';

const v = JSON.parse(readFileSync(resolve(process.cwd(), '../conformance/vectors.json'), 'utf8'));
const keys = parseJWKS(v.jwks);

test('verify vectors', () => {
  const ver = new Verifier(v.issuer, v.audience, keys);
  for (const c of v.verify) {
    if (c.valid) {
      const claims = ver.verify(c.token);
      if (c.provenance) assert.equal(claims.provenance(), c.provenance, c.name);
    } else {
      assert.throws(() => ver.verify(c.token), c.name);
    }
  }
});

test('audience canonicalization vectors', () => {
  for (const c of v.audienceCanonicalization) {
    const ver = new Verifier(v.issuer, c.configuredAudience, keys);
    if (c.valid) {
      assert.doesNotThrow(() => ver.verify(c.token), c.name);
    } else {
      assert.throws(() => ver.verify(c.token), c.name);
    }
  }
});

test('authorize vectors', () => {
  const ver = new Verifier(v.issuer, v.audience, keys);
  for (const c of v.authorize) {
    const claims = ver.verify(c.token);
    const action = {
      scope: c.action.scope,
      amount: c.action.amount,
      category: c.action.category,
      tool: c.action.tool,
      resource: c.action.resource,
      at: c.action.at ? new Date(c.action.at) : undefined,
    };
    let allowed = true;
    try {
      claims.authorize(action);
    } catch {
      allowed = false;
    }
    assert.equal(allowed, c.allow, c.name);
  }
});

test('revocation feed vectors', () => {
  const r = v.revocation;
  const feed = new RevocationFeed(null, v.issuer, keys);
  feed.applyFeed(r.feed);
  assert.equal(feed.isRevoked(r.revokedJti), true, 'revoked jti present');
  assert.equal(feed.isRevoked(r.liveJti), false, 'live jti absent');

  const ver = new Verifier(v.issuer, v.audience, keys, { feed });
  assert.throws(() => ver.verify(r.revokedToken), RevokedError, 'revoked token rejected');
  assert.doesNotThrow(() => ver.verify(r.liveToken), 'live token verifies');

  // A rollback (lower version) is rejected; revocation persists.
  assert.throws(() => feed.applyFeed(r.feedRollback), 'rollback rejected');
  assert.equal(feed.isRevoked(r.revokedJti), true, 'still revoked after rollback');

  // A newer feed dropping the jti clears the revocation.
  feed.applyFeed(r.feedNewer);
  assert.equal(feed.isRevoked(r.revokedJti), false, 'un-revoked by newer feed');
});
