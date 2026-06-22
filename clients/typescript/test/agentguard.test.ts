// AgentGuard runs the same shared conformance authorize vectors through the
// framework-agnostic tool wrapper, so the agent-facing adapter can't drift from
// the SDK's authorization. Mirrors the Python tests/test_agentguard.py.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { Verifier, parseJWKS, AgentGuard } from '../src/index.js';

const v = JSON.parse(readFileSync(resolve(process.cwd(), '../conformance/vectors.json'), 'utf8'));
const keys = parseJWKS(v.jwks);
const guardFor = (token: string) => new AgentGuard(new Verifier(v.issuer, v.audience, keys), token);

test('AgentGuard authorize vectors', async () => {
  for (const c of v.authorize) {
    const a = c.action;
    const ok = await guardFor(c.token).allowed(a.scope, {
      amount: a.amount,
      category: a.category,
      tool: a.tool,
      resource: a.resource,
      at: a.at ? new Date(a.at) : undefined,
    });
    assert.equal(ok, c.allow, c.name);
  }
});

test('AgentGuard tool wrapper enforces before running', async () => {
  const allow = v.authorize.find((c: any) => c.allow && c.action.scope === 'expenses:submit');
  const deny = v.authorize.find((c: any) => !c.allow && 'amount' in c.action);
  let calls = 0;
  const raw = (_a: { amount: number; category: string }) => {
    calls++;
    return 'submitted';
  };
  const opts = { amountArg: 'amount', categoryArg: 'category' };

  const okTool = guardFor(allow.token).tool('expenses:submit', raw, opts);
  assert.equal(await okTool({ amount: allow.action.amount ?? 0, category: allow.action.category ?? '' }), 'submitted');
  assert.equal(calls, 1);

  const denyTool = guardFor(deny.token).tool('expenses:submit', raw, opts);
  await assert.rejects(() => denyTool({ amount: deny.action.amount ?? 0, category: deny.action.category ?? '' }));
  assert.equal(calls, 1); // body did NOT run — blocked first
});
