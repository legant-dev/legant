// Framework-agnostic tool authorization for AI agents.
//
// Wrap any tool — a Vercel AI SDK `tool({ execute })`, a Mastra / LangChain.js
// tool, or a plain function — so every invocation is authorized against a Legant
// delegation token, offline, with no callback. The agent only ever wields the
// scoped, attenuating, revocable slice of authority the token carries.
//
//   const guard = new AgentGuard(verifier, agentDelegationToken);
//
//   const submit = guard.tool('expenses:submit', rawSubmit,
//     { amountArg: 'amount', categoryArg: 'category' });
//   // submit({ amount, category }) only runs if the token permits it, else throws.

import { Claims, Verifier, type Action } from './verifier.js';

/** A token string, or a (optionally async) function returning one (to refresh). */
export type TokenSource = string | (() => string) | (() => Promise<string>);

export interface ToolGuardOptions {
  /** Legant tool-constraint value to check (default: not constrained by tool). */
  tool?: string;
  /** Resource audience to check (default: not constrained by resource). */
  resource?: string;
  /** Key of the tool's first (object) argument holding the monetary amount. */
  amountArg?: string;
  /** Key of the tool's first (object) argument holding the category. */
  categoryArg?: string;
}

export class AgentGuard {
  constructor(
    private readonly verifier: Verifier,
    private readonly token: TokenSource,
  ) {}

  private async currentToken(): Promise<string> {
    return typeof this.token === 'function' ? await this.token() : this.token;
  }

  /** Verify the current token and authorize one action. Throws VerifyError /
   *  RevokedError on a bad token, or an Error if the action exceeds the grant. */
  async authorize(scope: string, opts: Omit<Action, 'scope'> = {}): Promise<Claims> {
    const claims = this.verifier.verify(await this.currentToken());
    claims.authorize({ scope, ...opts });
    return claims;
  }

  /** Non-throwing check — true iff `authorize` would succeed. */
  async allowed(scope: string, opts: Omit<Action, 'scope'> = {}): Promise<boolean> {
    try {
      await this.authorize(scope, opts);
      return true;
    } catch {
      return false;
    }
  }

  /** Wrap a tool function so it authorizes before running. `amountArg` /
   *  `categoryArg` name keys of the tool's first (object) argument to read the
   *  amount / category from, so constraint checks use the real call values. */
  tool<A extends unknown[], R>(
    scope: string,
    fn: (...args: A) => R | Promise<R>,
    opts: ToolGuardOptions = {},
  ): (...args: A) => Promise<R> {
    return async (...args: A): Promise<R> => {
      const a0 = (args[0] ?? {}) as Record<string, unknown>;
      const amount = opts.amountArg ? Number(a0[opts.amountArg] ?? 0) || 0 : undefined;
      const category = opts.categoryArg ? String(a0[opts.categoryArg] ?? '') : undefined;
      await this.authorize(scope, {
        tool: opts.tool,
        resource: opts.resource,
        amount,
        category,
      });
      return await fn(...args);
    };
  }
}
