// Offline verifier + authorizer for Legant delegation tokens. Verifies a
// composite sub/act token against the issuer's JWKS and authorizes a request's
// scope and constraints — entirely offline, no callback to Legant. Zero runtime
// dependencies: RS256 verification uses Node's built-in `crypto`.
import { createPublicKey, verify as nodeVerify, type KeyObject } from 'node:crypto';
import type { RevocationFeed } from './revocation.js';

export interface Actor {
  sub: string;
  act?: Actor;
}

export interface TimeWindow {
  weekdays?: number[]; // 0=Sun … 6=Sat; empty = any day
  start_min: number; // inclusive minute-of-day [0,1439]
  end_min: number;
  tz?: string; // IANA name; empty = UTC
}

export interface RateLimit {
  max_per_hour: number;
}

export interface Constraints {
  max_amount?: number;
  categories?: string[];
  tools?: string[];
  resources?: string[];
  time_window?: TimeWindow;
  rate?: RateLimit; // informational at the RS; enforced by Legant at mint time
}

export interface Action {
  scope: string;
  amount?: number;
  category?: string;
  tool?: string;
  resource?: string;
  at?: Date; // instant of the action; default now (for the time-window check)
}

// denyAll is the sentinel Legant puts in an allow-list that intersected to
// nothing during re-delegation. It matches no real value and denies the
// dimension entirely. Must match internal/delegation and the Go SDK.
const DENY_ALL = '\u0000legant:deny-all';

/** Thrown by Verifier.verify when the token's jti is in the revocation feed. */
export class RevokedError extends Error {
  constructor() {
    super('token revoked');
    this.name = 'RevokedError';
  }
}

interface RawClaims {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  iat?: number;
  jti?: string;
  scope?: string;
  act?: Actor;
  cnst?: Constraints;
}

/** The verified body of a delegation token. */
export class Claims {
  constructor(private readonly c: RawClaims) {}

  get subject(): string {
    return this.c.sub ?? '';
  }
  get jti(): string {
    return this.c.jti ?? '';
  }
  get scope(): string {
    return this.c.scope ?? '';
  }
  get act(): Actor | undefined {
    return this.c.act;
  }
  get constraints(): Constraints | undefined {
    return this.c.cnst;
  }

  /** Renders the delegation path, e.g. "user:alice -> agent:assistant -> agent:ocr". */
  provenance(): string {
    const parts = [this.c.sub ?? ''];
    const chain: string[] = [];
    for (let a = this.c.act; a; a = a.act) chain.push(a.sub);
    for (let i = chain.length - 1; i >= 0; i--) parts.push(chain[i]);
    return parts.join(' -> ');
  }

  /** Throws if the token lacks the required scope or the action violates a constraint. */
  authorize(a: Action): void {
    if (!hasScope(this.c.scope ?? '', a.scope)) {
      throw new Error(`missing required scope "${a.scope}"`);
    }
    const k = this.c.cnst;
    if (!k) return;
    if (k.max_amount != null && (a.amount ?? 0) > k.max_amount) {
      throw new Error(`amount ${a.amount ?? 0} exceeds max_amount ${k.max_amount}`);
    }
    permitList('category', k.categories, a.category ?? '', false);
    permitList('tool', k.tools, a.tool ?? '', false);
    permitList('resource', k.resources, a.resource ?? '', true);
    if (k.time_window) {
      const at = a.at ?? new Date();
      if (!timeWindowAllows(k.time_window, at)) {
        throw new Error('action is outside the delegated time window');
      }
    }
  }
}

export interface VerifierOptions {
  /** Tier B offline revocation: reject tokens whose jti is in this feed. */
  feed?: RevocationFeed;
  /** Reject tokens when the feed is staler than this many milliseconds (default: fail open to TTL). */
  feedFailClosedMs?: number;
}

/** Verifies delegation tokens against a fixed issuer and audience. */
export class Verifier {
  constructor(
    private readonly issuer: string,
    private readonly audience: string,
    private readonly keys: Map<string, KeyObject>,
    private readonly opts: VerifierOptions = {},
  ) {}

  /**
   * Verifies a token: RS256 signature under the key named by its kid, plus
   * issuer, expiry, not-before, and audience. Requires an act claim (a delegation
   * token, not a plain access token). Throws on any failure.
   */
  verify(token: string): Claims {
    const parts = token.split('.');
    if (parts.length !== 3) throw new Error('malformed token');
    const [h, p, s] = parts;
    const header = JSON.parse(Buffer.from(h, 'base64url').toString());
    if (header.alg !== 'RS256') throw new Error(`unexpected alg ${header.alg}`);
    if (!header.kid) throw new Error('token missing kid header');
    const key = this.keys.get(header.kid);
    if (!key) throw new Error(`unknown signing key "${header.kid}"`);
    if (!nodeVerify('RSA-SHA256', Buffer.from(`${h}.${p}`), key, Buffer.from(s, 'base64url'))) {
      throw new Error('signature verification failed');
    }
    const c: RawClaims = JSON.parse(Buffer.from(p, 'base64url').toString());
    if (c.iss !== this.issuer) throw new Error('invalid issuer');
    const now = Date.now();
    if (c.exp == null) throw new Error('token has no expiration');
    if (now >= c.exp * 1000) throw new Error('token is expired');
    if (c.nbf != null && now < c.nbf * 1000) throw new Error('token is not valid yet');
    if (!c.act) throw new Error('not a delegation token (no act claim)');
    if (!audienceMatches(c.aud, this.audience)) {
      throw new Error('token audience does not include this resource server');
    }
    if (this.opts.feed) {
      if (this.opts.feedFailClosedMs != null && this.opts.feed.staleness() > this.opts.feedFailClosedMs) {
        throw new Error('revocation feed is stale and fail-closed is set');
      }
      if (c.jti && this.opts.feed.isRevoked(c.jti)) throw new RevokedError();
    }
    return new Claims(c);
  }
}

function hasScope(scopeStr: string, want: string): boolean {
  return scopeStr.split(/\s+/).filter(Boolean).includes(want);
}

function permitList(dim: string, allowed: string[] | undefined, value: string, canonical: boolean): void {
  if (!allowed || allowed.length === 0) return;
  if (allowed.includes(DENY_ALL)) throw new Error(`${dim} access is fully restricted by the delegation`);
  if (value === '') return;
  let match = allowed.includes(value);
  if (!match && canonical) {
    const cv = canonicalizeAudience(value);
    match = allowed.some((a) => canonicalizeAudience(a) === cv);
  }
  if (!match) throw new Error(`${dim} "${value}" not permitted`);
}

function audienceMatches(aud: string | string[] | undefined, want: string): boolean {
  const auds = aud == null ? [] : Array.isArray(aud) ? aud : [aud];
  const cw = canonicalizeAudience(want);
  return auds.some((a) => canonicalizeAudience(a) === cw);
}

/**
 * Mirrors the issuer's RFC 8707 canonicalization: lowercase scheme+host, strip a
 * default port, drop userinfo and fragment, and treat an empty path as "/".
 * Non-absolute values are returned unchanged. (Node's URL already lowercases the
 * scheme/host and drops the default port.)
 */
function canonicalizeAudience(raw: string): string {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return raw;
  }
  if (!u.host) return raw; // e.g. urn:… — no authority
  const path = u.pathname === '' ? '/' : u.pathname;
  return `${u.protocol}//${u.host}${path}${u.search}`;
}

const WEEKDAY: Record<string, number> = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 };

function timeWindowAllows(w: TimeWindow, at: Date): boolean {
  const tz = w.tz && w.tz !== '' ? w.tz : 'UTC';
  let wd: number;
  let minutes: number;
  try {
    const parts = new Intl.DateTimeFormat('en-US', {
      timeZone: tz,
      weekday: 'short',
      hour: '2-digit',
      minute: '2-digit',
      hourCycle: 'h23',
    }).formatToParts(at);
    const get = (t: string) => parts.find((x) => x.type === t)?.value ?? '';
    wd = WEEKDAY[get('weekday')];
    minutes = parseInt(get('hour'), 10) * 60 + parseInt(get('minute'), 10);
  } catch {
    return false; // unknown timezone fails closed
  }
  if (w.weekdays && w.weekdays.length > 0 && !w.weekdays.includes(wd)) return false;
  return minutes >= w.start_min && minutes <= w.end_min;
}

/** Parses a JWKS document into a kid->key map (RSA keys only). */
export function parseJWKS(doc: { keys?: Array<{ kty?: string; kid?: string; n?: string; e?: string }> }): Map<string, KeyObject> {
  const out = new Map<string, KeyObject>();
  for (const k of doc.keys ?? []) {
    if (k.kty !== 'RSA' || !k.kid || !k.n || !k.e) continue;
    if (Buffer.from(k.n, 'base64url').length * 8 < 2048) {
      throw new Error(`jwk ${k.kid}: modulus too small (want >= 2048 bits)`);
    }
    out.set(k.kid, createPublicKey({ key: { kty: 'RSA', n: k.n, e: k.e }, format: 'jwk' }));
  }
  return out;
}

/** Fetches and parses an issuer's JWKS. Pass a trusted, configured URL. */
export async function fetchJWKS(jwksURL: string): Promise<Map<string, KeyObject>> {
  const r = await fetch(jwksURL);
  if (!r.ok) throw new Error(`jwks endpoint returned ${r.status}`);
  return parseJWKS(await r.json());
}
