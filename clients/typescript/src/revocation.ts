// Tier B offline revocation: a pull-based view of revoked tokens. The resource
// server fetches a signed feed from the issuer on a timer and checks token ids
// against an in-memory set — no per-request callback. A stale or missing feed can
// only ever MISS a revocation, never invent one, and a regressing version is
// rejected as a rollback. RS256 verification uses Node's built-in `crypto`.
import { verify as nodeVerify, type KeyObject } from 'node:crypto';

export class RevocationFeed {
  private revoked = new Set<string>();
  private version = 0;
  private fetchedAt = 0;

  constructor(
    private readonly url: string | null,
    private readonly issuer: string,
    private readonly keys: Map<string, KeyObject>,
  ) {}

  /**
   * Verifies and applies a signed feed JWS (RS256 under the issuer's kid, issuer
   * + expiry required), enforcing a monotonic version, then atomically swaps the
   * in-memory set. Use this to push feeds from any transport; refresh() is the
   * HTTP convenience.
   */
  applyFeed(jws: string): void {
    const [h, p, s] = jws.split('.');
    const header = JSON.parse(Buffer.from(h, 'base64url').toString());
    if (header.alg !== 'RS256') throw new Error(`unexpected alg ${header.alg}`);
    const key = this.keys.get(header.kid);
    if (!key) throw new Error(`unknown feed signing key "${header.kid}"`);
    if (!nodeVerify('RSA-SHA256', Buffer.from(`${h}.${p}`), key, Buffer.from(s, 'base64url'))) {
      throw new Error('feed signature verification failed');
    }
    const c = JSON.parse(Buffer.from(p, 'base64url').toString());
    if (c.iss !== this.issuer) throw new Error('feed issuer mismatch');
    if (c.exp == null || Date.now() >= c.exp * 1000) throw new Error('feed is expired or missing exp');
    const ver = Number(c.ver ?? 0);
    if (ver < this.version) {
      throw new Error(`revocation feed version regressed (${ver} < ${this.version}) — possible rollback, keeping current`);
    }
    this.revoked = new Set<string>(c.jtis ?? []);
    this.version = ver;
    this.fetchedAt = Date.now();
  }

  /** Fetches the feed from its URL and applies it. */
  async refresh(): Promise<void> {
    if (!this.url) throw new Error('revocation feed has no URL');
    const r = await fetch(this.url);
    if (!r.ok) throw new Error(`revocation feed returned ${r.status}`);
    this.applyFeed(await r.text());
  }

  /** Refreshes on an interval until the returned stop function is called. Errors are non-fatal. */
  startPolling(intervalMs: number, onError?: (e: unknown) => void): () => void {
    const id = setInterval(() => {
      this.refresh().catch((e) => onError?.(e));
    }, intervalMs);
    return () => clearInterval(id);
  }

  /** Reports whether a token id is in the latest feed snapshot. */
  isRevoked(jti: string): boolean {
    return this.revoked.has(jti);
  }

  /** Milliseconds since the feed was last successfully applied. */
  staleness(): number {
    return Date.now() - this.fetchedAt;
  }
}

/** Fetches and verifies the issuer's revocation feed once. */
export async function fetchRevocationFeed(
  feedURL: string,
  issuer: string,
  keys: Map<string, KeyObject>,
): Promise<RevocationFeed> {
  const f = new RevocationFeed(feedURL, issuer, keys);
  await f.refresh();
  return f;
}
