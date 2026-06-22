/**
 * OAuth 2.1 primitives for a remote MCP server.
 *
 * Everything an Authorization Server needs, with no framework and an in-memory
 * store so the whole thing runs with `npx tsx src/server.ts`. Swap the in-memory
 * Maps for a real database and the demo consent for your real auth to ship it.
 *
 * Security choices that matter (see README): PKCE S256 required, authorization
 * codes single-use + hashed + short-TTL, refresh tokens rotated with family
 * revocation on replay, exact-hostname loopback matching, one pinned canonical
 * resource/issuer/aud.
 */

import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { SignJWT, jwtVerify } from 'jose';

// ── Canonical identifiers (must be byte-identical across PRM, AS, JWT aud) ──
export const ISSUER = (process.env.OAUTH_ISSUER || 'http://localhost:8080').replace(/\/+$/, '');
export const RESOURCE = (process.env.OAUTH_RESOURCE || 'http://localhost:8080/mcp').replace(/\/+$/, '');
const ACCESS_TTL = 3600; // 1h
const CODE_TTL_MS = 10 * 60 * 1000; // 10 min
const REFRESH_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 d

function secret(): Uint8Array {
  const s = process.env.OAUTH_JWT_SECRET || 'dev-only-insecure-secret-change-me-32bytes!!';
  return new TextEncoder().encode(s);
}

// ── small crypto helpers ──
export const sha256hex = (s: string) => createHash('sha256').update(s).digest('hex');
export const sha256b64url = (s: string) => createHash('sha256').update(s).digest('base64url');
export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a), bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}
const randToken = (n = 32) => randomBytes(n).toString('base64url');

// ── redirect_uri validation (exact-hostname loopback; never substring-match) ──
export function isAllowedRedirectUri(uri: string): boolean {
  let u: URL;
  try { u = new URL(uri); } catch { return false; }
  if (u.hash || u.username || u.password) return false;
  if (u.protocol === 'https:') return true;
  const h = u.hostname.toLowerCase();
  return u.protocol === 'http:' && (h === 'localhost' || h === '127.0.0.1' || h === '[::1]' || h === '::1');
}
export function redirectUriEquals(registered: string, presented: string): boolean {
  if (registered === presented) return true;
  let r: URL, p: URL;
  try { r = new URL(registered); p = new URL(presented); } catch { return false; }
  const h = r.hostname.toLowerCase();
  const loopback = r.protocol === 'http:' && (h === 'localhost' || h === '127.0.0.1' || h === '[::1]' || h === '::1');
  if (!loopback) return false; // non-loopback must be exact-equal (handled above)
  return p.protocol === r.protocol && p.hostname.toLowerCase() === h && p.pathname === r.pathname && !p.hash && !p.username;
}
export const resourceMatches = (v?: string | null) =>
  !!v && v.replace(/\/+$/, '') === RESOURCE;

// ── access-token JWTs ──
export async function signAccessToken(uid: string, clientId: string, scope: string) {
  const jti = randomUUID();
  const token = await new SignJWT({ scope, client_id: clientId, jti })
    .setProtectedHeader({ alg: 'HS256', kid: 'k1' })
    .setIssuer(ISSUER).setAudience(RESOURCE).setSubject(uid)
    .setIssuedAt().setExpirationTime(`${ACCESS_TTL}s`)
    .sign(secret());
  return { token, expiresIn: ACCESS_TTL };
}
export async function verifyAccessToken(token: string): Promise<{ uid: string; scope: string } | null> {
  try {
    const { payload } = await jwtVerify(token, secret(), { issuer: ISSUER, audience: RESOURCE, algorithms: ['HS256'] });
    if (typeof payload.sub !== 'string') return null;
    return { uid: payload.sub, scope: typeof payload.scope === 'string' ? payload.scope : '' };
  } catch { return null; }
}
export const looksLikeJwt = (b: string) => /^[\w-]+\.[\w-]+\.[\w-]+$/.test(b);

// ── in-memory store (replace with a database) ──
interface Client { client_id: string; client_name: string; redirect_uris: string[] }
interface Code { clientId: string; uid: string; redirectUri: string; codeChallenge: string; scope: string; used: boolean; expiresAt: number }
interface Refresh { uid: string; clientId: string; familyId: string; scope: string; used: boolean; revoked: boolean; expiresAt: number }

const clients = new Map<string, Client>();
const codes = new Map<string, Code>();      // key = sha256(code)
const refresh = new Map<string, Refresh>(); // key = sha256(token)

export function createClient(client_name: string, redirect_uris: string[]): Client {
  const c: Client = { client_id: randomUUID(), client_name: client_name.slice(0, 200), redirect_uris };
  clients.set(c.client_id, c);
  return c;
}
export const getClient = (id: string) => clients.get(id) || null;

export function createCode(data: Omit<Code, 'used' | 'expiresAt'>): string {
  const raw = randToken();
  codes.set(sha256hex(raw), { ...data, used: false, expiresAt: Date.now() + CODE_TTL_MS });
  return raw;
}
export function consumeCode(raw: string): Code | { error: string } {
  const key = sha256hex(raw);
  const c = codes.get(key);
  if (!c) return { error: 'invalid_grant' };
  if (c.expiresAt < Date.now()) { codes.delete(key); return { error: 'invalid_grant' }; }
  if (c.used) {
    // Replay of a consumed code → revoke any tokens minted from it (defense in depth).
    for (const r of refresh.values()) if (r.familyId) r.revoked = true;
    return { error: 'invalid_grant' };
  }
  c.used = true;
  return c;
}

export function createRefresh(data: Omit<Refresh, 'used' | 'revoked' | 'expiresAt'>): string {
  const raw = randToken(40);
  refresh.set(sha256hex(raw), { ...data, used: false, revoked: false, expiresAt: Date.now() + REFRESH_TTL_MS });
  return raw;
}
export function rotateRefresh(raw: string): Refresh | { error: string } {
  const key = sha256hex(raw);
  const r = refresh.get(key);
  if (!r) return { error: 'invalid_grant' };
  if (r.expiresAt < Date.now()) { refresh.delete(key); return { error: 'invalid_grant' }; }
  if (r.used || r.revoked) {
    // Reuse detected → revoke the whole family.
    for (const o of refresh.values()) if (o.familyId === r.familyId) o.revoked = true;
    return { error: 'invalid_grant' };
  }
  r.used = true;
  return r;
}
export const newFamilyId = () => randomUUID();

// ── PKCE ──
export const verifyPkce = (codeVerifier: string, codeChallenge: string) =>
  safeEqual(sha256b64url(codeVerifier), codeChallenge);
