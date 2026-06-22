/**
 * A remote MCP server protected by OAuth 2.1 — runnable reference.
 *
 *   npx tsx src/server.ts        # then add http://localhost:8080/mcp to an MCP client
 *
 * Implements the full flow a client like Claude Desktop drives:
 *   POST /mcp (no token) → 401 + WWW-Authenticate → discovery → DCR → authorize
 *   → consent → token (PKCE) → POST /mcp (Bearer) → tools.
 *
 * Two things to replace before this is production:
 *   1. The demo consent (`renderConsent` / DEMO_USER) — authenticate your real
 *      user, then mint the code for THEIR id.
 *   2. The in-memory store in oauth.ts — use a database.
 */

import { createServer, IncomingMessage, ServerResponse } from 'node:http';
import { randomUUID } from 'node:crypto';
import {
  ISSUER, RESOURCE,
  createClient, getClient, createCode, consumeCode, createRefresh, rotateRefresh, newFamilyId,
  signAccessToken, verifyAccessToken, looksLikeJwt, verifyPkce,
  isAllowedRedirectUri, redirectUriEquals, resourceMatches,
} from './oauth.js';

const PORT = Number(process.env.PORT || 8080);
const DEMO_USER = 'demo-user@example.com'; // ← replace with your authenticated user's id

// ── tiny http helpers ──
const json = (res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}) =>
  res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers }).end(JSON.stringify(body));
const html = (res: ServerResponse, status: number, body: string) =>
  res.writeHead(status, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' }).end(body);
const redirect = (res: ServerResponse, location: string) => res.writeHead(302, { location }).end();
function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve) => { let b = ''; req.on('data', (c) => (b += c)); req.on('end', () => resolve(b)); });
}

// ── discovery metadata (RFC 9728 + RFC 8414) ──
const prm = () => ({ resource: RESOURCE, authorization_servers: [ISSUER], scopes_supported: ['mcp'], bearer_methods_supported: ['header'] });
const asMeta = () => ({
  issuer: ISSUER,
  authorization_endpoint: `${ISSUER}/authorize`,
  token_endpoint: `${ISSUER}/token`,
  registration_endpoint: `${ISSUER}/register`,
  response_types_supported: ['code'],
  grant_types_supported: ['authorization_code', 'refresh_token'],
  code_challenge_methods_supported: ['S256'],
  token_endpoint_auth_methods_supported: ['none'],
  scopes_supported: ['mcp'],
});

// ── demo MCP tools (replace with yours) ──
const TOOLS = [
  { name: 'echo', description: 'Echo back the provided text.', inputSchema: { type: 'object', properties: { text: { type: 'string' } }, required: ['text'] } },
  { name: 'whoami', description: 'Return the authenticated user id from the OAuth token.', inputSchema: { type: 'object', properties: {} } },
];
function runTool(name: string, args: Record<string, unknown>, uid: string) {
  if (name === 'echo') return { content: [{ type: 'text', text: String(args.text ?? '') }] };
  if (name === 'whoami') return { content: [{ type: 'text', text: `You are authenticated as: ${uid}` }] };
  return { content: [{ type: 'text', text: `Unknown tool: ${name}` }], isError: true };
}

// ── consent screen (DEMO: no real login — wire in your auth here) ──
function renderConsent(q: URLSearchParams, client: { client_name: string }): string {
  const hidden = ['client_id', 'redirect_uri', 'code_challenge', 'code_challenge_method', 'scope', 'state', 'resource']
    .map((k) => `<input type="hidden" name="${k}" value="${escapeHtml(q.get(k) || '')}">`).join('');
  let host = q.get('redirect_uri') || '';
  try { host = new URL(host).host; } catch { /* keep raw */ }
  return `<!doctype html><html><head><meta charset="utf-8"><title>Authorize</title>
  <style>body{font:16px system-ui;max-width:30rem;margin:6rem auto;padding:1rem}.card{border:1px solid #ddd;border-radius:12px;padding:1.5rem}button{font:inherit;padding:.6rem 1rem;border-radius:8px;border:1px solid #ccc;cursor:pointer}.primary{background:#111;color:#fff;border-color:#111}</style></head>
  <body><div class="card">
    <p style="color:#888;text-transform:uppercase;letter-spacing:.1em;font-size:.75rem">Authorization request</p>
    <h2>${escapeHtml(client.client_name)} wants access</h2>
    <p>Grant <b>${escapeHtml(client.client_name)}</b> read access (<code>${escapeHtml(q.get('scope') || 'mcp')}</code>).</p>
    <p style="font-size:.9rem;color:#555">Redirects to <code>${escapeHtml(host)}</code><br>Signed in as <code>${DEMO_USER}</code> <i>(demo — replace with your auth)</i></p>
    <form method="post" action="/authorize/consent">${hidden}
      <button type="submit" name="action" value="deny">Deny</button>
      <button type="submit" name="action" value="approve" class="primary">Approve</button>
    </form>
  </div></body></html>`;
}
const escapeHtml = (s: string) => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));

// ── server ──
const server = createServer(async (req, res) => {
  const url = new URL(req.url || '/', `http://localhost:${PORT}`);
  const { pathname } = url;
  const method = req.method || 'GET';

  // Discovery
  if (method === 'GET' && pathname === '/.well-known/oauth-protected-resource') return json(res, 200, prm());
  if (method === 'GET' && pathname === '/.well-known/oauth-authorization-server') return json(res, 200, asMeta());

  // Dynamic Client Registration (RFC 7591)
  if (method === 'POST' && pathname === '/register') {
    const body = safeJson(await readBody(req));
    const redirectUris = Array.isArray(body?.redirect_uris) ? body.redirect_uris.filter((u: unknown): u is string => typeof u === 'string') : [];
    if (!redirectUris.length || !redirectUris.every(isAllowedRedirectUri)) return json(res, 400, { error: 'invalid_redirect_uri' });
    const c = createClient(typeof body?.client_name === 'string' ? body.client_name : 'MCP Client', redirectUris);
    return json(res, 201, { client_id: c.client_id, token_endpoint_auth_method: 'none', grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'], redirect_uris: c.redirect_uris, client_name: c.client_name });
  }

  // Authorize (GET) — validate, then show consent. Never open-redirect.
  if (method === 'GET' && pathname === '/authorize') {
    const clientId = url.searchParams.get('client_id') || '';
    const redirectUri = url.searchParams.get('redirect_uri') || '';
    const client = getClient(clientId);
    if (!client) return html(res, 400, 'Unknown client_id');
    if (!client.redirect_uris.some((r) => redirectUriEquals(r, redirectUri))) return html(res, 400, 'redirect_uri not registered');
    if (url.searchParams.get('response_type') !== 'code') return badRedirect(res, redirectUri, 'unsupported_response_type', url.searchParams.get('state'));
    if (url.searchParams.get('code_challenge_method') !== 'S256' || !url.searchParams.get('code_challenge')) return badRedirect(res, redirectUri, 'invalid_request', url.searchParams.get('state'));
    if (url.searchParams.get('resource') && !resourceMatches(url.searchParams.get('resource'))) return badRedirect(res, redirectUri, 'invalid_target', url.searchParams.get('state'));
    return html(res, 200, renderConsent(url.searchParams, client));
  }

  // Consent (POST) — the real grant. In production: authenticate the user here.
  if (method === 'POST' && pathname === '/authorize/consent') {
    if (!sameOrigin(req)) return json(res, 403, { error: 'invalid_request', error_description: 'cross-origin' });
    const form = new URLSearchParams(await readBody(req));
    const clientId = form.get('client_id') || '';
    const redirectUri = form.get('redirect_uri') || '';
    const client = getClient(clientId);
    if (!client || !client.redirect_uris.some((r) => redirectUriEquals(r, redirectUri))) return json(res, 400, { error: 'invalid_request' });
    const state = form.get('state') || '';
    if (form.get('action') !== 'approve') return redirect(res, addParams(redirectUri, { error: 'access_denied', state }));
    const code = createCode({ clientId, uid: DEMO_USER, redirectUri, codeChallenge: form.get('code_challenge') || '', scope: 'mcp' });
    return redirect(res, addParams(redirectUri, { code, state }));
  }

  // Token (OAuth 2.1)
  if (method === 'POST' && pathname === '/token') {
    const form = new URLSearchParams(await readBody(req));
    const grant = form.get('grant_type');
    if (form.get('resource') && !resourceMatches(form.get('resource'))) return json(res, 400, { error: 'invalid_target' });

    if (grant === 'authorization_code') {
      const c = consumeCode(form.get('code') || '');
      if ('error' in c) return json(res, 400, { error: 'invalid_grant' });
      if (c.clientId !== form.get('client_id')) return json(res, 400, { error: 'invalid_grant' });
      if (!redirectUriEquals(c.redirectUri, form.get('redirect_uri') || '')) return json(res, 400, { error: 'invalid_grant' });
      if (!verifyPkce(form.get('code_verifier') || '', c.codeChallenge)) return json(res, 400, { error: 'invalid_grant', error_description: 'PKCE failed' });
      return json(res, 200, await issueTokens(c.uid, c.clientId, c.scope, newFamilyId()));
    }
    if (grant === 'refresh_token') {
      const r = rotateRefresh(form.get('refresh_token') || '');
      if ('error' in r) return json(res, 400, { error: 'invalid_grant' });
      if (r.clientId !== form.get('client_id')) return json(res, 400, { error: 'invalid_grant' });
      return json(res, 200, await issueTokens(r.uid, r.clientId, r.scope, r.familyId));
    }
    return json(res, 400, { error: 'unsupported_grant_type' });
  }

  // The MCP endpoint — OAuth-protected, Streamable HTTP (JSON-RPC over POST)
  if (pathname === '/mcp') {
    if (method === 'GET') return json(res, 200, { name: 'mcp-oauth-starter', transport: 'streamable-http', hint: 'POST JSON-RPC here with an OAuth bearer token' });
    if (method !== 'POST') return json(res, 405, { error: 'method_not_allowed' });
    const bearer = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
    const claims = bearer && looksLikeJwt(bearer) ? await verifyAccessToken(bearer) : null;
    if (!claims) {
      return res.writeHead(401, { 'content-type': 'application/json', 'www-authenticate': `Bearer resource_metadata="${ISSUER}/.well-known/oauth-protected-resource"` })
        .end(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32001, message: 'Authentication required' } }));
    }
    const msg = safeJson(await readBody(req)) || {};
    return json(res, 200, await handleRpc(msg, claims.uid));
  }

  json(res, 404, { error: 'not_found' });
});

// ── helpers used above ──
function safeJson(s: string): any { try { return JSON.parse(s); } catch { return null; } }
function sameOrigin(req: IncomingMessage): boolean {
  const origin = req.headers.origin;
  if (!origin) return true;
  try { return new URL(origin).host === (req.headers.host || ''); } catch { return false; }
}
function addParams(base: string, params: Record<string, string>): string {
  const u = new URL(base);
  for (const [k, v] of Object.entries(params)) if (v) u.searchParams.set(k, v);
  return u.toString();
}
function badRedirect(res: ServerResponse, redirectUri: string, error: string, state: string | null) {
  return redirect(res, addParams(redirectUri, { error, state: state || '' }));
}
async function issueTokens(uid: string, clientId: string, scope: string, familyId: string) {
  const access = await signAccessToken(uid, clientId, scope);
  const refreshToken = createRefresh({ uid, clientId, familyId, scope });
  return { access_token: access.token, token_type: 'Bearer', expires_in: access.expiresIn, refresh_token: refreshToken, scope };
}
async function handleRpc(msg: any, uid: string) {
  const { id, method, params } = msg;
  if (method === 'initialize') return { jsonrpc: '2.0', id, result: { protocolVersion: '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 'mcp-oauth-starter', version: '1.0.0' } } };
  if (method === 'tools/list') return { jsonrpc: '2.0', id, result: { tools: TOOLS } };
  if (method === 'tools/call') return { jsonrpc: '2.0', id, result: runTool(String(params?.name), params?.arguments || {}, uid) };
  if (method === 'ping') return { jsonrpc: '2.0', id, result: {} };
  return { jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${method}` } };
}

server.listen(PORT, () => {
  console.log(`MCP OAuth starter on ${ISSUER}`);
  console.log(`  MCP endpoint:    ${RESOURCE}`);
  console.log(`  PRM:             ${ISSUER}/.well-known/oauth-protected-resource`);
  console.log(`  AS metadata:     ${ISSUER}/.well-known/oauth-authorization-server`);
});
