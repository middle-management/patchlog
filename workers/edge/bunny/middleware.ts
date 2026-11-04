// A verifying edge for patchlog on Bunny (§C.5.3, §9), as an Edge Scripting
// middleware on the pull zone in front of the origin. It lets Bunny cache
// and merge reads of private namespaces that carry an edge-grant cookie
// (`POST /edge-grants`), as it does for public ones.
//
// Pull zone settings: "Run script before cache" on (General > Origin), so
// onClientRequest and onClientResponse run on cache hits too; cookies not
// disabled; the cache keyed on the query string.
//
// Script variables (secrets):
//   EDGE_KEYS           the origin's EDGE_KEYS: [{ "kid", "key" (hex) }]
//   EDGE_VERIFY_SECRET  the origin's EDGE_VERIFY_SECRET, which the origin
//                       accepts as proof that this edge verified a read
//
// On every request, before the cache:
//   - X-Edge-Verified and X-Edge-Prefix from the client are removed.
//   - A GET or HEAD without Authorization whose edge-grant cookie verifies
//     (MAC, expiry, the prefix covering the path) is marked, `pl-edge=1`
//     in the URL.
// On a miss, the marker is removed and a marked request goes to the origin
// with X-Edge-Verified and X-Edge-Prefix. The origin answers verified reads
// with an edge lifetime in CDN-Cache-Control, which this script makes
// Bunny's Cache-Control, keeping the client's (private) aside.
// On every response, hits included: a response cached for verified reads
// goes only to a request whose cookie verifies now, with its client
// Cache-Control restored. Bunny keys its cache on the URL the client sent,
// not the marked one (measured), so verified and other requests share
// entries: any other request is fetched from the origin directly, as if
// the cache weren't there.

export const MARK = "pl-edge";
const COOKIE = "__Secure-pl-eg-";
const SAVED_CC = "X-Patchlog-Client-Cache-Control";
const VERIFIED = "X-Patchlog-Edge";

type Key = { kid: string; key: Uint8Array };

function env(name: string): string | undefined {
  const g = globalThis as any;
  return g.process?.env?.[name] ?? g.Deno?.env?.get?.(name);
}

function hex(s: string): Uint8Array {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  return out;
}

export function keysFrom(json: string | undefined): Key[] {
  try {
    return (JSON.parse(json ?? "[]") as { kid: string; key: string }[]).map((k) => ({ kid: k.kid, key: hex(k.key) }));
  } catch {
    return [];
  }
}

function b64urlDecode(s: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) return null;
  const b = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
  return Uint8Array.from(b, (c) => c.charCodeAt(0));
}

function b64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function sha256(s: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)));
}

async function hmac(key: Uint8Array, msg: string): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, new TextEncoder().encode(msg)));
}

export async function cookieName(prefix: string): Promise<string> {
  const d = await sha256(prefix);
  return COOKIE + [...d.slice(0, 8)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** `/r/{ns}/{name}`, `/r/{ns}` or `/ns/{ns}` (§2.1); the origin checks names. */
function isEdgePrefix(p: string): boolean {
  return /^\/(r\/[^/]+(\/[^/]+)?|ns\/[^/]+)$/.test(p);
}

export function covers(p: string, path: string): boolean {
  return path === p || path.startsWith(p + "/");
}

/** §C.5.3's checks on one request; the prefix of a cookie that passes. */
export async function verify(req: Request, keys: Key[], nowMs = Date.now()): Promise<string | null> {
  if (req.method !== "GET" && req.method !== "HEAD") return null;
  if (req.headers.has("Authorization") || req.headers.has("Source-Authorization")) return null;
  const path = new URL(req.url).pathname;
  if (path !== "/" && (path.includes("%") || path.split("/").slice(1).some((s) => s === "" || s === "." || s === ".."))) return null;
  const cookies = (req.headers.get("Cookie") ?? "").split(";").map((c) => c.trim());
  for (const c of cookies) {
    const eq = c.indexOf("=");
    const name = c.slice(0, eq), value = c.slice(eq + 1);
    if (eq < 0 || !name.startsWith(COOKIE)) continue;
    const dot = value.indexOf(".");
    if (dot < 0) continue;
    const body = value.slice(0, dot), mac = b64urlDecode(value.slice(dot + 1));
    const raw = b64urlDecode(body);
    if (!raw || !mac) continue;
    const text = new TextDecoder().decode(raw);
    let claims: any;
    try { claims = JSON.parse(text); } catch { continue; }
    if (!claims || typeof claims !== "object" || Object.keys(claims).length !== 3) continue;
    const { exp, kid, p } = claims;
    if (!Number.isSafeInteger(exp) || typeof kid !== "string" || typeof p !== "string") continue;
    // Canonical byte for byte (§3.1): members in order, no whitespace.
    if (text !== JSON.stringify({ exp, kid, p })) continue;
    if (name !== (await cookieName(p)) || exp * 1000 <= nowMs || !isEdgePrefix(p) || !covers(p, path)) continue;
    const key = keys.find((k) => k.kid === kid);
    if (!key) continue;
    const want = await hmac(key.key, body);
    if (want.length !== mac.length || want.some((b, i) => b !== mac[i])) continue;
    return p;
  }
  return null;
}

function rebuild(req: Request, url: URL, headers: Headers): Request {
  const init: RequestInit = { method: req.method, headers, redirect: "manual" };
  if (req.method !== "GET" && req.method !== "HEAD") {
    init.body = req.body;
    (init as any).duplex = "half";
  }
  return new Request(url.toString(), init);
}

export function hooks(keys: Key[], secret: string, origin: string, now = () => Date.now(), fetcher: typeof fetch = fetch) {
  return {
    async onClientRequest(ctx: { request: Request }): Promise<Request | Response> {
      const req = ctx.request;
      const url = new URL(req.url);
      const headers = new Headers(req.headers);
      headers.delete("X-Edge-Verified");
      headers.delete("X-Edge-Prefix");
      url.searchParams.delete(MARK);
      if (await verify(req, keys, now())) url.searchParams.set(MARK, "1");
      return rebuild(req, url, headers);
    },

    async onOriginRequest(ctx: { request: Request }): Promise<Request | Response> {
      const req = ctx.request;
      const url = new URL(req.url);
      const headers = new Headers(req.headers);
      headers.delete("X-Edge-Verified");
      headers.delete("X-Edge-Prefix");
      if (url.searchParams.has(MARK)) {
        url.searchParams.delete(MARK);
        const p = await verify(req, keys, now());
        if (p) {
          headers.set("X-Edge-Verified", secret);
          headers.set("X-Edge-Prefix", p);
        }
      }
      return rebuild(req, url, headers);
    },

    async onOriginResponse(ctx: { request: Request; response: Response }): Promise<Response> {
      const res = ctx.response;
      const edge = res.headers.get("CDN-Cache-Control");
      if (!ctx.request.headers.has("X-Edge-Verified") || !edge || /no-store/.test(edge)) return res;
      const headers = new Headers(res.headers);
      headers.set(SAVED_CC, res.headers.get("Cache-Control") ?? "private");
      headers.set("Cache-Control", `public, ${edge}`);
      headers.set(VERIFIED, "1");
      return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
    },

    async onClientResponse(ctx: { request: Request; response: Response }): Promise<Response> {
      const res = ctx.response;
      if (!res.headers.has(VERIFIED)) return res;
      // Cached for verified reads: only for a cookie that verifies now.
      const req = new Request(ctx.request.url, { method: ctx.request.method, headers: ctx.request.headers });
      if (!(await verify(req, keys, now()))) {
        // Not for this request: ask the origin, without the cache.
        const url = new URL(ctx.request.url);
        url.searchParams.delete(MARK);
        const headers = new Headers(ctx.request.headers);
        headers.delete("X-Edge-Verified");
        headers.delete("X-Edge-Prefix");
        return fetcher(origin + url.pathname + url.search, { method: ctx.request.method, headers, redirect: "manual" });
      }
      const headers = new Headers(res.headers);
      headers.set("Cache-Control", res.headers.get(SAVED_CC) ?? "private, max-age=0");
      for (const h of [SAVED_CC, VERIFIED, "CDN-Cache-Control", "Surrogate-Control", "Cloudflare-CDN-Cache-Control"]) headers.delete(h);
      return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
    },
  };
}

// Registered on Bunny; imported without side effects by the tests.
if (!(globalThis as any).__PATCHLOG_TEST__) {
  const BunnySDK = await import("@bunny.net/edgescript-sdk@0.13.0");
  const origin = env("ORIGIN_URL") ?? "https://patchlog.middlemanagement.se";
  const h = hooks(keysFrom(env("EDGE_KEYS")), env("EDGE_VERIFY_SECRET") ?? "", origin);
  BunnySDK.net.http
    .servePullZone({ url: origin })
    .onClientRequest(h.onClientRequest)
    .onOriginRequest(h.onOriginRequest)
    .onOriginResponse(h.onOriginResponse)
    .onClientResponse(h.onClientResponse);
}
