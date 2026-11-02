const REDIRECT_URI = "https://kick-moderator.bitoadel44.workers.dev/api/auth/callback";
const SCOPES = "user:read channel:read events:subscribe moderation:ban moderation:chat_message:manage";

const json = (data, status = 200, extraHeaders = {}) => new Response(JSON.stringify(data), {
  status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...extraHeaders },
});
const base64url = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const randomToken = (length = 32) => {
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return base64url(bytes);
};
async function sign(value, secret) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return base64url(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value)));
}

function safeEqual(a, b) {
  const x = new TextEncoder().encode(a);
  const y = new TextEncoder().encode(b);
  if (x.length !== y.length) return false;
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}
async function hasDashboardSession(request, secret) {
  if (!secret) return false;
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(/(?:^|; )kb_session=([^;]+)/);
  if (!match) return false;
  const [payload, signature] = match[1].split(".");
  if (!payload || !signature || !safeEqual(signature, await sign(payload, secret))) return false;
  try {
    const padded = payload.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((payload.length + 3) % 4);
    const session = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(padded), c => c.charCodeAt(0))));
    return session.exp > Date.now();
  } catch { return false; }
}

async function ensureTables(db) {
  await db.prepare(`CREATE TABLE IF NOT EXISTS kick_connection (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    access_token TEXT NOT NULL,
    refresh_token TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    scope TEXT,
    connected_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`).run();
  await db.prepare(`CREATE TABLE IF NOT EXISTS moderation_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    spam_enabled INTEGER NOT NULL DEFAULT 0,
    repeat_count INTEGER NOT NULL DEFAULT 4,
    window_seconds INTEGER NOT NULL DEFAULT 30,
    timeout_seconds INTEGER NOT NULL DEFAULT 300,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`).run();
  await db.prepare(`INSERT OR IGNORE INTO moderation_settings (id) VALUES (1)`).run();
}
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/login" && request.method === "POST") {
      if (!env.DASHBOARD_PASSWORD) return json({ error: "Dashboard password is not configured." }, 503);
      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid request." }, 400); }
      if (typeof body.password !== "string" || !safeEqual(body.password, env.DASHBOARD_PASSWORD)) {
        return json({ error: "Incorrect password." }, 401);
      }
      const payload = base64url(new TextEncoder().encode(JSON.stringify({ exp: Date.now() + 12 * 60 * 60 * 1000 })));
      const signature = await sign(payload, env.DASHBOARD_PASSWORD);
      return json({ ok: true }, 200, {
        "set-cookie": `kb_session=${payload}.${signature}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=43200`
      });
    }

    if (url.pathname === "/api/logout" && request.method === "POST") {
      return json({ ok: true }, 200, {
        "set-cookie": "kb_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0"
      });
    }

    if (url.pathname.startsWith("/api/") && url.pathname !== "/api/health" &&
        url.pathname !== "/api/login" && url.pathname !== "/api/logout" &&
        !(await hasDashboardSession(request, env.DASHBOARD_PASSWORD))) {
      return json({ error: "Dashboard login required." }, 401);
    }

    if (url.pathname === "/api/health") {
      return json({ ok: true, app: env.APP_NAME || "K_Botros Kick Moderator", databaseConfigured: Boolean(env.DB), kickClientIdConfigured: Boolean(env.KICK_CLIENT_ID), kickClientSecretConfigured: Boolean(env.KICK_CLIENT_SECRET), kickCredentialsConfigured: Boolean(env.KICK_CLIENT_ID && env.KICK_CLIENT_SECRET) });
    }

    if (url.pathname === "/api/auth/start") {
      if (!env.KICK_CLIENT_ID || !env.KICK_CLIENT_SECRET || !env.DB) return json({ error: "Kick credentials or database binding are missing." }, 503);
      const state = randomToken(32);
      const verifier = randomToken(48);
      const challenge = base64url(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
      const payload = base64url(new TextEncoder().encode(JSON.stringify({ state, verifier, exp: Date.now() + 10 * 60 * 1000 })));
      const signature = await sign(payload, env.KICK_CLIENT_SECRET);
      const auth = new URL("https://id.kick.com/oauth/authorize");
      auth.search = new URLSearchParams({
        response_type: "code", client_id: env.KICK_CLIENT_ID, redirect_uri: REDIRECT_URI,
        scope: SCOPES, state, code_challenge: challenge, code_challenge_method: "S256",
      }).toString();
      return new Response(null, { status: 302, headers: {
        location: auth.toString(),
        "set-cookie": `kick_oauth=${payload}.${signature}; HttpOnly; Secure; SameSite=Lax; Path=/api/auth/callback; Max-Age=600`,
        "cache-control": "no-store",
      }});
    }

    if (url.pathname === "/api/auth/callback") {
      if (url.searchParams.get("error")) return new Response("Kick authorization was cancelled or denied. You can close this page.", { status: 400 });
      const code = url.searchParams.get("code");
      const state = url.searchParams.get("state");
      const cookie = request.headers.get("Cookie") || "";
      const match = cookie.match(/(?:^|; )kick_oauth=([^;]+)/);
      if (!code || !state || !match) return new Response("Missing OAuth code or session. Return to the dashboard and try Connect Kick again.", { status: 400 });
      const [payload, signature] = match[1].split(".");
      if (!payload || !signature || signature !== await sign(payload, env.KICK_CLIENT_SECRET || "")) return new Response("OAuth session verification failed. Please try again.", { status: 400 });
      let session;
      try { session = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(payload.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((payload.length + 3) % 4)), c => c.charCodeAt(0)))); } catch { return new Response("Invalid OAuth session.", { status: 400 }); }
      if (session.state !== state || session.exp < Date.now()) return new Response("OAuth state expired or did not match. Please try again.", { status: 400 });
      const tokenResponse = await fetch("https://id.kick.com/oauth/token", {
        method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code", code, client_id: env.KICK_CLIENT_ID,
          client_secret: env.KICK_CLIENT_SECRET, redirect_uri: REDIRECT_URI, code_verifier: session.verifier,
        }),
      });
      if (!tokenResponse.ok) return new Response("Kick token exchange failed. Return to the dashboard and retry; if it continues, verify the app redirect URL and credentials.", { status: 502 });
      const tokens = await tokenResponse.json();
      await ensureTables(env.DB);
      await env.DB.prepare(`INSERT INTO kick_connection (id, access_token, refresh_token, expires_at, scope, connected_at)
        VALUES (1, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(id) DO UPDATE SET access_token=excluded.access_token, refresh_token=excluded.refresh_token, expires_at=excluded.expires_at, scope=excluded.scope, connected_at=CURRENT_TIMESTAMP`)
        .bind(tokens.access_token, tokens.refresh_token, Math.floor(Date.now()/1000) + Number(tokens.expires_in || 3600), tokens.scope || "").run();
      return new Response('<!doctype html><html><head><meta charset="utf-8"><title>Kick connected</title></head><body style="background:#101014;color:#fff;font:16px system-ui;padding:48px"><h1>Kick connected successfully!</h1><p>You can close this tab and return to your K_Botros dashboard.</p><p>Moderation actions are not enabled yet.</p><a style="color:#53e0a1" href="/">Back to dashboard</a></body></html>', { headers: { "content-type": "text/html; charset=utf-8", "set-cookie": "kick_oauth=; HttpOnly; Secure; SameSite=Lax; Path=/api/auth/callback; Max-Age=0", "cache-control": "no-store" }});
    }

    if (url.pathname === "/api/connection") {
      if (!env.DB) return json({ connected: false, error: "Database unavailable" }, 503);
      await ensureTables(env.DB);
      const row = await env.DB.prepare("SELECT scope, expires_at, connected_at FROM kick_connection WHERE id = 1").first();
      return json({ connected: Boolean(row), ...(row || {}) });
    }

    if (url.pathname === "/api/settings" && (request.method === "GET" || request.method === "PUT")) {
      if (!env.DB) return json({ error: "Database unavailable" }, 503);
      await ensureTables(env.DB);
      if (request.method === "GET") {
        const row = await env.DB.prepare("SELECT spam_enabled, repeat_count, window_seconds, timeout_seconds, updated_at FROM moderation_settings WHERE id = 1").first();
        return json({
          spamEnabled: Boolean(row?.spam_enabled),
          repeatCount: row?.repeat_count ?? 4,
          windowSeconds: row?.window_seconds ?? 30,
          timeoutSeconds: row?.timeout_seconds ?? 300,
          updatedAt: row?.updated_at ?? null
        });
      }
      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid settings payload." }, 400); }
      const repeatCount = Number(body.repeatCount);
      const windowSeconds = Number(body.windowSeconds);
      const timeoutSeconds = Number(body.timeoutSeconds);
      if (typeof body.spamEnabled !== "boolean" ||
          !Number.isInteger(repeatCount) || repeatCount < 2 || repeatCount > 20 ||
          !Number.isInteger(windowSeconds) || windowSeconds < 5 || windowSeconds > 300 ||
          !Number.isInteger(timeoutSeconds) || timeoutSeconds < 10 || timeoutSeconds > 86400) {
        return json({ error: "Choose 2–20 repeats, a 5–300 second window, and a 10–86400 second timeout." }, 400);
      }
      await env.DB.prepare(`INSERT INTO moderation_settings (id, spam_enabled, repeat_count, window_seconds, timeout_seconds, updated_at)
        VALUES (1, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(id) DO UPDATE SET spam_enabled=excluded.spam_enabled, repeat_count=excluded.repeat_count,
        window_seconds=excluded.window_seconds, timeout_seconds=excluded.timeout_seconds, updated_at=CURRENT_TIMESTAMP`)
        .bind(body.spamEnabled ? 1 : 0, repeatCount, windowSeconds, timeoutSeconds).run();
      return json({ ok: true, spamEnabled: body.spamEnabled, repeatCount, windowSeconds, timeoutSeconds });
    }

    if (url.pathname.startsWith("/api/")) return json({ error: "Not implemented yet" }, 501);
    return env.ASSETS.fetch(request);
  },
};
