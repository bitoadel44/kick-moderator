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

function bannedWordTokens(value) {
  return String(value || "").normalize("NFKD").toLocaleLowerCase()
    .replace(/[\u0300-\u036f]/g, "")
    .match(/[\p{L}\p{N}]+/gu) || [];
}
function bannedWordKey(token) {
  return token.replace(/[aeiou]/g, "");
}
function findBannedWordMatch(message, terms) {
  const messageTokens = bannedWordTokens(message);
  for (const row of terms) {
    const termTokens = bannedWordTokens(row.term);
    if (!termTokens.length || termTokens.length > messageTokens.length) continue;
    for (let start = 0; start <= messageTokens.length - termTokens.length; start++) {
      const candidate = messageTokens.slice(start, start + termTokens.length);
      const exact = candidate.every((token, i) => token === termTokens[i]);
      const vowelOmitted = termTokens.every((token, i) =>
        token.length >= 5 && bannedWordKey(token).length >= 4 &&
        bannedWordKey(candidate[i]) === bannedWordKey(token)
      );
      if (exact || vowelOmitted) return row.term;
    }
  }
  return null;
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

async function verifyKickWebhook(request, rawBody) {
  const messageId = request.headers.get("Kick-Event-Message-Id");
  const timestamp = request.headers.get("Kick-Event-Message-Timestamp");
  const signature = request.headers.get("Kick-Event-Signature");
  if (!messageId || !timestamp || !signature) return false;

  const keyResponse = await fetch("https://api.kick.com/public/v1/public-key");
  if (!keyResponse.ok) throw new Error("Could not retrieve Kick's current webhook public key (HTTP " + keyResponse.status + ").");
  const keyText = await keyResponse.text();
  let pem = keyText.trim();
  try {
    const keyData = JSON.parse(keyText);
    const candidates = [
      keyData,
      keyData?.public_key,
      keyData?.publicKey,
      keyData?.data?.public_key,
      keyData?.data?.publicKey,
      keyData?.data
    ];
    const found = candidates.find(value => typeof value === "string" && value.includes("-----BEGIN PUBLIC KEY-----"));
    if (found) pem = found;
  } catch {
    // Kick may return the PEM directly as plain text.
  }
  pem = pem.replace(/\\n/g, "\n").trim();
  if (!pem) throw new Error("Kick public-key response was empty.");
  const match = pem.match(/-----BEGIN PUBLIC KEY-----([\s\S]+?)-----END PUBLIC KEY-----/);
  if (!match) {
    let shape = "plain text";
    try {
      const parsed = JSON.parse(keyText);
      if (parsed && typeof parsed === "object") {
        const data = parsed.data;
        const dataShape = Array.isArray(data)
          ? "array length " + data.length
          : data && typeof data === "object"
            ? "object keys: " + Object.keys(data).join(", ") + "; public_key type: " + typeof data.public_key + (typeof data.public_key === "string" ? "; public_key prefix: " + JSON.stringify(data.public_key.slice(0, 32)) : data.public_key && typeof data.public_key === "object" ? "; public_key keys: " + Object.keys(data.public_key).join(", ") : "")
            : typeof data;
        shape = "JSON keys: " + Object.keys(parsed).join(", ") + "; data is " + dataShape;
      } else shape = typeof parsed;
    } catch {}
    throw new Error("Kick public-key response did not contain a PEM public key (" + shape + "; HTTP 200).");
  }
  const decodeBase64 = (value, label) => {
    let normalized = String(value || "").trim();
    normalized = normalized.replace(/^(?:sha256|base64)\s*=\s*/i, "");
    normalized = normalized.replace(/\s/g, "").replace(/-/g, "+").replace(/_/g, "/");
    if (!normalized || !/^[A-Za-z0-9+/]*={0,2}$/.test(normalized)) {
      throw new Error(label + " was not valid Base64 (unexpected characters or prefix).");
    }
    normalized = normalized.replace(/=+$/, "");
    if (normalized.length % 4 === 1) throw new Error(label + " had an invalid Base64 length.");
    normalized += "=".repeat((4 - normalized.length % 4) % 4);
    try {
      const binary = atob(normalized);
      return Uint8Array.from(binary, c => c.charCodeAt(0));
    } catch {
      throw new Error(label + " could not be decoded as Base64.");
    }
  };
  const der = decodeBase64(match[1], "Kick public key");
  const key = await crypto.subtle.importKey("spki", der, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  const signedMessage = new TextEncoder().encode(messageId + "." + timestamp + "." + rawBody);
  const signatureBytes = decodeBase64(signature, "Kick webhook signature");
  return crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, signatureBytes, signedMessage);
}


async function createKickAppToken(env) {
  if (!env.KICK_CLIENT_ID || !env.KICK_CLIENT_SECRET) {
    throw new Error("Kick app credentials are missing. Add KICK_CLIENT_ID and KICK_CLIENT_SECRET in Cloudflare.");
  }
  const form = new URLSearchParams({
    grant_type: "client_credentials",
    client_id: env.KICK_CLIENT_ID,
    client_secret: env.KICK_CLIENT_SECRET
  });
  const response = await fetch("https://id.kick.com/oauth/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: form
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || !data.access_token) {
    throw new Error("Kick app-token request failed: " + (data.error_description || data.error || data.message || response.status));
  }
  return data.access_token;
}

async function subscribeChannelToChat(env, broadcasterUserId) {
  const appToken = await createKickAppToken(env);
  const response = await fetch("https://api.kick.com/public/v1/events/subscriptions", {
    method: "POST",
    headers: {
      Authorization: "Bearer " + appToken,
      "content-type": "application/json"
    },
    body: JSON.stringify({
      broadcaster_user_id: Number(broadcasterUserId),
      method: "webhook",
      events: [{ name: "chat.message.sent", version: 1 }]
    })
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error("Kick chat subscription failed: " + (data.message || data.error || response.status));
  }
  const errors = data?.data?.[0]?.error || data?.data?.error;
  if (errors) throw new Error("Kick rejected the chat subscription: " + errors);
  return data;
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
  await db.prepare(`CREATE TABLE IF NOT EXISTS webhook_events (
    message_id TEXT PRIMARY KEY, event_type TEXT NOT NULL, broadcaster_user_id INTEGER,
    broadcaster_slug TEXT, sender_user_id INTEGER, sender_username TEXT,
    content TEXT, event_created_at TEXT, received_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`).run();
  await db.prepare(`CREATE TABLE IF NOT EXISTS webhook_diagnostics (
    id INTEGER PRIMARY KEY AUTOINCREMENT, stage TEXT NOT NULL, outcome TEXT NOT NULL,
    detail TEXT, event_type TEXT, received_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`).run();
  await db.prepare(`CREATE TABLE IF NOT EXISTS managed_channels (
    broadcaster_user_id INTEGER PRIMARY KEY, slug TEXT NOT NULL UNIQUE,
    spam_enabled INTEGER NOT NULL DEFAULT 0, repeat_count INTEGER NOT NULL DEFAULT 4,
    window_seconds INTEGER NOT NULL DEFAULT 30, timeout_seconds INTEGER NOT NULL DEFAULT 300,
    added_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`).run();
  await db.prepare(`CREATE TABLE IF NOT EXISTS banned_words (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    term TEXT NOT NULL COLLATE NOCASE UNIQUE,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`).run();
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

    if (url.pathname === "/webhooks/kick" && request.method === "POST") {
      if (!env.DB) return json({ error: "Database unavailable." }, 503);
      const rawBody = await request.text();
      if (rawBody.length > 256_000) return json({ error: "Payload too large." }, 413);
      const eventType = request.headers.get("Kick-Event-Type") || "unknown";
      await ensureTables(env.DB);
      let verified = false;
      try {
        verified = await verifyKickWebhook(request, rawBody);
      } catch (error) {
        const detail = String(error?.message || error || "Unknown verification error").slice(0, 500);
        console.error("KICK_WEBHOOK_VERIFY_ERROR", JSON.stringify({ eventType, detail }));
        await env.DB.prepare("INSERT INTO webhook_diagnostics (stage, outcome, detail, event_type) VALUES (?, ?, ?, ?)")
          .bind("signature_verification", "error", detail, eventType).run()
          .catch(dbError => console.error("KICK_WEBHOOK_DIAGNOSTIC_WRITE_ERROR", dbError?.message));
        return json({ error: "Webhook signature verification failed.", diagnostic: detail }, 502);
      }
      if (!verified) {
        console.error("KICK_WEBHOOK_INVALID_SIGNATURE", JSON.stringify({ eventType }));
        return json({ error: "Invalid Kick webhook signature." }, 401);
      }

      let payload;
      try { payload = JSON.parse(rawBody); } catch (error) {
        console.error("KICK_WEBHOOK_INVALID_JSON", JSON.stringify({ eventType, detail: String(error?.message || error) }));
        return json({ error: "Invalid JSON payload." }, 400);
      }
      if (eventType === "chat.message.sent") {
        const broadcaster = payload.broadcaster || {};
        const sender = payload.sender || {};
        const messageId = String(payload.message_id || request.headers.get("Kick-Event-Message-Id"));
        const stored = await env.DB.prepare(`INSERT OR IGNORE INTO webhook_events
          (message_id, event_type, broadcaster_user_id, broadcaster_slug, sender_user_id, sender_username, content, event_created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
          .bind(
            messageId,
            eventType,
            broadcaster.user_id || null,
            broadcaster.channel_slug || null,
            sender.user_id || null,
            sender.username || null,
            String(payload.content || "").slice(0, 2000),
            payload.created_at || null
          ).run();

        // Safe preview only: detect matches and record them; never issue moderation actions here.
        if (stored.meta?.changes && broadcaster.user_id && sender.user_id) {
          const channel = await env.DB.prepare("SELECT slug FROM managed_channels WHERE broadcaster_user_id = ?")
            .bind(broadcaster.user_id).first();
          if (channel) {
            const terms = await env.DB.prepare("SELECT term FROM banned_words ORDER BY id").all();
            const matchedTerm = findBannedWordMatch(payload.content || "", terms.results || []);
            if (matchedTerm) {
              const detail = JSON.stringify({
                mode: "dry_run",
                action: "would_permanently_ban",
                channel: channel.slug,
                username: String(sender.username || "").slice(0, 80),
                sender_user_id: sender.user_id,
                matched_term: matchedTerm,
                message_id: messageId
              });
              await env.DB.prepare("INSERT INTO webhook_diagnostics (stage, outcome, detail, event_type) VALUES (?, ?, ?, ?)")
                .bind("banned_word_match", "dry_run_match", detail, eventType).run();
            }
          }
        }
      }
      return json({ ok: true });
    }

    if (url.pathname.startsWith("/api/") && url.pathname !== "/api/health" &&
        url.pathname !== "/api/login" && url.pathname !== "/api/logout" &&
        url.pathname !== "/api/auth/callback" &&
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

    if (url.pathname === "/api/webhooks/recent" && request.method === "GET") {
      if (!env.DB) return json({ error: "Database unavailable." }, 503);
      await ensureTables(env.DB);
      const result = await env.DB.prepare(`SELECT event_type, broadcaster_user_id, broadcaster_slug,
        sender_user_id, sender_username, content, event_created_at, received_at
        FROM webhook_events ORDER BY received_at DESC LIMIT 20`).all();
      return json({ events: result.results || [] });
    }

    if (url.pathname === "/api/webhooks/diagnostics" && request.method === "GET") {
      if (!env.DB) return json({ error: "Database unavailable." }, 503);
      await ensureTables(env.DB);
      const result = await env.DB.prepare(`SELECT stage, outcome, detail, event_type, received_at
        FROM webhook_diagnostics ORDER BY id DESC LIMIT 20`).all();
      return json({ diagnostics: result.results || [] });
    }

    if (url.pathname === "/api/channels" && request.method === "GET") {
      await ensureTables(env.DB);
      const result = await env.DB.prepare("SELECT broadcaster_user_id, slug, spam_enabled, repeat_count, window_seconds, timeout_seconds, added_at FROM managed_channels ORDER BY slug").all();
      return json({ channels: (result.results || []).map(row => ({ broadcasterUserId: row.broadcaster_user_id, slug: row.slug, spamEnabled: Boolean(row.spam_enabled), repeatCount: row.repeat_count, windowSeconds: row.window_seconds, timeoutSeconds: row.timeout_seconds, addedAt: row.added_at })) });
    }
    if (url.pathname === "/api/channels" && request.method === "POST") {
      await ensureTables(env.DB);
      const connection = await env.DB.prepare("SELECT access_token, expires_at FROM kick_connection WHERE id = 1").first();
      if (!connection) return json({ error: "Connect your Kick account first." }, 409);
      if (connection.expires_at <= Math.floor(Date.now()/1000) + 60) return json({ error: "Reconnect Kick; the saved connection may have expired." }, 401);
      let body; try { body = await request.json(); } catch { return json({ error: "Invalid request." }, 400); }
      const slug = String(body.slug || "").trim().replace(/^@/, "").toLowerCase();
      if (!/^[a-z0-9_-]{1,25}$/.test(slug)) return json({ error: "Enter a valid Kick username (up to 25 characters)." }, 400);
      const lookup = await fetch("https://api.kick.com/public/v1/channels?slug=" + encodeURIComponent(slug), { headers: { Authorization: "Bearer " + connection.access_token } });
      const data = await lookup.json().catch(() => ({}));
      if (!lookup.ok) return json({ error: lookup.status === 401 ? "Reconnect Kick and try again." : "Kick channel lookup failed: " + (data.message || lookup.statusText) }, lookup.status === 401 ? 401 : 400);
      const channel = data.data && data.data[0];
      if (!channel) return json({ error: "No Kick channel found with that username." }, 404);
      await env.DB.prepare("INSERT INTO managed_channels (broadcaster_user_id, slug) VALUES (?, ?) ON CONFLICT(broadcaster_user_id) DO UPDATE SET slug=excluded.slug").bind(channel.broadcaster_user_id, channel.slug).run();
      try {
        const subscription = await subscribeChannelToChat(env, channel.broadcaster_user_id);
        return json({ ok: true, channel: { broadcasterUserId: channel.broadcaster_user_id, slug: channel.slug }, permissionStatus: "not_checked", webhookSubscription: "subscribed", subscription });
      } catch (error) {
        return json({ ok: true, channel: { broadcasterUserId: channel.broadcaster_user_id, slug: channel.slug }, permissionStatus: "not_checked", webhookSubscription: "failed", warning: error.message });
      }
    }
    if (url.pathname.startsWith("/api/channels/") && request.method === "DELETE") {
      await ensureTables(env.DB); const id = Number(url.pathname.split("/").pop());
      if (!Number.isSafeInteger(id) || id <= 0) return json({ error: "Invalid channel ID." }, 400);
      await env.DB.prepare("DELETE FROM managed_channels WHERE broadcaster_user_id = ?").bind(id).run();
      return json({ ok: true });
    }
    if (url.pathname === "/api/banned-words" && request.method === "GET") {
      if (!env.DB) return json({ error: "Database unavailable." }, 503);
      await ensureTables(env.DB);
      const result = await env.DB.prepare("SELECT id, term, created_at FROM banned_words ORDER BY term COLLATE NOCASE").all();
      return json({ words: result.results || [] });
    }
    if (url.pathname === "/api/banned-words" && request.method === "POST") {
      if (!env.DB) return json({ error: "Database unavailable." }, 503);
      await ensureTables(env.DB);
      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid request." }, 400); }
      const term = String(body.term || "").trim().replace(/\s+/g, " ");
      if (!term || term.length > 80 || /[\r\n]/.test(term)) return json({ error: "Enter one word or phrase (1–80 characters)." }, 400);
      try {
        const result = await env.DB.prepare("INSERT INTO banned_words (term) VALUES (?) RETURNING id, term, created_at").bind(term).first();
        return json({ ok: true, word: result }, 201);
      } catch (error) {
        if (/unique/i.test(String(error?.message || error))) return json({ error: "That word or phrase is already in the list." }, 409);
        throw error;
      }
    }
    if (url.pathname.startsWith("/api/banned-words/") && request.method === "DELETE") {
      if (!env.DB) return json({ error: "Database unavailable." }, 503);
      await ensureTables(env.DB);
      const id = Number(url.pathname.split("/").pop());
      if (!Number.isSafeInteger(id) || id <= 0) return json({ error: "Invalid word ID." }, 400);
      await env.DB.prepare("DELETE FROM banned_words WHERE id = ?").bind(id).run();
      return json({ ok: true });
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
