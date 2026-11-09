// Accounts API for the Roblox fan mockup. Runs on Cloudflare Workers + D1.
const enc = new TextEncoder();
const SESSION_SECONDS = 60 * 60 * 24 * 30;
const ITERATIONS = 100000; // Workers' maximum for PBKDF2

const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const fromHex = (s) => new Uint8Array(s.match(/../g).map((h) => parseInt(h, 16)));

async function hashPassword(password, saltBytes) {
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: saltBytes, iterations: ITERATIONS },
    key,
    256
  );
  return hex(bits);
}

async function sha256(text) {
  return hex(await crypto.subtle.digest("SHA-256", enc.encode(text)));
}

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store", ...headers },
  });

function getCookie(request, name) {
  const raw = request.headers.get("cookie") || "";
  for (const part of raw.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return v.join("=");
  }
  return null;
}

const sessionCookie = (token, maxAge) =>
  `session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`;

async function createSession(env, userId) {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  const token = hex(bytes);
  const expires = Math.floor(Date.now() / 1000) + SESSION_SECONDS;
  await env.DB.prepare("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)")
    .bind(await sha256(token), userId, expires)
    .run();
  return token;
}

async function currentUser(request, env) {
  const token = getCookie(request, "session");
  if (!token) return null;
  const now = Math.floor(Date.now() / 1000);
  return env.DB.prepare(
    `SELECT u.id, u.display_name FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = ? AND s.expires_at > ?`
  )
    .bind(await sha256(token), now)
    .first();
}

async function readCreds(request) {
  let body;
  try {
    body = await request.json();
  } catch {
    return { error: "Invalid request." };
  }
  const username = String(body.username || "").trim();
  const password = String(body.password || "");
  return { username, password };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (!url.pathname.startsWith("/api/")) return env.ASSETS.fetch(request);

    // Basic CSRF defence for state-changing calls: same-origin only.
    if (request.method === "POST") {
      const origin = request.headers.get("origin");
      if (origin && origin !== url.origin) return json({ error: "Bad origin." }, 403);
    }

    try {
      if (url.pathname === "/api/me" && request.method === "GET") {
        const user = await currentUser(request, env);
        return json({ user: user ? { name: user.display_name } : null });
      }

      if (url.pathname === "/api/signup" && request.method === "POST") {
        const { username, password, error } = await readCreds(request);
        if (error) return json({ error }, 400);
        if (!/^[A-Za-z0-9_]{3,20}$/.test(username))
          return json({ error: "Username must be 3–20 letters, numbers or underscores." }, 400);
        if (password.length < 8 || password.length > 200)
          return json({ error: "Password must be at least 8 characters." }, 400);

        const salt = crypto.getRandomValues(new Uint8Array(16));
        const hash = await hashPassword(password, salt);
        try {
          const res = await env.DB.prepare(
            "INSERT INTO users (username, display_name, salt, hash, created_at) VALUES (?, ?, ?, ?, ?)"
          )
            .bind(username.toLowerCase(), username, hex(salt), hash, Math.floor(Date.now() / 1000))
            .run();
          const token = await createSession(env, res.meta.last_row_id);
          return json({ user: { name: username } }, 200, { "set-cookie": sessionCookie(token, SESSION_SECONDS) });
        } catch (e) {
          if (String(e).includes("UNIQUE")) return json({ error: "That username is taken." }, 409);
          throw e;
        }
      }

      if (url.pathname === "/api/login" && request.method === "POST") {
        const { username, password, error } = await readCreds(request);
        if (error) return json({ error }, 400);
        const row = await env.DB.prepare("SELECT id, display_name, salt, hash FROM users WHERE username = ?")
          .bind(username.toLowerCase())
          .first();
        // Always do the hashing work so timing doesn't reveal whether the user exists.
        const saltBytes = row ? fromHex(row.salt) : new Uint8Array(16);
        const attempt = await hashPassword(password.slice(0, 200), saltBytes);
        if (!row || !safeEqual(attempt, row.hash)) return json({ error: "Wrong username or password." }, 401);
        const token = await createSession(env, row.id);
        return json({ user: { name: row.display_name } }, 200, { "set-cookie": sessionCookie(token, SESSION_SECONDS) });
      }

      if (url.pathname === "/api/logout" && request.method === "POST") {
        const token = getCookie(request, "session");
        if (token) await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(await sha256(token)).run();
        return json({ ok: true }, 200, { "set-cookie": sessionCookie("", 0) });
      }

      return json({ error: "Not found." }, 404);
    } catch (e) {
      return json({ error: "Server error. Please try again." }, 500);
    }
  },
};
