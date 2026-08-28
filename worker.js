// SocialScan Lab Backend v0.1
// Cloudflare Worker - TikTok Login Kit / Display API
// Secrets must be configured in Cloudflare, never committed to GitHub.

const TIKTOK_AUTHORIZE = "https://www.tiktok.com/v2/auth/authorize/";
const TIKTOK_TOKEN = "https://open.tiktokapis.com/v2/oauth/token/";
const TIKTOK_USER_INFO = "https://open.tiktokapis.com/v2/user/info/";
const TIKTOK_VIDEO_LIST = "https://open.tiktokapis.com/v2/video/list/";

export default {
  async fetch(request, env) {
    try {
      return await router(request, env);
    } catch (error) {
      const status = error?.status || 500;
      return apiJson(
        {
          ok: false,
          error: error?.code || "server_error",
          message: error?.message || "Unknown server error",
        },
        status,
        request,
        env
      );
    }
  },
};

async function router(request, env) {
  const url = new URL(request.url);

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders(request, env) });
  }

  if (url.pathname === "/health" && request.method === "GET") {
    return apiJson(
      {
        ok: true,
        service: "socialscan-api",
        version: "0.1.0",
        tiktokConfigured: Boolean(
          env.TIKTOK_CLIENT_KEY &&
          env.TIKTOK_CLIENT_SECRET &&
          env.TIKTOK_REDIRECT_URI &&
          env.FRONTEND_URL &&
          env.SESSIONS
        ),
      },
      200,
      request,
      env
    );
  }

  if (url.pathname === "/auth/tiktok/start" && request.method === "GET") {
    requireTikTokConfig(env);

    const state = randomToken(32);
    await env.SESSIONS.put(
      `oauth_state:${state}`,
      JSON.stringify({ createdAt: Date.now() }),
      { expirationTtl: 600 }
    );

    const scope = env.TIKTOK_SCOPES ||
      "user.info.basic,user.info.profile,user.info.stats,video.list";

    const authUrl = new URL(TIKTOK_AUTHORIZE);
    authUrl.searchParams.set("client_key", env.TIKTOK_CLIENT_KEY);
    authUrl.searchParams.set("response_type", "code");
    authUrl.searchParams.set("scope", scope);
    authUrl.searchParams.set("redirect_uri", env.TIKTOK_REDIRECT_URI);
    authUrl.searchParams.set("state", state);

    return Response.redirect(authUrl.toString(), 302);
  }

  if (url.pathname === "/auth/tiktok/callback" && request.method === "GET") {
    requireTikTokConfig(env);

    const error = url.searchParams.get("error");
    const errorDescription = url.searchParams.get("error_description");
    if (error) {
      return redirectToFrontend(env, {
        socialscan_error: `${error}: ${errorDescription || "TikTok authorization failed"}`,
      });
    }

    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state");

    if (!code || !state) {
      return redirectToFrontend(env, {
        socialscan_error: "Missing TikTok authorization code or state.",
      });
    }

    const stateKey = `oauth_state:${state}`;
    const storedState = await env.SESSIONS.get(stateKey);
    if (!storedState) {
      return redirectToFrontend(env, {
        socialscan_error: "Invalid or expired OAuth state.",
      });
    }
    await env.SESSIONS.delete(stateKey);

    const token = await exchangeCodeForToken(code, env);

    const sessionId = randomToken(36);
    const now = Math.floor(Date.now() / 1000);
    const refreshTtl = clampTtl(token.refresh_expires_in || 30 * 24 * 60 * 60);

    const session = {
      provider: "tiktok",
      open_id: token.open_id || null,
      access_token: token.access_token,
      refresh_token: token.refresh_token,
      scope: token.scope || "",
      token_type: token.token_type || "Bearer",
      access_expires_at: now + Number(token.expires_in || 86400),
      refresh_expires_at: now + Number(token.refresh_expires_in || refreshTtl),
      created_at: now,
    };

    await env.SESSIONS.put(`session:${sessionId}`, JSON.stringify(session), {
      expirationTtl: refreshTtl,
    });

    return redirectToFrontend(env, {
      socialscan_session: sessionId,
      provider: "tiktok",
      connected: "1",
    });
  }

  if (url.pathname === "/api/session" && request.method === "GET") {
    const { sessionId, session } = await getValidSession(request, env);
    return apiJson(
      {
        ok: true,
        provider: session.provider,
        scope: session.scope,
        open_id: session.open_id,
        access_expires_at: session.access_expires_at,
        refresh_expires_at: session.refresh_expires_at,
        session_id_hint: `${sessionId.slice(0, 6)}…`,
      },
      200,
      request,
      env
    );
  }

  if (url.pathname === "/api/tiktok/me" && request.method === "GET") {
    let { sessionId, session } = await getValidSession(request, env);
    ({ sessionId, session } = await ensureFreshTikTokToken(sessionId, session, env));

    const scopes = scopeSet(session.scope);
    const fields = ["open_id", "avatar_url", "display_name"];

    if (scopes.has("user.info.profile")) {
      fields.push("username", "bio_description", "profile_deep_link", "is_verified");
    }
    if (scopes.has("user.info.stats")) {
      fields.push("follower_count", "following_count", "likes_count", "video_count");
    }

    const apiUrl = new URL(TIKTOK_USER_INFO);
    apiUrl.searchParams.set("fields", fields.join(","));

    const response = await fetch(apiUrl.toString(), {
      headers: { Authorization: `Bearer ${session.access_token}` },
    });
    const payload = await response.json();

    assertTikTokApiResponse(response, payload);

    return apiJson(
      {
        ok: true,
        provider: "tiktok",
        granted_scopes: [...scopes],
        user: payload?.data?.user || null,
      },
      200,
      request,
      env
    );
  }

  if (url.pathname === "/api/tiktok/videos" && request.method === "GET") {
    let { sessionId, session } = await getValidSession(request, env);
    ({ sessionId, session } = await ensureFreshTikTokToken(sessionId, session, env));

    const scopes = scopeSet(session.scope);
    if (!scopes.has("video.list")) {
      return apiJson(
        { ok: false, error: "missing_scope", required_scope: "video.list" },
        403,
        request,
        env
      );
    }

    const maxCount = Math.max(1, Math.min(20, Number(url.searchParams.get("max_count") || 10)));
    const cursorParam = url.searchParams.get("cursor");

    const apiUrl = new URL(TIKTOK_VIDEO_LIST);
    apiUrl.searchParams.set(
      "fields",
      [
        "id",
        "title",
        "video_description",
        "create_time",
        "cover_image_url",
        "share_url",
        "duration",
        "like_count",
        "comment_count",
        "share_count",
        "view_count",
        "is_aigc",
      ].join(",")
    );

    const body = { max_count: maxCount };
    if (cursorParam) body.cursor = Number(cursorParam);

    const response = await fetch(apiUrl.toString(), {
      method: "POST",
      headers: {
        Authorization: `Bearer ${session.access_token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });
    const payload = await response.json();

    assertTikTokApiResponse(response, payload);

    return apiJson(
      {
        ok: true,
        provider: "tiktok",
        videos: payload?.data?.videos || [],
        cursor: payload?.data?.cursor ?? null,
        has_more: Boolean(payload?.data?.has_more),
      },
      200,
      request,
      env
    );
  }

  if (url.pathname === "/auth/tiktok/logout" && request.method === "POST") {
    const sessionId = bearerToken(request);
    if (sessionId) await env.SESSIONS.delete(`session:${sessionId}`);
    return apiJson({ ok: true }, 200, request, env);
  }

  return apiJson(
    { ok: false, error: "not_found", path: url.pathname },
    404,
    request,
    env
  );
}

function requireTikTokConfig(env) {
  const required = [
    "TIKTOK_CLIENT_KEY",
    "TIKTOK_CLIENT_SECRET",
    "TIKTOK_REDIRECT_URI",
    "FRONTEND_URL",
  ];
  const missing = required.filter((name) => !env[name]);
  if (!env.SESSIONS) missing.push("SESSIONS_KV_BINDING");
  if (missing.length) throw new Error(`Missing backend configuration: ${missing.join(", ")}`);
}

async function exchangeCodeForToken(code, env) {
  const body = new URLSearchParams({
    client_key: env.TIKTOK_CLIENT_KEY,
    client_secret: env.TIKTOK_CLIENT_SECRET,
    code,
    grant_type: "authorization_code",
    redirect_uri: env.TIKTOK_REDIRECT_URI,
  });

  const response = await fetch(TIKTOK_TOKEN, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  const payload = await response.json();

  if (!response.ok || !payload?.access_token) {
    throw new Error(
      `TikTok token exchange failed: ${payload?.error_description || payload?.error || response.status}`
    );
  }
  return payload;
}

async function refreshTikTokToken(session, env) {
  const body = new URLSearchParams({
    client_key: env.TIKTOK_CLIENT_KEY,
    client_secret: env.TIKTOK_CLIENT_SECRET,
    grant_type: "refresh_token",
    refresh_token: session.refresh_token,
  });

  const response = await fetch(TIKTOK_TOKEN, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  const payload = await response.json();

  if (!response.ok || !payload?.access_token) {
    throw new Error(
      `TikTok token refresh failed: ${payload?.error_description || payload?.error || response.status}`
    );
  }

  const now = Math.floor(Date.now() / 1000);
  return {
    ...session,
    access_token: payload.access_token,
    refresh_token: payload.refresh_token || session.refresh_token,
    scope: payload.scope || session.scope,
    token_type: payload.token_type || session.token_type || "Bearer",
    access_expires_at: now + Number(payload.expires_in || 86400),
    refresh_expires_at:
      now + Number(payload.refresh_expires_in || Math.max(60, session.refresh_expires_at - now)),
  };
}

async function ensureFreshTikTokToken(sessionId, session, env) {
  const now = Math.floor(Date.now() / 1000);
  if (Number(session.access_expires_at || 0) > now + 90) {
    return { sessionId, session };
  }

  const refreshed = await refreshTikTokToken(session, env);
  const ttl = clampTtl(Number(refreshed.refresh_expires_at || now + 86400) - now);

  await env.SESSIONS.put(`session:${sessionId}`, JSON.stringify(refreshed), {
    expirationTtl: ttl,
  });

  return { sessionId, session: refreshed };
}

async function getValidSession(request, env) {
  const sessionId = bearerToken(request);
  if (!sessionId) {
    throw new HttpError(401, "missing_session", "Missing SocialScan session token.");
  }

  const raw = await env.SESSIONS.get(`session:${sessionId}`);
  if (!raw) {
    throw new HttpError(401, "expired_session", "Session not found or expired.");
  }

  const session = JSON.parse(raw);
  if (session.provider !== "tiktok") {
    throw new HttpError(400, "wrong_provider", "This session is not a TikTok session.");
  }

  const now = Math.floor(Date.now() / 1000);
  if (Number(session.refresh_expires_at || 0) <= now) {
    await env.SESSIONS.delete(`session:${sessionId}`);
    throw new HttpError(401, "expired_session", "TikTok authorization expired.");
  }

  return { sessionId, session };
}

function assertTikTokApiResponse(response, payload) {
  const apiError = payload?.error;
  const apiOk = !apiError || apiError.code === "ok" || apiError.code === 0 || apiError.code === "0";
  if (!response.ok || !apiOk) {
    throw new Error(
      `TikTok API error: ${apiError?.message || apiError?.code || response.status}`
    );
  }
}

function bearerToken(request) {
  const auth = request.headers.get("Authorization") || "";
  const match = auth.match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : null;
}

function scopeSet(scopeText) {
  return new Set(
    String(scopeText || "")
      .split(/[,\s]+/)
      .map((s) => s.trim())
      .filter(Boolean)
  );
}

function randomToken(bytes = 32) {
  const array = new Uint8Array(bytes);
  crypto.getRandomValues(array);
  return base64Url(array);
}

function base64Url(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function clampTtl(seconds) {
  const n = Number(seconds || 0);
  return Math.max(60, Math.min(n || 86400, 30 * 24 * 60 * 60));
}

function redirectToFrontend(env, params) {
  const target = new URL(env.FRONTEND_URL);
  const hash = new URLSearchParams(params);
  target.hash = hash.toString();
  return Response.redirect(target.toString(), 302);
}

function frontendOrigin(env) {
  try {
    return new URL(env.FRONTEND_URL).origin;
  } catch {
    return "";
  }
}

function corsHeaders(request, env) {
  const requestOrigin = request.headers.get("Origin") || "";
  const allowed = frontendOrigin(env);
  const headers = {
    "Access-Control-Allow-Headers": "Authorization, Content-Type",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin",
  };
  if (allowed && requestOrigin === allowed) {
    headers["Access-Control-Allow-Origin"] = allowed;
  }
  return headers;
}

function apiJson(data, status, request, env) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...corsHeaders(request, env),
    },
  });
}

class HttpError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}
