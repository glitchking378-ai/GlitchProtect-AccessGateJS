const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store"
};

function toHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: JSON_HEADERS
  });
}

export async function parseJsonBody(request) {
  try {
    return await request.json();
  } catch {
    return {};
  }
}

export function isValidUuidLike(value) {
  return typeof value === "string" && value.trim().length >= 8 && value.trim().length <= 128;
}

export async function sha256Hex(input) {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return toHex(new Uint8Array(digest));
}

export async function blockKeyForUuid(uuid) {
  const hash = await sha256Hex(uuid);
  return `block:${hash}`;
}

export async function userKeyForUuid(uuid) {
  const hash = await sha256Hex(uuid);
  return `user:${hash}`;
}

export async function userKeyForId(id) {
  const hash = await sha256Hex(id);
  return `user:${hash}`;
}

export function parseCookieHeader(cookieHeader) {
  const out = {};
  if (!cookieHeader || typeof cookieHeader !== "string") return out;
  const parts = cookieHeader.split(";");
  for (const part of parts) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    const key = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    out[key] = value;
  }
  return out;
}

export function getKvOrError(env) {
  if (!env || !env.ACCESS_GATE_KV) {
    const errorId = createErrorId("cfg");
    logEvent("error", "access_gate.kv_binding_missing", { errorId });
    return {
      kv: null,
      error: json(
        {
          error: "Missing KV binding ACCESS_GATE_KV.",
          errorId
        },
        500
      )
    };
  }
  return { kv: env.ACCESS_GATE_KV, error: null };
}

export function validateAccessGateEnv(env) {
  const issues = [];
  if (!env || !env.ACCESS_GATE_KV) {
    issues.push("Missing required binding ACCESS_GATE_KV.");
  }
  if (env && env.ACCESS_GATE_ADMIN_TOKEN && String(env.ACCESS_GATE_ADMIN_TOKEN).trim().length < 8) {
    issues.push("ACCESS_GATE_ADMIN_TOKEN should be at least 8 characters.");
  }
  return {
    ok: issues.length === 0,
    issues
  };
}

export function readAdminToken(env) {
  return (env && (env.ACCESS_GATE_ADMIN_TOKEN || env.ADMIN_TOKEN)) || "";
}

export function tokenFromRequest(request) {
  return (
    request.headers.get("x-access-gate-token") ||
    request.headers.get("x-admin-token") ||
    request.headers.get("ACCESS_GATE_ADMIN_TOKEN") ||
    request.headers.get("access_gate_admin_token") ||
    ""
  );
}

export function constantTimeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

export function requireAdminAuth(context) {
  const expectedToken = readAdminToken(context.env || {});
  if (!expectedToken) {
    const errorId = createErrorId("auth");
    logEvent("error", "access_gate.admin_token_missing", { errorId });
    return json({ error: "Admin token is not configured.", errorId }, 500);
  }
  const providedToken = tokenFromRequest(context.request);
  if (!constantTimeEqual(expectedToken, providedToken)) {
    const errorId = createErrorId("auth");
    logEvent("warn", "access_gate.admin_unauthorized", { errorId });
    return json({ error: "Unauthorized.", errorId }, 401);
  }
  return null;
}

async function readAdminTokenFromKv(env) {
  if (!env || !env.ACCESS_GATE_KV) return "";
  const raw = await env.ACCESS_GATE_KV.get("config:access_gate_admin_token");
  if (!raw) return "";
  try {
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed.token === "string") return parsed.token.trim();
  } catch {}
  return String(raw).trim();
}

export async function requireAdminAuthAsync(context) {
  const env = context.env || {};
  let expectedToken = readAdminToken(env);
  if (!expectedToken) {
    expectedToken = await readAdminTokenFromKv(env);
  }
  if (!expectedToken) {
    const errorId = createErrorId("auth");
    logEvent("error", "access_gate.admin_token_missing", { errorId });
    return json(
      {
        error: "Admin token is not configured.",
        hint: "Set ACCESS_GATE_ADMIN_TOKEN secret or KV key config:access_gate_admin_token.",
        errorId
      },
      500
    );
  }
  const providedToken = tokenFromRequest(context.request);
  if (!constantTimeEqual(expectedToken, providedToken)) {
    const errorId = createErrorId("auth");
    logEvent("warn", "access_gate.admin_unauthorized", { errorId });
    return json({ error: "Unauthorized.", errorId }, 401);
  }
  return null;
}

function readOtpWasmPolicy(env) {
  const requireOtp =
    (env && (env.ACCESS_GATE_REQUIRE_OTP || env.ACCESS_GATE_REQUIRE_OTP_WASM)) || "";
  const otpValue =
    (env && (env.ACCESS_GATE_OTP_VALUE || env.ACCESS_GATE_OTP_WASM_VALUE)) || "2608";
  return {
    enabled: String(requireOtp).toLowerCase() === "true",
    expectedProof: String(otpValue)
  };
}

export function requireOtpWasmIfEnabled(context) {
  const env = context.env || {};
  const { enabled, expectedProof } = readOtpWasmPolicy(env);
  if (!enabled) return null;

  const provided = String(context.request.headers.get("x-otp-wasm") || "").trim();
  if (!provided || !constantTimeEqual(provided, expectedProof)) {
    return json({ error: "Missing or invalid OTPWasm proof." }, 401);
  }
  return null;
}

export function createErrorId(prefix = "err") {
  const rand = crypto.getRandomValues(new Uint8Array(6));
  return `${prefix}_${toHex(rand)}`;
}

export function logEvent(level, event, data = {}) {
  const payload = {
    level,
    event,
    ts: new Date().toISOString(),
    ...data
  };
  const line = JSON.stringify(payload);
  if (level === "error") {
    console.error(line);
    return;
  }
  if (level === "warn") {
    console.warn(line);
    return;
  }
  console.log(line);
}

function pickClientIp(request) {
  return (
    request.headers.get("cf-connecting-ip") ||
    request.headers.get("x-forwarded-for") ||
    request.headers.get("x-real-ip") ||
    "unknown"
  )
    .split(",")[0]
    .trim();
}

function rateLimitKv(env) {
  if (env && env.ACCESS_GATE_RATE_LIMIT_KV) return env.ACCESS_GATE_RATE_LIMIT_KV;
  return null;
}

function envNumber(env, key, fallback) {
  const raw = env && env[key];
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

export async function enforceRateLimit(context, scope, defaults) {
  const env = context.env || {};
  const kv = rateLimitKv(env);
  if (!kv) {
    return { limited: false, enabled: false };
  }

  const limit = envNumber(env, `${scope.toUpperCase()}_RATE_LIMIT`, defaults.limit);
  const windowSec = envNumber(env, `${scope.toUpperCase()}_RATE_WINDOW_SEC`, defaults.windowSec);
  const ip = pickClientIp(context.request);
  const bucket = Math.floor(Date.now() / (windowSec * 1000));
  const key = `rl:${scope}:${ip}:${bucket}`;

  const currentRaw = await kv.get(key);
  const current = currentRaw ? Number(currentRaw) : 0;
  const next = Number.isFinite(current) ? current + 1 : 1;
  await kv.put(key, String(next), { expirationTtl: windowSec + 5 });

  if (next > limit) {
    return {
      limited: true,
      enabled: true,
      status: 429,
      response: json(
        {
          error: "Rate limit exceeded.",
          scope,
          limit,
          windowSec
        },
        429
      )
    };
  }

  return {
    limited: false,
    enabled: true,
    remaining: Math.max(0, limit - next),
    limit,
    windowSec
  };
}
