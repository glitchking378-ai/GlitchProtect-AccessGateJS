import {
  enforceRateLimit,
  getKvOrError,
  isValidUuidLike,
  json,
  parseCookieHeader,
  userKeyForId,
  validateAccessGateEnv
} from "../_utils/access-gate.js";

const COOKIE_NAME = "accessgate_sid";
const ONE_YEAR = 60 * 60 * 24 * 365;

function setCookieHeader(value) {
  return `${COOKIE_NAME}=${value}; Path=/; Max-Age=${ONE_YEAR}; HttpOnly; Secure; SameSite=Lax`;
}

export async function onRequestPost(context) {
  const rl = await enforceRateLimit(context, "access_session", { limit: 60, windowSec: 60 });
  if (rl.limited) return rl.response;

  const env = context.env || {};
  const validation = validateAccessGateEnv(env);
  if (!validation.ok) {
    return json({ error: "Invalid access gate environment.", issues: validation.issues }, 500);
  }
  const { kv, error } = getKvOrError(env);
  if (error) return error;

  const cookieHeader = context.request.headers.get("cookie") || "";
  const cookies = parseCookieHeader(cookieHeader);
  const existing = cookies[COOKIE_NAME];
  const id = isValidUuidLike(existing) ? existing.trim() : crypto.randomUUID();

  const now = new Date().toISOString();
  const key = await userKeyForId(id);
  const prior = await kv.get(key, { type: "json" });
  await kv.put(
    key,
    JSON.stringify({
      createdAt: prior && prior.createdAt ? prior.createdAt : now,
      lastSeenAt: now,
      source: "session-cookie"
    })
  );

  const response = json({
    ok: true,
    id,
    uuid: id
  });
  if (!existing || existing !== id) {
    response.headers.set("set-cookie", setCookieHeader(id));
  }
  return response;
}
