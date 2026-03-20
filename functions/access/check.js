import {
  blockKeyForUuid,
  enforceRateLimit,
  getKvOrError,
  isValidUuidLike,
  json,
  parseJsonBody,
  validateAccessGateEnv
} from "../_utils/access-gate.js";

/**
 * Cloudflare Pages Functions env binding expected:
 * ACCESS_GATE_KV: KVNamespace
 */
export async function onRequestPost(context) {
  const rl = await enforceRateLimit(context, "access_check", { limit: 180, windowSec: 60 });
  if (rl.limited) return rl.response;

  const env = context.env || {};
  const validation = validateAccessGateEnv(env);
  if (!validation.ok) {
    return json({ error: "Invalid access gate environment.", issues: validation.issues }, 500);
  }
  const { kv, error } = getKvOrError(env);
  if (error) return error;

  const body = await parseJsonBody(context.request);
  const uuid = body && (body.uuid || body.id);
  if (!isValidUuidLike(uuid)) {
    return json({ error: "Invalid or missing uuid." }, 400);
  }

  const key = await blockKeyForUuid(uuid.trim());
  const raw = await kv.get(key);

  if (!raw) {
    return json({ blocked: false });
  }

  try {
    const parsed = JSON.parse(raw);
    const blocked = parsed.blocked !== false;
    return json({
      blocked,
      reason: parsed.reason || null
    });
  } catch {
    return json({
      blocked: true,
      reason: raw
    });
  }
}
