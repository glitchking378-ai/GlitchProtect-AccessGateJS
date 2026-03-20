import {
  enforceRateLimit,
  getKvOrError,
  isValidUuidLike,
  json,
  parseJsonBody,
  userKeyForUuid,
  validateAccessGateEnv
} from "../_utils/access-gate.js";

/**
 * Cloudflare Pages Functions env binding expected:
 * ACCESS_GATE_KV: KVNamespace
 */
export async function onRequestPost(context) {
  const rl = await enforceRateLimit(context, "access_issue", { limit: 20, windowSec: 60 });
  if (rl.limited) return rl.response;

  const body = await parseJsonBody(context.request);
  const existingUuid = body && (body.existingUuid || body.existingId);
  const uuid = isValidUuidLike(existingUuid) ? existingUuid.trim() : crypto.randomUUID();

  const env = context.env || {};
  const validation = validateAccessGateEnv(env);
  if (!validation.ok) {
    return json({ error: "Invalid access gate environment.", issues: validation.issues }, 500);
  }
  const { kv, error } = getKvOrError(env);
  if (error) return error;

  const key = await userKeyForUuid(uuid);
  const now = new Date().toISOString();
  const prior = await kv.get(key, { type: "json" });
  const record = {
    createdAt: prior && prior.createdAt ? prior.createdAt : now,
    lastSeenAt: now
  };

  await kv.put(key, JSON.stringify(record));

  return json({
    id: uuid,
    uuid,
    ok: true
  });
}
