import {
  blockKeyForUuid,
  enforceRateLimit,
  getKvOrError,
  isValidUuidLike,
  json,
  parseJsonBody,
  requireAdminAuthAsync,
  requireOtpWasmIfEnabled,
  validateAccessGateEnv
} from "../_utils/access-gate.js";

export async function onRequestPost(context) {
  const rl = await enforceRateLimit(context, "access_unblock", { limit: 20, windowSec: 60 });
  if (rl.limited) return rl.response;

  const otpError = requireOtpWasmIfEnabled(context);
  if (otpError) return otpError;

  const authError = await requireAdminAuthAsync(context);
  if (authError) return authError;

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
  await kv.delete(key);

  return json({
    ok: true,
    blocked: false
  });
}
