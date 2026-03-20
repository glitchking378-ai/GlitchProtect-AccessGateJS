import { json, requireAdminAuthAsync, requireOtpWasmIfEnabled, validateAccessGateEnv } from "../_utils/access-gate.js";

export async function onRequestPost(context) {
  const otpError = requireOtpWasmIfEnabled(context);
  if (otpError) return otpError;

  const validation = validateAccessGateEnv(context.env || {});
  if (!validation.ok) {
    return json({ error: "Invalid access gate environment.", issues: validation.issues }, 500);
  }

  const authError = await requireAdminAuthAsync(context);
  if (authError) return authError;

  return json({
    ok: true,
    isAdmin: true
  });
}
