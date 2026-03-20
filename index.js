export async function onRequestGet(context) {
  return new Response(JSON.stringify({
    ok: true,
    message: "GlitchProtect AccessGate functions are mounted. Use /access/issue, /access/session, /access/check, /access/block, /access/unblock, /access/is-admin"
  }), {
    status: 200,
    headers: { "content-type": "application/json; charset=utf-8" }
  });
}
