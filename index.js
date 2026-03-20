export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === "OPTIONS") {
      return cors();
    }

    if (path === "/" && request.method === "GET") {
      return json({
        ok: true,
        message:
          "GlitchProtect AccessGate Worker is running. Endpoints: /access/issue, /access/session, /access/check, /access/block, /access/unblock, /access/is-admin"
      });
    }

    if (path === "/access/issue" && request.method === "POST") {
      return issueIdentity(request, env);
    }

    if (path === "/access/session" && request.method === "POST") {
      return createSession(request, env);
    }

    if (path === "/access/check" && request.method === "POST") {
      return checkBlocked(request, env);
    }

    if (path === "/access/block" && request.method === "POST") {
      return blockUser(request, env);
    }

    if (path === "/access/unblock" && request.method === "POST") {
      return unblockUser(request, env);
    }

    if (path === "/access/is-admin" && request.method === "POST") {
      return isAdmin(request, env);
    }

    return new Response("Not found", { status: 404 });
  }
};

function cors() {
  return new Response("", {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "*",
      "Access-Control-Allow-Methods": "GET,POST,OPTIONS"
    }
  });
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      "content-type": "application/json",
      "Access-Control-Allow-Origin": "*"
    }
  });
}

async function readJson(request) {
  try {
    return await request.json();
  } catch {
    return {};
  }
}

function randomId() {
  return crypto.randomUUID().replace(/-/g, "");
}

function isValidId(id) {
  return typeof id === "string" && id.trim().length >= 8 && id.trim().length <= 128;
}

async function issueIdentity(request, env) {
  const body = await readJson(request);
  const existing = body.existingId;

  if (isValidId(existing)) {
    await env.ACCESS_GATE_KV.put(`identity:${existing}`, JSON.stringify({ updated: Date.now() }));
    return json({ id: existing });
  }

  const id = randomId();
  await env.ACCESS_GATE_KV.put(`identity:${id}`, JSON.stringify({ created: Date.now() }));

  return json({ id });
}

async function createSession(request, env) {
  const id = randomId();
  await env.ACCESS_GATE_KV.put(`session:${id}`, JSON.stringify({ created: Date.now() }));
  return json({ id });
}

async function checkBlocked(request, env) {
  const body = await readJson(request);
  const id = body.id || body.uuid;

  if (!isValidId(id)) {
    return json({ blocked: false });
  }

  const block = await env.ACCESS_GATE_KV.get(`block:${id}`, "json");
  return json({ blocked: !!block });
}

async function blockUser(request, env) {
  const token =
    request.headers.get("x-access-gate-token") ||
    request.headers.get("ACCESS_GATE_ADMIN_TOKEN");

  if (!token) return json({ ok: false, error: "missing-admin-token" }, 403);

  const admin = await env.ACCESS_GATE_KV.get(`admin:${token}`);
  if (!admin) return json({ ok: false, error: "invalid-admin-token" }, 403);

  const body = await readJson(request);
  const id = body.id || body.uuid;
  const reason = body.reason || "manual";

  if (!isValidId(id)) return json({ ok: false, error: "invalid-id" }, 400);

  await env.ACCESS_GATE_KV.put(
    `block:${id}`,
    JSON.stringify({ reason, timestamp: Date.now() })
  );

  return json({ ok: true, id, blocked: true });
}

async function unblockUser(request, env) {
  const token =
    request.headers.get("x-access-gate-token") ||
    request.headers.get("ACCESS_GATE_ADMIN_TOKEN");

  if (!token) return json({ ok: false, error: "missing-admin-token" }, 403);

  const admin = await env.ACCESS_GATE_KV.get(`admin:${token}`);
  if (!admin) return json({ ok: false, error: "invalid-admin-token" }, 403);

  const body = await readJson(request);
  const id = body.id || body.uuid;

  if (!isValidId(id)) return json({ ok: false, error: "invalid-id" }, 400);

  await env.ACCESS_GATE_KV.delete(`block:${id}`);

  return json({ ok: true, id, blocked: false });
}

async function isAdmin(request, env) {
  const token =
    request.headers.get("x-access-gate-token") ||
    request.headers.get("ACCESS_GATE_ADMIN_TOKEN");

  if (!token) return json({ isAdmin: false });

  const admin = await env.ACCESS_GATE_KV.get(`admin:${token}`);
  return json({ isAdmin: !!admin });
}
