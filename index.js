export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Root endpoint
    if (url.pathname === "/" && request.method === "GET") {
      return new Response(
        JSON.stringify({
          ok: true,
          message:
            "GlitchProtect AccessGate Worker is running. Use /access/issue, /access/session, /access/check, /access/block, /access/unblock, /access/is-admin"
        }),
        {
          status: 200,
          headers: { "content-type": "application/json; charset=utf-8" }
        }
      );
    }

    // Example routing for your AccessGate endpoints
    if (url.pathname === "/access/issue" && request.method === "POST") {
      return issueAccess(request, env);
    }

    if (url.pathname === "/access/session" && request.method === "POST") {
      return createSession(request, env);
    }

    if (url.pathname === "/access/check" && request.method === "POST") {
      return checkAccess(request, env);
    }

    if (url.pathname === "/access/block" && request.method === "POST") {
      return blockUser(request, env);
    }

    if (url.pathname === "/access/unblock" && request.method === "POST") {
      return unblockUser(request, env);
    }

    if (url.pathname === "/access/is-admin" && request.method === "POST") {
      return isAdmin(request, env);
    }

    return new Response("Not found", { status: 404 });
  }
};

// -----------------------------
// Endpoint Implementations
// -----------------------------

async function issueAccess(request, env) {
  return new Response(JSON.stringify({ ok: true, endpoint: "issue" }), {
    headers: { "content-type": "application/json" }
  });
}

async function createSession(request, env) {
  return new Response(JSON.stringify({ ok: true, endpoint: "session" }), {
    headers: { "content-type": "application/json" }
  });
}

async function checkAccess(request, env) {
  return new Response(JSON.stringify({ ok: true, endpoint: "check" }), {
    headers: { "content-type": "application/json" }
  });
}

async function blockUser(request, env) {
  return new Response(JSON.stringify({ ok: true, endpoint: "block" }), {
    headers: { "content-type": "application/json" }
  });
}

async function unblockUser(request, env) {
  return new Response(JSON.stringify({ ok: true, endpoint: "unblock" }), {
    headers: { "content-type": "application/json" }
  });
}

async function isAdmin(request, env) {
  return new Response(JSON.stringify({ ok: true, endpoint: "is-admin" }), {
    headers: { "content-type": "application/json" }
  });
}
