// behest — Cloudflare Worker broker
// Credential relay: stores encrypted credential blobs, never sees plaintext.

export interface Env {
  REQUESTS: KVNamespace;
  REQUEST_TTL_SECONDS: string;
  MAX_CREDENTIAL_BYTES: string;
  NOTIFIERS: string; // JSON array of notifier configs
}

interface CreateRequest {
  service: string;
  message: string;
  hint?: string;
  public_key: string;
}

interface StoredRequest {
  id: string;
  service: string;
  message: string;
  hint: string;
  public_key: string;
  status: "pending" | "fulfilled";
  created_at: string;
  expires_at: string;
  credential?: {
    nonce: string;
    ciphertext: string;
    agent_public_key: string;
  };
}

interface NotifierConfig {
  type: "ntfy" | "webhook";
  url: string;
  headers?: Record<string, string>;
  topic?: string;
}

// --- CORS ---

const CORS_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Max-Age": "86400",
};

function corsify(response: Response): Response {
  const headers = new Headers(response.headers);
  for (const [k, v] of Object.entries(CORS_HEADERS)) {
    headers.set(k, v);
  }
  return new Response(response.body, { status: response.status, headers });
}

// --- Helpers ---

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function errorResponse(error: string, message: string, status: number): Response {
  return json({ error, message }, status);
}

function ttl(env: Env): number {
  return parseInt(env.REQUEST_TTL_SECONDS || "600", 10);
}

function maxCredentialBytes(env: Env): number {
  return parseInt(env.MAX_CREDENTIAL_BYTES || "65536", 10);
}

// --- Notifiers ---

async function fireNotifiers(env: Env, request: StoredRequest): Promise<void> {
  let configs: NotifierConfig[];
  try {
    configs = JSON.parse(env.NOTIFIERS || "[]");
  } catch {
    return;
  }

  const promises = configs.map(async (config) => {
    const payload = {
      id: request.id,
      service: request.service,
      message: request.message,
      created_at: request.created_at,
      expires_at: request.expires_at,
    };

    try {
      if (config.type === "ntfy") {
        await fetch(config.url, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Title: `behest: ${request.service}`,
            Priority: "high",
            Tags: "key",
            ...(config.headers || {}),
          },
          body: request.message,
        });
      } else if (config.type === "webhook") {
        await fetch(config.url, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            ...(config.headers || {}),
          },
          body: JSON.stringify(payload),
        });
      }
    } catch {
      // Notifier failures are non-fatal
    }
  });

  await Promise.allSettled(promises);
}

// --- Route: POST /v1/requests ---

async function createRequest(request: Request, env: Env): Promise<Response> {
  let body: CreateRequest;
  try {
    body = (await request.json()) as CreateRequest;
  } catch {
    return errorResponse("bad_request", "Invalid JSON body", 400);
  }

  if (!body.service || typeof body.service !== "string") {
    return errorResponse("bad_request", "Missing or invalid 'service'", 400);
  }
  if (!body.message || typeof body.message !== "string") {
    return errorResponse("bad_request", "Missing or invalid 'message'", 400);
  }
  if (!body.public_key || typeof body.public_key !== "string") {
    return errorResponse("bad_request", "Missing or invalid 'public_key'", 400);
  }
  if (body.service.length > 128) {
    return errorResponse("bad_request", "Service name exceeds 128 characters", 400);
  }
  if (body.message.length > 1024) {
    return errorResponse("bad_request", "Message exceeds 1 KiB", 400);
  }
  if (body.hint && body.hint.length > 4096) {
    return errorResponse("bad_request", "Hint exceeds 4 KiB", 400);
  }

  const id = crypto.randomUUID();
  const now = new Date();
  const ttlSeconds = ttl(env);
  const expiresAt = new Date(now.getTime() + ttlSeconds * 1000);

  const stored: StoredRequest = {
    id,
    service: body.service,
    message: body.message,
    hint: body.hint || "",
    public_key: body.public_key,
    status: "pending",
    created_at: now.toISOString(),
    expires_at: expiresAt.toISOString(),
  };

  await env.REQUESTS.put(`req:${id}`, JSON.stringify(stored), {
    expirationTtl: ttlSeconds,
  });

  // Index for pending list
  await env.REQUESTS.put(`pending:${id}`, id, {
    expirationTtl: ttlSeconds,
  });

  // Fire notifiers in background
  fireNotifiers(env, stored);

  return json({ id, expires_at: expiresAt.toISOString(), status: "pending" }, 201);
}

// --- Route: GET /v1/requests/:id ---

async function getRequest(id: string, env: Env): Promise<Response> {
  const raw = await env.REQUESTS.get(`req:${id}`);
  if (raw === null) {
    // Check if it was consumed
    const consumed = await env.REQUESTS.get(`consumed:${id}`);
    if (consumed !== null) {
      return errorResponse("gone", "Request was already consumed", 410);
    }
    return errorResponse("not_found", "Request not found or expired", 404);
  }

  const stored: StoredRequest = JSON.parse(raw);

  if (stored.status === "fulfilled" && stored.credential) {
    // Single-use: delete the request, mark as consumed
    await env.REQUESTS.delete(`req:${id}`);
    await env.REQUESTS.delete(`pending:${id}`);
    await env.REQUESTS.put(`consumed:${id}`, "1", { expirationTtl: ttl(env) });

    return json({
      id: stored.id,
      service: stored.service,
      message: stored.message,
      status: "fulfilled",
      expires_at: stored.expires_at,
      credential: stored.credential,
    });
  }

  return json({
    id: stored.id,
    service: stored.service,
    message: stored.message,
    status: stored.status,
    expires_at: stored.expires_at,
  });
}

// --- Route: POST /v1/requests/:id/fulfill ---

async function fulfillRequest(id: string, request: Request, env: Env): Promise<Response> {
  const raw = await env.REQUESTS.get(`req:${id}`);
  if (raw === null) {
    return errorResponse("not_found", "Request not found or expired", 404);
  }

  const stored: StoredRequest = JSON.parse(raw);
  if (stored.status === "fulfilled") {
    return errorResponse("conflict", "Request already fulfilled", 409);
  }

  let body: { nonce: string; ciphertext: string; agent_public_key: string };
  try {
    body = (await request.json()) as typeof body;
  } catch {
    return errorResponse("bad_request", "Invalid JSON body", 400);
  }

  if (!body.nonce || !body.ciphertext || !body.agent_public_key) {
    return errorResponse("bad_request", "Missing nonce, ciphertext, or agent_public_key", 400);
  }

  // Check credential size (base64 is ~4/3 of raw)
  const estimatedSize = Math.ceil(body.ciphertext.length * 3 / 4);
  if (estimatedSize > maxCredentialBytes(env)) {
    return errorResponse("payload_too_large", "Credential exceeds size limit", 413);
  }

  stored.status = "fulfilled";
  stored.credential = {
    nonce: body.nonce,
    ciphertext: body.ciphertext,
    agent_public_key: body.agent_public_key,
  };

  // Calculate remaining TTL
  const remaining = Math.max(
    60,
    Math.floor((new Date(stored.expires_at).getTime() - Date.now()) / 1000)
  );

  await env.REQUESTS.put(`req:${id}`, JSON.stringify(stored), {
    expirationTtl: remaining,
  });

  return new Response(null, { status: 204 });
}

// --- Route: GET /v1/requests/pending ---

async function listPending(env: Env): Promise<Response> {
  const list = await env.REQUESTS.list({ prefix: "pending:" });
  const requests: Omit<StoredRequest, "credential" | "status">[] = [];

  for (const key of list.keys) {
    const id = key.name.slice("pending:".length);
    const raw = await env.REQUESTS.get(`req:${id}`);
    if (raw === null) continue;
    const stored: StoredRequest = JSON.parse(raw);
    if (stored.status !== "pending") continue;
    requests.push({
      id: stored.id,
      service: stored.service,
      message: stored.message,
      hint: stored.hint,
      public_key: stored.public_key,
      created_at: stored.created_at,
      expires_at: stored.expires_at,
    });
  }

  return json({ requests });
}

// --- Route: DELETE /v1/requests/:id ---

async function deleteRequest(id: string, env: Env): Promise<Response> {
  await env.REQUESTS.delete(`req:${id}`);
  await env.REQUESTS.delete(`pending:${id}`);
  return new Response(null, { status: 204 });
}

// --- Router ---

async function handleRequest(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  // POST /v1/requests
  if (path === "/v1/requests" && method === "POST") {
    return createRequest(request, env);
  }

  // GET /v1/requests/pending
  if (path === "/v1/requests/pending" && method === "GET") {
    return listPending(env);
  }

  // GET /v1/requests/:id
  const getMatch = path.match(/^\/v1\/requests\/([0-9a-f-]{36})$/);
  if (getMatch && method === "GET") {
    return getRequest(getMatch[1], env);
  }

  // POST /v1/requests/:id/fulfill
  const fulfillMatch = path.match(/^\/v1\/requests\/([0-9a-f-]{36})\/fulfill$/);
  if (fulfillMatch && method === "POST") {
    return fulfillRequest(fulfillMatch[1], request, env);
  }

  // DELETE /v1/requests/:id
  const deleteMatch = path.match(/^\/v1\/requests\/([0-9a-f-]{36})$/);
  if (deleteMatch && method === "DELETE") {
    return deleteRequest(deleteMatch[1], env);
  }

  return errorResponse("not_found", "Not found", 404);
}

// --- Entry point ---

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }
    const response = await handleRequest(request, env);
    return corsify(response);
  },
} satisfies ExportedHandler<Env>;
