// src/index.ts
import { DurableObject } from "cloudflare:workers";

/**
 * Env bindings you MUST have (via wrangler.jsonc + secrets):
 * - MY_DURABLE_OBJECT (Durable Object namespace binding)
 * - PROVOST_EVENT_QUEUE (Queue binding)
 * - ORIGIN_BASE_URL (string var)
 * - FRONTEND_URL (string var)
 * - STRIPE_SECRET (secret)
 * - STRIPE_WEBHOOK_SECRET (secret)
 *
 * Optional:
 * - EDGE_ADMIN_TOKEN (secret/var)
 */
export interface Env {
  MY_DURABLE_OBJECT: DurableObjectNamespace;

  // Queues binding (wrangler "queues.producers")
  PROVOST_EVENT_QUEUE: Queue;

  // Reverse proxy origin (Heroku)
  ORIGIN_BASE_URL: string;

  // For success/cancel URLs
  FRONTEND_URL: string;

  // Stripe secrets
  STRIPE_SECRET: string;
  STRIPE_WEBHOOK_SECRET: string;

  // Optional: lock down edge-only endpoints
  EDGE_ADMIN_TOKEN?: string;
}

type CheckoutItem = {
  name?: string;
  currency?: string; // default usd
  unit_amount_cents?: number; // required if no price_id
  quantity?: number; // default 1
  price_id?: string; // optional if you use Stripe Prices later
};

type CheckoutRequestBody = {
  idempotency_key?: string;
  items: CheckoutItem[];
};

type StoredSession = {
  idempotency_key: string;
  session_id: string;
  checkout_url: string;
  status: "created" | "paid";
  created_at: string;
  paid_at?: string;
  items: CheckoutItem[];
  processed_event_ids?: string[];
};

function json(data: unknown, init: ResponseInit = {}) {
  const headers = new Headers(init.headers);
  headers.set("Content-Type", "application/json");
  return new Response(JSON.stringify(data), { ...init, headers });
}

function applyCors(resp: Response, req: Request) {
  const origin = req.headers.get("Origin");
  const headers = new Headers(resp.headers);

  if (!origin) return resp;

  headers.set("Access-Control-Allow-Origin", origin);
  headers.append("Vary", "Origin");
  headers.set("Access-Control-Allow-Credentials", "true");
  headers.set(
    "Access-Control-Allow-Headers",
    req.headers.get("Access-Control-Request-Headers") || "Content-Type, Authorization"
  );
  headers.set(
    "Access-Control-Allow-Methods",
    req.headers.get("Access-Control-Request-Method") || "GET,POST,PUT,PATCH,DELETE,OPTIONS"
  );

  return new Response(resp.body, { status: resp.status, statusText: resp.statusText, headers });
}

function isAllowedEdgeAdmin(req: Request, env: Env) {
  if (!env.EDGE_ADMIN_TOKEN) return true;
  return req.headers.get("X-Edge-Admin") === env.EDGE_ADMIN_TOKEN;
}

async function proxyToOrigin(request: Request, env: Env): Promise<Response> {
  if (!env.ORIGIN_BASE_URL) return new Response("Missing ORIGIN_BASE_URL", { status: 500 });

  const incomingUrl = new URL(request.url);
  const originBase = new URL(env.ORIGIN_BASE_URL);

  // Keep path + query, swap origin host
  const upstreamUrl = new URL(incomingUrl.pathname + incomingUrl.search, originBase);

  // Copy headers, remove hop-by-hop headers
  const headers = new Headers(request.headers);
  headers.delete("host");
  headers.delete("connection");
  headers.delete("keep-alive");
  headers.delete("proxy-authenticate");
  headers.delete("proxy-authorization");
  headers.delete("te");
  headers.delete("trailer");
  headers.delete("transfer-encoding");
  headers.delete("upgrade");

  // Helpful forwarding headers (Django logs / debugging)
  headers.set("X-Forwarded-Host", incomingUrl.host);
  headers.set("X-Forwarded-Proto", incomingUrl.protocol.replace(":", ""));
  const ip = request.headers.get("CF-Connecting-IP");
  if (ip) {
    headers.set("X-Forwarded-For", ip);
    headers.set("X-Real-IP", ip);
  }

  const init: RequestInit = {
    method: request.method,
    headers,
    body: request.method === "GET" || request.method === "HEAD" ? undefined : request.body,
    redirect: "manual",
    cf: { cacheTtl: 0, cacheEverything: false },
  };

  return fetch(upstreamUrl.toString(), init);
}

// ---------- Stripe webhook signature verification (Worker-native, no Stripe SDK) ----------
function parseStripeSigHeader(sigHeader: string | null): { t: string; v1s: string[] } | null {
  if (!sigHeader) return null;
  const parts = sigHeader.split(",").map((s) => s.trim());
  let t = "";
  const v1s: string[] = [];

  for (const p of parts) {
    const [k, v] = p.split("=");
    if (!k || !v) continue;
    if (k === "t") t = v;
    if (k === "v1") v1s.push(v);
  }
  if (!t || v1s.length === 0) return null;
  return { t, v1s };
}

function hexFromArrayBuffer(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let out = "";
  for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, "0");
  return out;
}

function timingSafeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function hmacSha256Hex(secret: string, message: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return hexFromArrayBuffer(sig);
}

async function verifyStripeWebhook(payloadText: string, sigHeader: string | null, secret: string): Promise<boolean> {
  const parsed = parseStripeSigHeader(sigHeader);
  if (!parsed) return false;

  // Stripe signs: `${t}.${payload}`
  const signedPayload = `${parsed.t}.${payloadText}`;
  const expected = await hmacSha256Hex(secret, signedPayload);

  for (const v1 of parsed.v1s) {
    if (timingSafeEqualHex(expected, v1)) return true;
  }
  return false;
}

// ---------- Stripe Checkout Session creation (Worker-native REST call) ----------
function normalizeItem(it: CheckoutItem): Required<Pick<CheckoutItem, "currency" | "quantity">> & CheckoutItem {
  return {
    ...it,
    currency: (it.currency || "usd").toLowerCase(),
    quantity: Math.max(1, Math.floor(it.quantity ?? 1)),
  };
}

function validateCheckoutBody(
  body: CheckoutRequestBody
): { ok: true; value: CheckoutRequestBody } | { ok: false; error: string } {
  if (!body || typeof body !== "object") return { ok: false, error: "invalid_json" };
  if (!Array.isArray(body.items) || body.items.length === 0) return { ok: false, error: "items_required" };
  if (body.items.length > 20) return { ok: false, error: "too_many_items" };

  for (const it of body.items) {
    const n = normalizeItem(it);
    const hasPriceId = typeof n.price_id === "string" && n.price_id.length > 0;
    const hasPriceData =
      typeof n.unit_amount_cents === "number" && Number.isFinite(n.unit_amount_cents) && n.unit_amount_cents > 0;

    if (!hasPriceId && !hasPriceData) return { ok: false, error: "each_item_requires_price_id_or_unit_amount_cents" };
    if (!hasPriceId) {
      const nm = (n.name || "").trim();
      if (!nm) return { ok: false, error: "each_item_requires_name_when_using_unit_amount_cents" };
    }
  }

  return { ok: true, value: body };
}

function buildStripeSessionParams(env: Env, idempotency_key: string, items: CheckoutItem[]) {
  const params = new URLSearchParams();

  params.set("mode", "payment");
  const frontend = (env.FRONTEND_URL || "").replace(/\/$/, "");
  params.set("success_url", `${frontend}/checkout/success?session_id={CHECKOUT_SESSION_ID}`);
  params.set("cancel_url", `${frontend}/checkout/cancel`);

  params.set("metadata[idempotency_key]", idempotency_key);
  params.set("metadata[source]", "provost-edge");

  const normalized = items.map(normalizeItem);

  normalized.forEach((it, idx) => {
    if (it.price_id) {
      params.set(`line_items[${idx}][price]`, it.price_id);
      params.set(`line_items[${idx}][quantity]`, String(it.quantity));
      return;
    }

    const unit = Math.max(1, Math.floor(it.unit_amount_cents ?? 0));
    params.set(`line_items[${idx}][price_data][currency]`, (it.currency || "usd").toLowerCase());
    params.set(`line_items[${idx}][price_data][unit_amount]`, String(unit));
    params.set(`line_items[${idx}][price_data][product_data][name]`, (it.name || "Item").slice(0, 250));
    params.set(`line_items[${idx}][quantity]`, String(it.quantity));
  });

  return params;
}

/**
 * Durable Object: authoritative state per idempotency_key.
 */
export class MyDurableObject extends DurableObject<Env> {
  // IMPORTANT: keep a reference to state; don't add a `ctx` property/getter
  private state: DurableObjectState;

  constructor(state: DurableObjectState, env: Env) {
    super(state, env);
    this.state = state;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/hello") {
      const name = url.searchParams.get("name") || "world";
      return json({ greeting: `Hello, ${name}!` }, { status: 200 });
    }

    if (url.pathname === "/create" && request.method === "POST") {
      return this.handleCreate(request);
    }

    if (url.pathname === "/status" && request.method === "GET") {
      const session = (await this.state.storage.get<StoredSession>("session")) || null;
      if (!session) return json({ error: "not_found" }, { status: 404 });
      return json({ ok: true, session }, { status: 200 });
    }

    if (url.pathname === "/markPaid" && request.method === "POST") {
      return this.handleMarkPaid(request);
    }

    return new Response("Not found", { status: 404 });
  }

  private async handleCreate(request: Request): Promise<Response> {
    const existing = await this.state.storage.get<StoredSession>("session");
    if (existing) return json({ ok: true, session: existing }, { status: 200 });

    let body: CheckoutRequestBody;
    try {
      body = (await request.json()) as CheckoutRequestBody;
    } catch {
      return json({ error: "invalid_json" }, { status: 400 });
    }

    const validated = validateCheckoutBody(body);
    if (!validated.ok) return json({ error: validated.error }, { status: 400 });

    const idempotency_key = (validated.value.idempotency_key || "").trim();
    if (!idempotency_key) return json({ error: "idempotency_key_required" }, { status: 400 });

    const stripeParams = buildStripeSessionParams(this.env, idempotency_key, validated.value.items);

    const stripeRes = await fetch("https://api.stripe.com/v1/checkout/sessions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${this.env.STRIPE_SECRET}`,
        "Content-Type": "application/x-www-form-urlencoded",
        // guarantees Stripe won’t create duplicates if this DO retries
        "Idempotency-Key": `provost:${idempotency_key}`,
      },
      body: stripeParams.toString(),
    });

    if (!stripeRes.ok) {
      const errTxt = await stripeRes.text();
      console.error("stripe_create_failed", stripeRes.status, errTxt);
      return json({ error: "stripe_create_failed", status: stripeRes.status, details: errTxt }, { status: 502 });
    }

    const session = (await stripeRes.json()) as { id: string; url: string };

    const stored: StoredSession = {
      idempotency_key,
      session_id: session.id,
      checkout_url: session.url,
      status: "created",
      created_at: new Date().toISOString(),
      items: validated.value.items,
      processed_event_ids: [],
    };

    await this.state.storage.put("session", stored);
    return json({ ok: true, session: stored }, { status: 200 });
  }

  private async handleMarkPaid(request: Request): Promise<Response> {
    let body: any;
    try {
      body = await request.json();
    } catch {
      return json({ error: "invalid_json" }, { status: 400 });
    }

    const eventId = String(body?.event_id || "");
    const sessionId = String(body?.session_id || "");
    const eventType = String(body?.event_type || "");

    const session = await this.state.storage.get<StoredSession>("session");
    if (!session) return json({ error: "not_found" }, { status: 404 });

    // Ignore if webhook is for different session
    if (sessionId && session.session_id && sessionId !== session.session_id) {
      return json({ ok: true, status: "ignored_wrong_session" }, { status: 200 });
    }

    if (eventId) {
      const processed = session.processed_event_ids || [];
      if (processed.includes(eventId)) return json({ ok: true, status: "already_processed" }, { status: 200 });
      processed.push(eventId);
      session.processed_event_ids = processed.slice(-20);
    }

    if (session.status !== "paid") {
      session.status = "paid";
      session.paid_at = new Date().toISOString();
    }

    await this.state.storage.put("session", session);
    return json({ ok: true, status: "paid", event_type: eventType }, { status: 200 });
  }
}

// ---------- Worker routes ----------
async function handleEdgeCheckout(request: Request, env: Env): Promise<Response> {
  if (request.method !== "POST") return new Response("Method Not Allowed", { status: 405 });

  let body: CheckoutRequestBody;
  try {
    body = (await request.json()) as CheckoutRequestBody;
  } catch {
    return json({ error: "invalid_json" }, { status: 400 });
  }

  const idempotency_key = (body.idempotency_key || crypto.randomUUID()).trim();
  const items = body.items || [];

  const doId = env.MY_DURABLE_OBJECT.idFromName(`checkout:${idempotency_key}`);
  const stub = env.MY_DURABLE_OBJECT.get(doId);

  const doResp = await stub.fetch("https://do.internal/create", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ idempotency_key, items }),
  });

  if (!doResp.ok) {
    const txt = await doResp.text();
    return json({ error: "do_create_failed", details: txt }, { status: doResp.status });
  }

  const payload = await doResp.json<any>();
  return json(
    {
      ok: true,
      idempotency_key,
      session: payload.session,
      checkout_url: payload.session?.checkout_url,
      session_id: payload.session?.session_id,
    },
    { status: 200 }
  );
}

async function handleStripeWebhook(request: Request, env: Env): Promise<Response> {
  if (request.method !== "POST") return new Response("Method Not Allowed", { status: 405 });

  const sig = request.headers.get("stripe-signature");
  const buf = await request.arrayBuffer();
  const payloadText = new TextDecoder("utf-8").decode(buf);

  const ok = await verifyStripeWebhook(payloadText, sig, env.STRIPE_WEBHOOK_SECRET);
  if (!ok) return new Response("invalid signature", { status: 400 });

  await env.PROVOST_EVENT_QUEUE.send(payloadText);
  return new Response("ok", { status: 200 });
}

async function processStripeEventMessage(messageBody: string, env: Env): Promise<void> {
  const ev = JSON.parse(messageBody) as any;
  const type = String(ev?.type || "");
  const eventId = String(ev?.id || "");

  const isPaidEvent =
    type === "checkout.session.completed" ||
    type === "checkout.session.async_payment_succeeded" ||
    type === "payment_intent.succeeded";

  if (!isPaidEvent) return;

  // Prefer checkout.session.* (it has metadata)
  if (type.startsWith("checkout.session.")) {
    const session = ev?.data?.object || {};
    const session_id = String(session?.id || "");
    const idempotency_key = String(session?.metadata?.idempotency_key || "");

    if (!idempotency_key) {
      console.error("webhook_missing_idempotency_key", { eventId, type, session_id });
      return;
    }

    const doId = env.MY_DURABLE_OBJECT.idFromName(`checkout:${idempotency_key}`);
    const stub = env.MY_DURABLE_OBJECT.get(doId);

    const res = await stub.fetch("https://do.internal/markPaid", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        event_id: eventId,
        event_type: type,
        session_id,
      }),
    });

    if (!res.ok) {
      // 5xx => retry
      if (res.status >= 500) {
        const t = await res.text();
        throw new Error(`DO markPaid failed: ${res.status} ${t}`);
      }
      // 4xx => permanent
      console.error("do_markPaid_nonretryable", res.status, await res.text());
    }

    return;
  }

  // payment_intent.succeeded won't include your session metadata; ignore for now.
  if (type === "payment_intent.succeeded") {
    console.warn("payment_intent_succeeded_received_but_not_mapped", { eventId });
    return;
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // Preflight
    if (request.method === "OPTIONS") {
      return applyCors(new Response(null, { status: 204 }), request);
    }

    // Edge-only healthcheck
    if (url.pathname === "/__edge/health") {
      return applyCors(new Response("ok", { status: 200 }), request);
    }

    // Edge-only DO test endpoint
    if (url.pathname === "/__edge/do-hello") {
      if (!isAllowedEdgeAdmin(request, env)) {
        return applyCors(new Response("unauthorized", { status: 401 }), request);
      }
      const name = url.searchParams.get("name") || "world";
      const id = env.MY_DURABLE_OBJECT.idFromName("default");
      const stub = env.MY_DURABLE_OBJECT.get(id);
      const doResp = await stub.fetch(`https://do.internal/hello?name=${encodeURIComponent(name)}`);
      return applyCors(doResp, request);
    }

    // Edge checkout
    if (url.pathname === "/edge/checkout") {
      const resp = await handleEdgeCheckout(request, env);
      return applyCors(resp, request);
    }

    // Stripe webhook intake
    if (url.pathname === "/webhooks/stripe") {
      const resp = await handleStripeWebhook(request, env);
      return applyCors(resp, request);
    }

    // Everything else: reverse proxy to Heroku origin
    const upstream = await proxyToOrigin(request, env);
    return applyCors(upstream, request);
  },

  // Queue consumer (Wrangler will type this as unknown; we cast inside)
  async queue(batch: MessageBatch, env: Env, ctx: ExecutionContext): Promise<void> {
    for (const msg of batch.messages) {
      try {
        const bodyStr = typeof msg.body === "string" ? msg.body : JSON.stringify(msg.body);
        await processStripeEventMessage(bodyStr, env);
        await (msg as any).ack?.();
      } catch (err) {
        console.error("queue_process_error", err);
        throw err; // retry
      }
    }
  },
} satisfies ExportedHandler<Env>;
