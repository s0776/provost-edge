// src/index.ts
import { DurableObject } from "cloudflare:workers";

/**
 * HARD REQUIREMENT:
 * - Django must NOT be touched until AFTER Stripe confirms payment.
 *
 * Env bindings required:
 * - MY_DURABLE_OBJECT (Durable Object namespace binding)
 * - PROVOST_EVENT_QUEUE (Queue binding)
 * - ORIGIN_BASE_URL (var)  -> https://provost-api-....herokuapp.com
 * - FRONTEND_URL (var)     -> https://joinprovost.com
 * - STRIPE_SECRET (secret)
 * - STRIPE_WEBHOOK_SECRET (secret)
 * - INTERNAL_AUTH_SECRET (secret)  -> used ONLY after paid, inside /finalize
 *
 * Optional:
 * - EDGE_ADMIN_TOKEN (secret/var)
 * - STRIPE_PRICE_MAP_JSON (var/secret) -> optional best-practice mapping to Stripe Price IDs
 */
export interface Env {
  MY_DURABLE_OBJECT: DurableObjectNamespace;
  PROVOST_EVENT_QUEUE: Queue;

  ORIGIN_BASE_URL: string;
  FRONTEND_URL: string;

  STRIPE_SECRET: string;
  STRIPE_WEBHOOK_SECRET: string;

  INTERNAL_AUTH_SECRET: string;

  STRIPE_PRICE_MAP_JSON?: string;

  EDGE_ADMIN_TOKEN?: string;
}

// -------------------- Pricing + labels (ported from your Django) --------------------

type TierId = "f50" | "f100" | "f1000";
type Volume = 10 | 25 | 50 | 100;

const PLACEHOLDER_SKU = "dynamic_package";

// Matches core/pricing.py exactly (whole dollars)
const BASE_PRICING_USD: Record<TierId, Record<Volume, number>> = {
  f1000: { 10: 9, 25: 50, 50: 100, 100: 100 },
  f100: { 10: 19, 25: 75, 50: 100, 100: 200 },
  f50: { 10: 19, 25: 75, 50: 100, 100: 200 },
};

const BANKING_PRICING_USD: Record<TierId, Record<Volume, number>> = {
  f1000: { 10: 9, 25: 50, 50: 100, 100: 100 },
  f100: { 10: 19, 25: 75, 50: 100, 100: 200 },
  f50: { 10: 29, 25: 100, 50: 150, 100: 200 },
};

const CONSULTING_PRICING_USD: Record<TierId, Record<Volume, number>> = {
  f1000: { 10: 9, 25: 50, 50: 100, 100: 100 },
  f100: { 10: 19, 25: 75, 50: 100, 100: 200 },
  f50: { 10: 29, 25: 100, 50: 150, 100: 200 },
};

const TECHNOLOGY_PRICING_USD: Record<TierId, Record<Volume, number>> = {
  f1000: { 10: 9, 25: 50, 50: 100, 100: 100 },
  f100: { 10: 19, 25: 75, 50: 100, 100: 200 },
  f50: { 10: 29, 25: 100, 50: 150, 100: 200 },
};

function tableForIndustry(industry_id: string): Record<TierId, Record<Volume, number>> {
  if (industry_id === "banking") return BANKING_PRICING_USD;
  if (industry_id === "consulting") return CONSULTING_PRICING_USD;
  if (industry_id === "technology") return TECHNOLOGY_PRICING_USD;
  return BASE_PRICING_USD;
}

function computePriceUsd(industry_id: string, tier_id: TierId, count: Volume): number {
  const table = tableForIndustry(industry_id || "all");
  return table[tier_id][count];
}

const INDUSTRY_LABELS: Record<string, string> = {
  all: "All Companies",
  banking: "Investment Banking",
  technology: "Technology",
  consulting: "Consulting",
  entertainment: "Entertainment",
  healthcare: "Healthcare",
  industrial: "Industrial",
  energy: "Energy",
  consumer: "Consumer",
  defense: "Defense",
};

// Your old backend label behavior
const TIER_LABEL_DEFAULTS: Record<TierId, string> = {
  f50: "Premium",
  f100: "Premium",
  f1000: "Standard",
};

const TIER_LABEL_OVERRIDES: Partial<Record<string, Partial<Record<TierId, string>>>> = {
  banking: { f50: "Bulge Bracket", f100: "Middle Market", f1000: "Regional" },
  consulting: { f50: "MBB", f100: "Big 4", f1000: "General" },
  technology: { f50: "Premier", f100: "Mid-Tier", f1000: "Standard" },
};

function tierLabelForIndustry(tier_id: TierId, industry_id: string): string {
  return TIER_LABEL_OVERRIDES[industry_id]?.[tier_id] || TIER_LABEL_DEFAULTS[tier_id] || String(tier_id);
}

// -------------------- Types --------------------

type EdgeCartItemInput = {
  tier_id: string;
  industry_id?: string;
  count: number;
  quantity: number;
};

type EdgeCheckoutRequestBody = {
  idempotency_key?: string; // browser nonce
  items: EdgeCartItemInput[];
};

type NormalizedCartItem = {
  tier_id: TierId;
  industry_id: string;
  count: Volume;
  quantity: number;
};

type ComputedLineItem = NormalizedCartItem & {
  unit_amount_cents: number;
  line_total_cents: number;
  display_name: string;
  display_desc: string;
  price_key: string; // industry:tier:count
};

type StoredSession = {
  effective_key: string; // nonce.cartHash
  nonce: string;
  cart_hash: string;

  stripe_session_id: string;
  checkout_url: string;

  status: "created" | "paid";
  created_at: string;
  paid_at?: string;

  // captured from webhook payload
  customer_email?: string;
  customer_phone?: string;
  stripe_customer_id?: string;

  // set only AFTER paid, once Django is reachable
  order_id?: number;
  origin_finalized_at?: string;

  items: ComputedLineItem[];
  processed_event_ids?: string[];
};

// -------------------- Small helpers --------------------

function json(data: unknown, init: ResponseInit = {}) {
  const headers = new Headers(init.headers);
  headers.set("Content-Type", "application/json");
  return new Response(JSON.stringify(data), { ...init, headers });
}

function applyCors(resp: Response, req: Request) {
  const origin = req.headers.get("Origin");
  if (!origin) return resp;

  const headers = new Headers(resp.headers);
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

function joinUrl(base: string, path: string) {
  const b = base.replace(/\/+$/, "");
  const p = path.startsWith("/") ? path : `/${path}`;
  return `${b}${p}`;
}

function isTierId(x: string): x is TierId {
  return x === "f50" || x === "f100" || x === "f1000";
}

function isVolume(x: number): x is Volume {
  return x === 10 || x === 25 || x === 50 || x === 100;
}

function normalizeItems(raw: unknown): { ok: true; items: NormalizedCartItem[] } | { ok: false; error: string } {
  if (!Array.isArray(raw) || raw.length === 0) return { ok: false, error: "items_required" };

  const out: NormalizedCartItem[] = [];

  for (const r of raw) {
    if (!r || typeof r !== "object") return { ok: false, error: "invalid_item" };
    const it = r as any;

    const tier_id = String(it.tier_id || "");
    const industry_id = String(it.industry_id || "all") || "all";

    const countNum = Number(it.count);
    const qtyNum = Number(it.quantity);

    if (!isTierId(tier_id)) return { ok: false, error: "invalid_tier_id" };
    if (!Number.isFinite(countNum) || !isVolume(countNum)) return { ok: false, error: "invalid_count" };
    if (!Number.isFinite(qtyNum) || qtyNum <= 0) return { ok: false, error: "invalid_quantity" };

    // Match your old backend enforcement (UI locked to 10)
    if (countNum !== 10) return { ok: false, error: "only_10_pack_allowed" };

    out.push({
      tier_id,
      industry_id,
      count: countNum,
      quantity: Math.floor(qtyNum),
    });
  }

  return { ok: true, items: out };
}

function computeLineItems(items: NormalizedCartItem[]): ComputedLineItem[] {
  return items.map((it) => {
    const price_usd = computePriceUsd(it.industry_id, it.tier_id, it.count);
    const unit_amount_cents = Math.round(price_usd * 100);

    const tier_label = tierLabelForIndustry(it.tier_id, it.industry_id);
    const industry_label = INDUSTRY_LABELS[it.industry_id] || String(it.industry_id);

    // EXACT format from your old Django checkout
    const display_name = `${industry_label} • ${tier_label} • ${it.count}-Pack`;
    const display_desc = `${it.count} verified recruiter emails • ${industry_label} • ${tier_label}`;

    return {
      ...it,
      unit_amount_cents,
      line_total_cents: unit_amount_cents * it.quantity,
      display_name,
      display_desc,
      price_key: `${it.industry_id}:${it.tier_id}:${it.count}`,
    };
  });
}

function canonicalCartStringForHash(items: NormalizedCartItem[]): string {
  const sorted = [...items].sort((a, b) => {
    const ak = `${a.industry_id}|${a.tier_id}|${a.count}|${a.quantity}`;
    const bk = `${b.industry_id}|${b.tier_id}|${b.count}|${b.quantity}`;
    return ak.localeCompare(bk);
  });
  return JSON.stringify(sorted);
}

function hexFromArrayBuffer(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let out = "";
  for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, "0");
  return out;
}

async function sha256Hex(text: string): Promise<string> {
  const enc = new TextEncoder();
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(text));
  return hexFromArrayBuffer(digest);
}

// -------------------- Stripe Price ID mapping (best practice for large scale) --------------------
// IMPORTANT:
// Using Stripe "price_data + product_data" creates new Products/Prices over time.
// At your scale, you want stable Price IDs per SKU.
// Provide env.STRIPE_PRICE_MAP_JSON like:
// { "all:f50:10": "price_...", "banking:f50:10": "price_...", ... }
let _cachedPriceMap: Record<string, string> | null = null;

function getPriceMap(env: Env): Record<string, string> {
  if (_cachedPriceMap) return _cachedPriceMap;
  const raw = env.STRIPE_PRICE_MAP_JSON;
  if (!raw) {
    _cachedPriceMap = {};
    return _cachedPriceMap;
  }
  try {
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === "object") {
      _cachedPriceMap = parsed as Record<string, string>;
      return _cachedPriceMap;
    }
  } catch {
    // ignore; will behave like empty map
  }
  _cachedPriceMap = {};
  return _cachedPriceMap;
}

// -------------------- Stripe session params --------------------

function buildStripeSessionParams(args: {
  env: Env;
  effective_key: string;
  items: ComputedLineItem[];
}) {
  const { env, effective_key, items } = args;

  const params = new URLSearchParams();
  params.set("mode", "payment");

  // Match old behavior
  params.set("allow_promotion_codes", "true");
  params.set("phone_number_collection[enabled]", "true");

  const frontend = (env.FRONTEND_URL || "").replace(/\/$/, "");
  // Include k=<effective_key> so the success page can poll edge status without Django
  params.set(
    "success_url",
    `${frontend}/checkout/success?session_id={CHECKOUT_SESSION_ID}&k=${encodeURIComponent(effective_key)}`
  );
  params.set("cancel_url", `${frontend}/#build`);

  // Metadata for queue consumer routing
  params.set("metadata[idempotency_key]", effective_key);
  params.set("metadata[source]", "provost-edge");
  params.set("metadata[product_sku]", PLACEHOLDER_SKU);

  const selectedIndustries = Array.from(new Set(items.map((i) => i.industry_id))).sort();
  params.set("metadata[selected_industries]", selectedIndustries.join(","));

  // Best practice: prefer Price IDs if you set STRIPE_PRICE_MAP_JSON
  const priceMap = getPriceMap(env);

  items.forEach((it, idx) => {
    params.set(`line_items[${idx}][quantity]`, String(it.quantity));

    const mappedPriceId = priceMap[it.price_key];
    if (mappedPriceId) {
      // Uses stable Stripe Price (recommended for scale)
      params.set(`line_items[${idx}][price]`, mappedPriceId);
      return;
    }

    // Fallback: dynamic price_data (restores EXACT checkout look immediately)
    params.set(`line_items[${idx}][price_data][currency]`, "usd");
    params.set(`line_items[${idx}][price_data][unit_amount]`, String(it.unit_amount_cents));
    params.set(`line_items[${idx}][price_data][product_data][name]`, it.display_name.slice(0, 250));
    params.set(`line_items[${idx}][price_data][product_data][description]`, it.display_desc.slice(0, 250));
  });

  return params;
}

// -------------------- Reverse proxy (unchanged) --------------------

async function proxyToOrigin(request: Request, env: Env): Promise<Response> {
  if (!env.ORIGIN_BASE_URL) return new Response("Missing ORIGIN_BASE_URL", { status: 500 });

  const incomingUrl = new URL(request.url);
  const originBase = new URL(env.ORIGIN_BASE_URL);
  const upstreamUrl = new URL(incomingUrl.pathname + incomingUrl.search, originBase);

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

  headers.set("X-Forwarded-Host", incomingUrl.host);
  headers.set("X-Forwarded-Proto", incomingUrl.protocol.replace(":", ""));
  const ip = request.headers.get("CF-Connecting-IP");
  if (ip) {
    headers.set("X-Forwarded-For", ip);
    headers.set("X-Real-IP", ip);
  }

  return fetch(upstreamUrl.toString(), {
    method: request.method,
    headers,
    body: request.method === "GET" || request.method === "HEAD" ? undefined : request.body,
    redirect: "manual",
    cf: { cacheTtl: 0, cacheEverything: false },
  });
}

// -------------------- Stripe webhook signature verify (unchanged) --------------------

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

function timingSafeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function hmacSha256Hex(secret: string, message: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, [
    "sign",
  ]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return hexFromArrayBuffer(sig);
}

async function verifyStripeWebhook(payloadText: string, sigHeader: string | null, secret: string): Promise<boolean> {
  const parsed = parseStripeSigHeader(sigHeader);
  if (!parsed) return false;

  const signedPayload = `${parsed.t}.${payloadText}`;
  const expected = await hmacSha256Hex(secret, signedPayload);

  for (const v1 of parsed.v1s) {
    if (timingSafeEqualHex(expected, v1)) return true;
  }
  return false;
}

// -------------------- Django internal call (ONLY AFTER PAID) --------------------

async function createPaidOrderInOrigin(env: Env, payload: unknown): Promise<{ order_id: number }> {
  const url = joinUrl(env.ORIGIN_BASE_URL, "/internal/edge/create-paid-order/");
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Internal-Auth": env.INTERNAL_AUTH_SECRET,
    },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    const t = await res.text();
    // Throw so queue retries (or goes to DLQ) — never lose paid orders
    throw new Error(`origin_create_paid_order_failed ${res.status}: ${t}`);
  }

  const j = (await res.json()) as any;
  const order_id = Number(j?.order_id);
  if (!Number.isFinite(order_id) || order_id <= 0) {
    throw new Error(`origin_create_paid_order_invalid_response: ${JSON.stringify(j).slice(0, 500)}`);
  }
  return { order_id };
}

// -------------------- Durable Object --------------------

export class MyDurableObject extends DurableObject<Env> {
  private state: DurableObjectState;

  private sockets: Set<WebSocket> = new Set();

  constructor(state: DurableObjectState, env: Env) {
    super(state, env);
    this.state = state;
  }

  private safeSend(ws: WebSocket, data: unknown) {
    try {
      ws.send(JSON.stringify(data));
      return true;
    } catch {
      return false;
    }
  }

  private broadcast(data: unknown) {
    for (const ws of this.sockets) {
      const ok = this.safeSend(ws, data);
      if (!ok) this.sockets.delete(ws);
    }
  }

  private async handleWs(request: Request): Promise<Response> {
    if (request.headers.get("Upgrade") !== "websocket") {
      return new Response("expected websocket", { status: 426 });
    }

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair) as [WebSocket, WebSocket];

    server.accept();
    this.sockets.add(server);

    server.addEventListener("close", () => this.sockets.delete(server));
    server.addEventListener("error", () => this.sockets.delete(server));

    // Optional: respond to pings from client (keeps some proxies happy)
    server.addEventListener("message", (evt: MessageEvent) => {
      const msg = typeof evt.data === "string" ? evt.data : "";
      if (msg === "ping") {
        this.safeSend(server, { type: "pong" });
      }
    });

    // Immediately push current state
    const session = (await this.state.storage.get<StoredSession>("session")) || null;
    this.safeSend(server, { type: "session", session });

    return new Response(null, { status: 101, webSocket: client });
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/create" && request.method === "POST") return this.handleCreate(request);
    if (url.pathname === "/status" && request.method === "GET") return this.handleStatus();
    if (url.pathname === "/markPaid" && request.method === "POST") return this.handleMarkPaid(request);
    if (url.pathname === "/finalize" && request.method === "POST") return this.handleFinalize();
    if (url.pathname === "/ws") return this.handleWs(request);


    if (url.pathname === "/hello") return json({ ok: true, hello: "world" }, { status: 200 });

    return new Response("Not found", { status: 404 });
  }

  private async handleStatus(): Promise<Response> {
    const session = (await this.state.storage.get<StoredSession>("session")) || null;
    if (!session) return json({ error: "not_found" }, { status: 404 });
    return json({ ok: true, session }, { status: 200 });
  }

    private async handleCreate(request: Request): Promise<Response> {
    // Idempotent: if already created for this DO instance, return it
    const existing = await this.state.storage.get<StoredSession>("session");
    if (existing) {
      // If the session has already been paid, do NOT return the same checkout_url.
      // Returning a paid session causes Stripe to show "this session has already been used".
      if (existing.status === "paid") {
        return json(
          {
            error: "session_already_paid",
            message: "This checkout session has already been paid; start a fresh checkout attempt.",
          },
          { status: 409 }
        );
      }
      // If not paid, return the existing session (idempotent create behavior).
      return json({ ok: true, session: existing }, { status: 200 });
    }

    let body: any;
    try {
      body = await request.json();
    } catch {
      return json({ error: "invalid_json" }, { status: 400 });
    }

    const effective_key = String(body?.effective_key || "");
    const nonce = String(body?.nonce || "");
    const cart_hash = String(body?.cart_hash || "");
    const normalizedItems = body?.items as unknown;

    if (!effective_key || !nonce || !cart_hash) {
      return json({ error: "missing_effective_key_or_nonce_or_cart_hash" }, { status: 400 });
    }

    const norm = normalizeItems(normalizedItems);
    if (!norm.ok) return json({ error: norm.error }, { status: 400 });

    const computed = computeLineItems(norm.items);

    // Create Stripe Checkout Session (NO Django call here)
    const stripeParams = buildStripeSessionParams({
      env: this.env,
      effective_key,
      items: computed,
    });

    const stripeRes = await fetch("https://api.stripe.com/v1/checkout/sessions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${this.env.STRIPE_SECRET}`,
        "Content-Type": "application/x-www-form-urlencoded",
        // Cart-sensitive idempotency
        "Idempotency-Key": `provost:${effective_key}`,
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
      effective_key,
      nonce,
      cart_hash,

      stripe_session_id: session.id,
      checkout_url: session.url,

      status: "created",
      created_at: new Date().toISOString(),

      items: computed,
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

    const customer_email = body?.customer_email ? String(body.customer_email) : undefined;
    const customer_phone = body?.customer_phone ? String(body.customer_phone) : undefined;
    const stripe_customer_id = body?.stripe_customer_id ? String(body.stripe_customer_id) : undefined;

    const stored = await this.state.storage.get<StoredSession>("session");
    if (!stored) return json({ error: "not_found" }, { status: 404 });

    // Ignore if webhook is for different session
    if (sessionId && stored.stripe_session_id && sessionId !== stored.stripe_session_id) {
      return json({ ok: true, status: "ignored_wrong_session" }, { status: 200 });
    }

    // De-dupe by Stripe event id
    if (eventId) {
      const processed = stored.processed_event_ids || [];
      if (processed.includes(eventId)) return json({ ok: true, status: "already_processed" }, { status: 200 });
      processed.push(eventId);
      stored.processed_event_ids = processed.slice(-50);
    }

    if (stored.status !== "paid") {
      stored.status = "paid";
      stored.paid_at = new Date().toISOString();
    }

    // capture customer info if present
    if (customer_email) stored.customer_email = customer_email;
    if (customer_phone) stored.customer_phone = customer_phone;
    if (stripe_customer_id) stored.stripe_customer_id = stripe_customer_id;

    await this.state.storage.put("session", stored);
    this.broadcast({ type: "session", session: stored });
    return json({ ok: true, status: "paid", event_type: eventType }, { status: 200 });
  }

  private async handleFinalize(): Promise<Response> {
    const stored = await this.state.storage.get<StoredSession>("session");
    if (!stored) return json({ error: "not_found" }, { status: 404 });

    if (stored.status !== "paid") {
      // queue called too early or wrong event type
      return json({ error: "not_paid" }, { status: 409 });
    }

    if (stored.order_id) {
      return json({ ok: true, status: "already_finalized", order_id: stored.order_id }, { status: 200 });
    }

    const total_cents = stored.items.reduce((sum, it) => sum + it.line_total_cents, 0);

    // Create PAID order in Django now (this is the FIRST time we touch Django)
    const { order_id } = await createPaidOrderInOrigin(this.env, {
      effective_key: stored.effective_key,
      stripe_session_id: stored.stripe_session_id,
      checkout_url: stored.checkout_url,
      paid_at: stored.paid_at,
      currency: "USD",
      total_cents,
      customer_email: stored.customer_email,
      customer_phone: stored.customer_phone,
      stripe_customer_id: stored.stripe_customer_id,
      items: stored.items,
    });

    stored.order_id = order_id;
    stored.origin_finalized_at = new Date().toISOString();
    await this.state.storage.put("session", stored);
    this.broadcast({ type: "session", session: stored });
    return json({ ok: true, status: "finalized", order_id }, { status: 200 });
  }
}

// -------------------- Worker routes --------------------

async function handleEdgeCheckout(request: Request, env: Env): Promise<Response> {
  if (request.method !== "POST") return new Response("Method Not Allowed", { status: 405 });

  let body: EdgeCheckoutRequestBody;
  try {
    body = (await request.json()) as EdgeCheckoutRequestBody;
  } catch {
    return json({ error: "invalid_json" }, { status: 400 });
  }

  const nonce = (body.idempotency_key || crypto.randomUUID()).trim();

  const normalized = normalizeItems(body.items);
  if (!normalized.ok) return json({ error: normalized.error }, { status: 400 });

  // Cart-sensitive idempotency (fixes your “back/change cart” bug)
  const cartStr = canonicalCartStringForHash(normalized.items);
  const cart_hash = await sha256Hex(cartStr);
  const effective_key = `${nonce}.${cart_hash}`;

  // DO instance per effective_key
  const doId = env.MY_DURABLE_OBJECT.idFromName(`checkout:${effective_key}`);
  const stub = env.MY_DURABLE_OBJECT.get(doId);

  const doResp = await stub.fetch("https://do.internal/create", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      nonce,
      cart_hash,
      effective_key,
      items: normalized.items,
    }),
  });

  if (!doResp.ok) {
    const txt = await doResp.text();
    return json({ error: "do_create_failed", details: txt }, { status: doResp.status });
  }

  const payload = await doResp.json<any>();
  const session: StoredSession | undefined = payload?.session;

  return json(
    {
      ok: true,
      idempotency_key: nonce, // keep storing this browser nonce
      cart_hash,
      checkout_key: effective_key, // store this per-attempt (used for status polling)
      checkout_url: session?.checkout_url,
      stripe_session_id: session?.stripe_session_id,
    },
    { status: 200 }
  );
}

async function handleEdgeCheckoutStatus(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const k = url.searchParams.get("k") || "";
  if (!k) return json({ error: "missing_k" }, { status: 400 });

  const doId = env.MY_DURABLE_OBJECT.idFromName(`checkout:${k}`);
  const stub = env.MY_DURABLE_OBJECT.get(doId);

  const doResp = await stub.fetch("https://do.internal/status", { method: "GET" });
  if (!doResp.ok) {
    const t = await doResp.text();
    return json({ error: "status_failed", details: t }, { status: doResp.status });
  }

  const data = await doResp.json<any>();
  // returns { ok:true, session }
  return json(data, { status: 200 });
}

async function handleStripeWebhook(request: Request, env: Env): Promise<Response> {
  if (request.method !== "POST") return new Response("Method Not Allowed", { status: 405 });

  const sig = request.headers.get("stripe-signature");
  const buf = await request.arrayBuffer();
  const payloadText = new TextDecoder("utf-8").decode(buf);

  const ok = await verifyStripeWebhook(payloadText, sig, env.STRIPE_WEBHOOK_SECRET);
  if (!ok) return new Response("invalid signature", { status: 400 });

  // Do NOT do heavy work here. Enqueue and return immediately.
  await env.PROVOST_EVENT_QUEUE.send(payloadText);
  return new Response("ok", { status: 200 });
}

async function handleEdgeCheckoutWs(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const k = url.searchParams.get("k") || "";
  if (!k) return new Response("missing k", { status: 400 });

  // Must be a websocket upgrade request
  if (request.headers.get("Upgrade") !== "websocket") {
    return new Response("expected websocket", { status: 426 });
  }

  const doId = env.MY_DURABLE_OBJECT.idFromName(`checkout:${k}`);
  const stub = env.MY_DURABLE_OBJECT.get(doId);

  // Forward the websocket upgrade to the Durable Object
  const doReq = new Request("https://do.internal/ws", request);
  return stub.fetch(doReq);
}


// -------------------- Queue consumer --------------------

function isPaidCheckoutEvent(type: string): boolean {
  return type === "checkout.session.completed" || type === "checkout.session.async_payment_succeeded";
}

async function processStripeEventMessage(messageBody: string, env: Env): Promise<void> {
  const ev = JSON.parse(messageBody) as any;
  const type = String(ev?.type || "");
  const eventId = String(ev?.id || "");

  if (!isPaidCheckoutEvent(type)) return;

  const sessionObj = ev?.data?.object || {};
  const stripe_session_id = String(sessionObj?.id || "");
  const effective_key = String(sessionObj?.metadata?.idempotency_key || "");

  if (!stripe_session_id || !effective_key) {
    console.error("webhook_missing_routing", { eventId, type, stripe_session_id, effective_key });
    return;
  }

  // Extra safety: only treat as paid if Stripe says paid (for completed)
  const payment_status = String(sessionObj?.payment_status || "");
  if (type === "checkout.session.completed" && payment_status && payment_status !== "paid") {
    // not paid yet; ignore/ack
    console.warn("checkout_completed_not_paid", { eventId, stripe_session_id, payment_status });
    return;
  }

  const customer_email = sessionObj?.customer_details?.email;
  const customer_phone = sessionObj?.customer_details?.phone;
  const stripe_customer_id = sessionObj?.customer;

  const doId = env.MY_DURABLE_OBJECT.idFromName(`checkout:${effective_key}`);
  const stub = env.MY_DURABLE_OBJECT.get(doId);

  // 1) mark paid (idempotent)
  const mark = await stub.fetch("https://do.internal/markPaid", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      event_id: eventId,
      event_type: type,
      session_id: stripe_session_id,
      customer_email,
      customer_phone,
      stripe_customer_id,
    }),
  });

  if (!mark.ok) {
    const t = await mark.text();
    // retry on 5xx by throwing
    if (mark.status >= 500) throw new Error(`DO markPaid failed ${mark.status}: ${t}`);
    console.error("do_markPaid_nonretryable", mark.status, t);
    return;
  }

  // 2) finalize into Django (ONLY after paid)
  // If Django is down, this MUST retry (never lose paid orders).
  const fin = await stub.fetch("https://do.internal/finalize", { method: "POST" });
  if (!fin.ok) {
    const t = await fin.text();
    // Always retry finalization failures (Django might be down)
    throw new Error(`finalize_failed ${fin.status}: ${t}`);
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return applyCors(new Response(null, { status: 204 }), request);
    }

    if (url.pathname === "/__edge/health") {
      return applyCors(new Response("ok", { status: 200 }), request);
    }

    if (url.pathname === "/__edge/do-hello") {
      if (!isAllowedEdgeAdmin(request, env)) {
        return applyCors(new Response("unauthorized", { status: 401 }), request);
      }
      const id = env.MY_DURABLE_OBJECT.idFromName("default");
      const stub = env.MY_DURABLE_OBJECT.get(id);
      const doResp = await stub.fetch("https://do.internal/hello");
      return applyCors(doResp, request);
    }

    if (url.pathname === "/edge/checkout") {
      const resp = await handleEdgeCheckout(request, env);
      return applyCors(resp, request);
    }

    if (url.pathname === "/edge/checkout/status") {
      const resp = await handleEdgeCheckoutStatus(request, env);
      return applyCors(resp, request);
    }

    if (url.pathname === "/edge/checkout/ws") {
  return handleEdgeCheckoutWs(request, env);
}


    if (url.pathname === "/webhooks/stripe") {
      const resp = await handleStripeWebhook(request, env);
      return applyCors(resp, request);
    }

    // Everything else: reverse proxy to Heroku origin
    const upstream = await proxyToOrigin(request, env);
    return applyCors(upstream, request);
  },

  async queue(batch: MessageBatch, env: Env, ctx: ExecutionContext): Promise<void> {
    for (const msg of batch.messages) {
      try {
        const bodyStr = typeof msg.body === "string" ? msg.body : JSON.stringify(msg.body);
        await processStripeEventMessage(bodyStr, env);
        await (msg as any).ack?.();
      } catch (err) {
        console.error("queue_process_error", err);
        // Throw => Cloudflare retries; if too many retries => DLQ.
        throw err;
      }
    }
  },
} satisfies ExportedHandler<Env>;
