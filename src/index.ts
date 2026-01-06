// src/index.ts
import { DurableObject } from "cloudflare:workers";

export interface Env {
  // Durable Object binding (from wrangler.jsonc)
  MY_DURABLE_OBJECT: DurableObjectNamespace;

  // Your true origin (Heroku) base URL, e.g.:
  // https://provost-api-67030f934f07.herokuapp.com
  ORIGIN_BASE_URL: string;

  // Optional: lock down edge-only endpoints
  EDGE_ADMIN_TOKEN?: string;
}

/**
 * Durable Object: implemented with fetch() (most compatible).
 * Instances are created automatically when you call idFromName()/get().
 */
export class MyDurableObject extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    // Example endpoint inside the DO
    if (url.pathname === "/hello") {
      const name = url.searchParams.get("name") || "world";
      return new Response(JSON.stringify({ greeting: `Hello, ${name}!` }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }

    return new Response("Not found", { status: 404 });
  }
}

function applyCors(resp: Response, req: Request) {
  const origin = req.headers.get("Origin");
  const headers = new Headers(resp.headers);

  // If no Origin header, it’s not a browser CORS request (or it’s same-origin).
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

      // Call the DO via fetch
      const doResp = await stub.fetch(`https://do.internal/hello?name=${encodeURIComponent(name)}`);
      return applyCors(doResp, request);
    }

    // Everything else: reverse proxy to Heroku origin
    const upstream = await proxyToOrigin(request, env);
    return applyCors(upstream, request);
  },
} satisfies ExportedHandler<Env>; 
