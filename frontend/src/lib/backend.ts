import { NextRequest, NextResponse } from "next/server";

// Server-side only — these env vars are NOT exposed to the browser.
const API_BASE = process.env.API_BASE ?? "http://localhost:8000";
const API_TOKEN = process.env.API_TOKEN ?? "";

/**
 * Forward a browser request to the backend and relay the response.
 *
 * Injects the shared bearer token (authenticates this proxy to the backend),
 * forwards the session Cookie and the real client IP, and relays Set-Cookie
 * and redirect Location back so auth cookies land on the frontend origin and
 * OAuth redirects resolve there.
 */
export async function proxyRequest(
  req: NextRequest,
  backendPath: string,
  init?: { method?: string; body?: string | null }
): Promise<NextResponse> {
  const headers: Record<string, string> = {};
  if (API_TOKEN) headers["Authorization"] = `Bearer ${API_TOKEN}`;

  const cookie = req.headers.get("cookie");
  if (cookie) headers["Cookie"] = cookie;

  const contentType = req.headers.get("content-type");
  if (contentType) headers["Content-Type"] = contentType;

  const origin = req.headers.get("origin");
  if (origin) headers["Origin"] = origin;

  // First x-forwarded-for hop = browser IP (Vercel sets it); the backend
  // trusts this header only on token-authenticated requests.
  const forwarded = req.headers.get("x-forwarded-for");
  const clientIp = forwarded?.split(",")[0]?.trim();
  if (clientIp) headers["X-Client-IP"] = clientIp;

  const res = await fetch(`${API_BASE}${backendPath}`, {
    method: init?.method ?? req.method,
    headers,
    body: init?.body === undefined ? null : init.body,
    cache: "no-store",
    redirect: "manual", // relay backend 302s (OAuth) instead of following them
  });

  const responseHeaders = new Headers();
  const resContentType = res.headers.get("content-type");
  if (resContentType) responseHeaders.set("Content-Type", resContentType);
  const location = res.headers.get("location");
  if (location) responseHeaders.set("Location", location);
  // getSetCookie: headers.get would fold multiple cookies into one bad value
  for (const value of res.headers.getSetCookie()) {
    responseHeaders.append("Set-Cookie", value);
  }

  return new NextResponse(res.status === 204 ? null : await res.text(), {
    status: res.status,
    headers: responseHeaders,
  });
}
