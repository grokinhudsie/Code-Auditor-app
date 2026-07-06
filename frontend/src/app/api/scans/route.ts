import { NextRequest, NextResponse } from "next/server";

// Server-side only — these env vars are NOT exposed to the browser.
const API_BASE = process.env.API_BASE ?? "http://localhost:8000";
const API_TOKEN = process.env.API_TOKEN ?? "";

function authHeaders(): Record<string, string> {
  return API_TOKEN ? { Authorization: `Bearer ${API_TOKEN}` } : {};
}

export async function POST(req: NextRequest) {
  const body = await req.text();
  const res = await fetch(`${API_BASE}/scans`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...authHeaders() },
    body,
  });
  return new NextResponse(await res.text(), {
    status: res.status,
    headers: { "Content-Type": "application/json" },
  });
}
