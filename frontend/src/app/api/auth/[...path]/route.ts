import { NextRequest, NextResponse } from "next/server";
import { proxyRequest } from "@/lib/backend";

// Only known auth subpaths are proxied — this must not become an open proxy.
const GET_PATHS = new Set(["github/start", "github/callback", "me"]);
const POST_PATHS = new Set([
  "email/code",
  "email/verify",
  "webauthn/register/options",
  "webauthn/register/verify",
  "webauthn/login/options",
  "webauthn/login/verify",
  "logout",
]);

async function handle(
  req: NextRequest,
  params: Promise<{ path: string[] }>,
  allowed: Set<string>,
  body?: string
) {
  const { path } = await params;
  const subpath = path.join("/");
  if (!allowed.has(subpath)) {
    return NextResponse.json({ detail: "not found" }, { status: 404 });
  }
  const search = req.nextUrl.search;
  return proxyRequest(req, `/auth/${subpath}${search}`, { body });
}

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ path: string[] }> }
) {
  return handle(req, params, GET_PATHS);
}

export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ path: string[] }> }
) {
  return handle(req, params, POST_PATHS, await req.text());
}
