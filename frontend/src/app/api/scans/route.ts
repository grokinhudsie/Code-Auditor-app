import { NextRequest } from "next/server";
import { proxyRequest } from "@/lib/backend";

export async function POST(req: NextRequest) {
  return proxyRequest(req, "/scans", { body: await req.text() });
}

export async function GET(req: NextRequest) {
  return proxyRequest(req, "/scans");
}
