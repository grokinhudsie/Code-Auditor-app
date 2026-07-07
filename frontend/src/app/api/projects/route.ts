import { NextRequest } from "next/server";
import { proxyRequest } from "@/lib/backend";

export async function GET(req: NextRequest) {
  return proxyRequest(req, "/projects");
}

export async function PUT(req: NextRequest) {
  return proxyRequest(req, "/projects", { body: await req.text() });
}
