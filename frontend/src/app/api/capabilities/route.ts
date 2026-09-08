import { NextRequest } from "next/server";
import { proxyRequest } from "@/lib/backend";

export async function GET(req: NextRequest) {
  return proxyRequest(req, "/capabilities");
}
