import { NextRequest } from "next/server";
import { proxyRequest } from "@/lib/backend";

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  return proxyRequest(req, `/scans/${encodeURIComponent(id)}`);
}
