// Calls go to same-origin Next.js route handlers under /api, which proxy to the
// backend server-side and inject the auth token. The browser never sees the
// backend URL or token.
export type Finding = {
  id: string;
  scanner: string;
  category: string;
  rule_id: string;
  title: string;
  raw_severity: string;
  file_path: string | null;
  start_line: number | null;
  end_line: number | null;
  code_snippet: string | null;
  cve_ids: string[];
  references: string[];
  triaged_severity: string | null;
  likely_false_positive: boolean | null;
  explanation: string | null;
  suggested_patch: string | null;
  patch_rationale: string | null;
};

export type Scan = {
  id: string;
  git_url: string;
  status: string;
  error: string | null;
  file_tree: string[] | null;
  created_at: string | null;
  updated_at: string | null;
  findings: Finding[];
};

export async function createScan(gitUrl: string): Promise<{ scan_id: string }> {
  const res = await fetch(`/api/scans`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ git_url: gitUrl }),
  });
  if (!res.ok) {
    const detail = await res.json().catch(() => ({}));
    throw new Error(detail.detail ?? `Request failed (${res.status})`);
  }
  return res.json();
}

export async function getScan(id: string): Promise<Scan> {
  const res = await fetch(`/api/scans/${id}`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Scan not found (${res.status})`);
  return res.json();
}
