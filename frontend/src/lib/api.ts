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
  source_type: string;
  git_url: string | null;
  local_path: string | null;
  status: string;
  error: string | null;
  file_tree: string[] | null;
  created_at: string | null;
  updated_at: string | null;
  findings: Finding[];
};

export type ScanSource = { git_url: string } | { local_path: string };

export type ScanSummary = Omit<Scan, "findings"> & {
  target: string;
  finding_count: number;
};

export type Project = {
  id: string;
  name: string;
  target: string;
};

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, { cache: "no-store", ...init });
  if (!res.ok) {
    const detail = await res.json().catch(() => ({}));
    throw new Error(detail.detail ?? `Request failed (${res.status})`, {
      cause: res.status,
    });
  }
  return res.status === 204 ? (undefined as T) : res.json();
}

export async function createScan(source: ScanSource): Promise<{ scan_id: string }> {
  return request(`/api/scans`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(source),
  });
}

export async function getScan(id: string): Promise<Scan> {
  const res = await fetch(`/api/scans/${id}`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Scan not found (${res.status})`);
  return res.json();
}

export async function listScans(): Promise<ScanSummary[]> {
  const data = await request<{ scans: ScanSummary[] }>(`/api/scans`);
  return data.scans;
}

export async function listProjects(): Promise<Project[]> {
  const data = await request<{ projects: Project[] }>(`/api/projects`);
  return data.projects;
}

export async function upsertProject(target: string, name: string): Promise<Project> {
  return request(`/api/projects`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target, name }),
  });
}

export async function deleteProject(id: string): Promise<void> {
  return request(`/api/projects/${encodeURIComponent(id)}`, { method: "DELETE" });
}
