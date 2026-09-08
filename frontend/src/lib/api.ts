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
  upload_name: string | null;
  status: string;
  error: string | null;
  file_tree: string[] | null;
  created_at: string | null;
  updated_at: string | null;
  findings: Finding[];
};

export type ScanSource =
  | { git_url: string }
  | { local_path: string }
  | { upload_name: string; upload_size: number };

export type ScanSummary = Omit<Scan, "findings"> & {
  target: string;
  finding_count: number;
};

export type Capabilities = {
  local_scans: boolean;
  zip_uploads: boolean;
  max_upload_mb: number;
};

// Only present when the scan source was a zip: the ticket for the one direct
// browser -> backend request in the app.
export type CreatedScan = {
  scan_id: string;
  status: string;
  upload_url?: string;
  upload_token?: string;
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

// Local scans need ALLOW_LOCAL_SCANS on the backend; treat any failure as
// "off" so the UI never offers a source the backend would reject with 403.
export async function getCapabilities(): Promise<Capabilities> {
  try {
    return await request<Capabilities>(`/api/capabilities`);
  } catch {
    return { local_scans: false, zip_uploads: false, max_upload_mb: 0 };
  }
}

export async function createScan(source: ScanSource): Promise<CreatedScan> {
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

/**
 * Send the archive straight to the backend, skipping the Next.js proxy.
 *
 * Vercel caps serverless request bodies at 4.5MB, which is too small for real
 * codebases, so this is the one request that talks to the backend directly.
 * The one-time ticket from createScan authenticates it; no cookie or API token
 * is involved, so withCredentials stays off to match the backend's CORS config.
 *
 * XHR rather than fetch: fetch still cannot report upload progress.
 */
export function uploadZip(
  url: string,
  token: string,
  blob: Blob,
  onProgress?: (fraction: number) => void
): Promise<void> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", url);
    xhr.setRequestHeader("Content-Type", "application/zip");
    xhr.setRequestHeader("X-Upload-Token", token);
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) onProgress?.(e.loaded / e.total);
    };
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) return resolve();
      let detail = `Upload failed (${xhr.status})`;
      try {
        detail = JSON.parse(xhr.responseText).detail ?? detail;
      } catch {
        // non-JSON error body (e.g. a proxy's own 413 page)
      }
      reject(new Error(detail, { cause: xhr.status }));
    };
    xhr.onerror = () =>
      reject(new Error("Could not reach the scan server. Check that it is running and reachable over https."));
    xhr.onabort = () => reject(new Error("Upload cancelled"));
    xhr.send(blob);
  });
}
