"use client";

import { use, useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { createScan, getScan, type Scan, type Finding } from "@/lib/api";
import { FindingCard } from "@/components/FindingCard";
import { ExportMenu } from "@/components/ExportMenu";

const TERMINAL = new Set(["completed", "failed"]);
const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
const CATEGORY_LABEL: Record<string, string> = {
  sca: "Dependencies (SCA)",
  sast: "Code (SAST)",
  secret: "Secrets",
  iac: "IaC / Config",
};

function severity(f: Finding): string {
  return f.triaged_severity ?? f.raw_severity;
}

function sortFindings(a: Finding, b: Finding): number {
  return (
    SEVERITY_ORDER.indexOf(severity(a)) - SEVERITY_ORDER.indexOf(severity(b))
  );
}

export default function ScanPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = use(params);
  const [scan, setScan] = useState<Scan | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [rescanning, setRescanning] = useState(false);
  const [rescanError, setRescanError] = useState<string | null>(null);
  const router = useRouter();

  useEffect(() => {
    let active = true;
    let timer: ReturnType<typeof setTimeout>;

    async function poll() {
      try {
        const data = await getScan(id);
        if (!active) return;
        setScan(data);
        if (!TERMINAL.has(data.status)) {
          timer = setTimeout(poll, 2500);
        }
      } catch (err) {
        if (active) setError(err instanceof Error ? err.message : "Error");
      }
    }
    poll();
    return () => {
      active = false;
      clearTimeout(timer);
    };
  }, [id]);

  if (error) {
    return <Shell><p className="text-red-600">{error}</p></Shell>;
  }
  if (!scan) {
    return <Shell><p className="text-neutral-500">Loading…</p></Shell>;
  }

  const running = !TERMINAL.has(scan.status);
  const real = scan.findings.filter((f) => !f.likely_false_positive);
  const falsePositives = scan.findings.filter((f) => f.likely_false_positive);

  async function rescan() {
    if (!scan) return;
    setRescanError(null);
    setRescanning(true);
    try {
      const { scan_id } = await createScan(
        scan.git_url ? { git_url: scan.git_url } : { local_path: scan.local_path! }
      );
      router.push(`/scans/${scan_id}`);
    } catch (err) {
      setRescanError(err instanceof Error ? err.message : "Rescan failed");
      setRescanning(false);
    }
  }

  const byCategory = new Map<string, Finding[]>();
  for (const f of real) {
    const list = byCategory.get(f.category) ?? [];
    list.push(f);
    byCategory.set(f.category, list);
  }

  return (
    <Shell>
      <div className="mb-6">
        <Link href="/" className="text-sm text-neutral-500 hover:underline">
          ← New scan
        </Link>
        <h1 className="mt-2 break-all text-xl font-semibold">
          {scan.git_url ?? scan.local_path}
        </h1>
        <div className="mt-2 flex items-center gap-2 text-sm">
          <StatusBadge status={scan.status} />
          {running && (
            <span className="text-neutral-500">
              polling… ({scan.status})
            </span>
          )}
          <span className="text-neutral-400">
            {scan.findings.length} finding
            {scan.findings.length === 1 ? "" : "s"}
          </span>
        </div>
        <div className="mt-3 flex items-center gap-2">
          <button
            type="button"
            onClick={rescan}
            disabled={rescanning || running}
            className="rounded border border-neutral-300 px-2 py-1 text-xs font-medium text-neutral-600 hover:bg-neutral-100 disabled:opacity-50 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
          >
            {rescanning ? "Starting…" : "Rescan"}
          </button>
          {!running && real.length > 0 && (
            <ExportMenu scan={scan} findings={real} label="Download all findings" />
          )}
        </div>
        {rescanError && (
          <p className="mt-2 text-xs text-red-600">{rescanError}</p>
        )}
        {scan.error && (
          <p className="mt-2 rounded bg-amber-50 px-3 py-2 text-xs text-amber-800 dark:bg-amber-950 dark:text-amber-300">
            {scan.error}
          </p>
        )}
      </div>

      {scan.status === "completed" && scan.findings.length === 0 && (
        <p className="text-neutral-500">No findings. 🎉</p>
      )}

      {[...byCategory.entries()].map(([category, findings]) => (
        <section key={category} className="mb-8">
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-neutral-500">
            {CATEGORY_LABEL[category] ?? category} ({findings.length})
          </h2>
          <div className="space-y-3">
            {findings.sort(sortFindings).map((f) => (
              <FindingCard key={f.id} finding={f} scan={scan} />
            ))}
          </div>
        </section>
      ))}

      {falsePositives.length > 0 && (
        <details className="mt-4">
          <summary className="cursor-pointer text-sm text-neutral-500">
            {falsePositives.length} likely false positive
            {falsePositives.length === 1 ? "" : "s"} (collapsed)
          </summary>
          <div className="mt-3 space-y-3 opacity-70">
            {falsePositives.sort(sortFindings).map((f) => (
              <FindingCard key={f.id} finding={f} scan={scan} />
            ))}
          </div>
        </details>
      )}
    </Shell>
  );
}

function Shell({ children }: { children: React.ReactNode }) {
  return (
    <main className="mx-auto max-w-3xl px-6 py-10">{children}</main>
  );
}

function StatusBadge({ status }: { status: string }) {
  const color =
    status === "completed"
      ? "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200"
      : status === "failed"
        ? "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200"
        : "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200";
  return (
    <span className={`rounded px-2 py-0.5 text-xs font-medium ${color}`}>
      {status}
    </span>
  );
}
