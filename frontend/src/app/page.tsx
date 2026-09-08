"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { createScan, getCapabilities, uploadZip } from "@/lib/api";
import { EXCLUDED_DIRS, zipFolder } from "@/lib/zip";

type Source = "git" | "local" | "zip";
type Phase = { label: string; fraction: number } | null;

export default function Home() {
  const [source, setSource] = useState<Source>("git");
  const [target, setTarget] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [phase, setPhase] = useState<Phase>(null);
  // null until the backend answers; sources stay hidden until then so a
  // deployment never flashes an option it would reject.
  const [localAllowed, setLocalAllowed] = useState<boolean | null>(null);
  const [zipAllowed, setZipAllowed] = useState<boolean | null>(null);
  const [maxUploadMb, setMaxUploadMb] = useState(0);
  const [dragging, setDragging] = useState(false);
  const zipInput = useRef<HTMLInputElement>(null);
  const folderInput = useRef<HTMLInputElement>(null);
  const router = useRouter();

  useEffect(() => {
    let active = true;
    getCapabilities().then((caps) => {
      if (!active) return;
      setLocalAllowed(caps.local_scans);
      setZipAllowed(caps.zip_uploads);
      setMaxUploadMb(caps.max_upload_mb);
    });
    return () => {
      active = false;
    };
  }, []);

  function switchSource(next: Source) {
    setSource(next);
    setTarget("");
    setError(null);
  }

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const value = target.trim();
      const { scan_id } = await createScan(
        source === "git" ? { git_url: value } : { local_path: value }
      );
      router.push(`/scans/${scan_id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong");
      setSubmitting(false);
    }
  }

  /**
   * Zip flow: compress (folders only) -> claim a ticket -> upload straight to
   * the backend -> show the scan. The ticket is claimed after compressing so
   * the declared size is accurate and a failed zip leaves no orphan scan row.
   */
  async function startZipScan(blob: Blob, name: string) {
    setError(null);
    setSubmitting(true);
    try {
      const maxBytes = maxUploadMb * 1024 * 1024;
      if (blob.size > maxBytes) {
        throw new Error(
          `That archive is ${Math.ceil(blob.size / (1024 * 1024))}MB, over the ${maxUploadMb}MB limit.`
        );
      }
      setPhase({ label: "Uploading", fraction: 0 });
      const created = await createScan({ upload_name: name, upload_size: blob.size });
      if (!created.upload_url || !created.upload_token) {
        throw new Error("The server did not issue an upload ticket.");
      }
      await uploadZip(created.upload_url, created.upload_token, blob, (fraction) =>
        setPhase({ label: "Uploading", fraction })
      );
      router.push(`/scans/${created.scan_id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Upload failed");
      setSubmitting(false);
      setPhase(null);
    }
  }

  async function onPickZip(file: File | undefined) {
    if (!file) return;
    if (!file.name.toLowerCase().endsWith(".zip")) {
      setError("That is not a .zip file.");
      return;
    }
    await startZipScan(file, file.name);
  }

  async function onPickFolder(files: FileList | null) {
    if (!files || files.length === 0) return;
    setError(null);
    setSubmitting(true);
    setPhase({ label: "Compressing", fraction: 0 });
    try {
      // Allow a generous raw size: source compresses well, and the packed blob
      // is checked against the real cap in startZipScan.
      const result = await zipFolder(
        Array.from(files),
        maxUploadMb * 1024 * 1024 * 8,
        (fraction) => setPhase({ label: "Compressing", fraction })
      );
      setSubmitting(false);
      await startZipScan(result.blob, result.name);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not build the archive");
      setSubmitting(false);
      setPhase(null);
    }
  }

  const tabClass = (active: boolean) =>
    `rounded-md px-3 py-1.5 text-sm font-medium ${
      active
        ? "bg-neutral-900 text-white dark:bg-neutral-100 dark:text-neutral-900"
        : "text-neutral-500 hover:text-neutral-900 dark:hover:text-neutral-100"
    }`;

  const showTabs = localAllowed || zipAllowed;

  return (
    <main className="mx-auto flex w-full max-w-2xl flex-1 flex-col justify-center px-6">
      <h1 className="text-3xl font-bold tracking-tight">VulnScan Code Auditor</h1>
      <p className="mt-2 text-neutral-500">
        Scan a codebase with Trivy, Semgrep, and Gitleaks, then let an LLM triage
        the findings and suggest fixes.
      </p>

      {showTabs && (
        <div className="mt-8 flex gap-1">
          <button type="button" onClick={() => switchSource("git")} className={tabClass(source === "git")}>
            Git URL
          </button>
          {zipAllowed && (
            <button type="button" onClick={() => switchSource("zip")} className={tabClass(source === "zip")}>
              Upload
            </button>
          )}
          {localAllowed && (
            <button type="button" onClick={() => switchSource("local")} className={tabClass(source === "local")}>
              Local path
            </button>
          )}
        </div>
      )}

      {source === "zip" ? (
        <div
          onDragOver={(e) => {
            e.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={(e) => {
            e.preventDefault();
            setDragging(false);
            if (!submitting) void onPickZip(e.dataTransfer.files[0]);
          }}
          className={`mt-3 rounded-lg border border-dashed px-6 py-10 text-center ${
            dragging
              ? "border-neutral-900 bg-neutral-50 dark:border-neutral-100 dark:bg-neutral-900"
              : "border-neutral-300 dark:border-neutral-700"
          }`}
        >
          {phase ? (
            <div className="mx-auto max-w-xs">
              <p className="text-sm text-neutral-600 dark:text-neutral-300">
                {phase.label}… {Math.round(phase.fraction * 100)}%
              </p>
              <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-neutral-200 dark:bg-neutral-800">
                <div
                  className="h-full bg-neutral-900 transition-[width] dark:bg-neutral-100"
                  style={{ width: `${Math.round(phase.fraction * 100)}%` }}
                />
              </div>
            </div>
          ) : (
            <>
              <p className="text-sm text-neutral-500">
                Drop a .zip here, or
              </p>
              <div className="mt-3 flex justify-center gap-2">
                <button
                  type="button"
                  disabled={submitting}
                  onClick={() => zipInput.current?.click()}
                  className="rounded-md bg-neutral-900 px-4 py-2 text-sm font-medium text-white disabled:opacity-50 dark:bg-neutral-100 dark:text-neutral-900"
                >
                  Choose a .zip
                </button>
                <button
                  type="button"
                  disabled={submitting}
                  onClick={() => folderInput.current?.click()}
                  className="rounded-md border border-neutral-300 px-4 py-2 text-sm font-medium text-neutral-700 disabled:opacity-50 dark:border-neutral-700 dark:text-neutral-200"
                >
                  Choose a folder
                </button>
              </div>
            </>
          )}
          <input
            ref={zipInput}
            type="file"
            accept=".zip,application/zip"
            hidden
            onChange={(e) => {
              void onPickZip(e.target.files?.[0]);
              e.target.value = "";
            }}
          />
          <input
            ref={(el) => {
              folderInput.current = el;
              // Not in the HTML spec, so React has no prop for it.
              el?.setAttribute("webkitdirectory", "");
            }}
            type="file"
            hidden
            onChange={(e) => {
              void onPickFolder(e.target.files);
              e.target.value = "";
            }}
          />
        </div>
      ) : (
        <form onSubmit={onSubmit} className={`${showTabs ? "mt-3" : "mt-8"} flex gap-2`}>
          <input
            type={source === "git" ? "url" : "text"}
            required
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder={
              source === "git"
                ? "https://github.com/owner/repo.git"
                : "/Users/you/projects/my-repo"
            }
            className="flex-1 rounded-md border border-neutral-300 px-3 py-2 text-sm outline-none focus:border-neutral-900 dark:border-neutral-700 dark:bg-neutral-900 dark:focus:border-neutral-100"
          />
          <button
            type="submit"
            disabled={submitting}
            className="rounded-md bg-neutral-900 px-4 py-2 text-sm font-medium text-white disabled:opacity-50 dark:bg-neutral-100 dark:text-neutral-900"
          >
            {submitting ? "Starting…" : "Scan"}
          </button>
        </form>
      )}

      {error && <p className="mt-3 text-sm text-red-600">{error}</p>}

      <p className="mt-6 text-xs text-neutral-400">
        {source === "git" &&
          "Only https git URLs are accepted. Scanning runs in an isolated sandbox. No tool finds every vulnerability — the goal is prioritization and low false positives."}
        {source === "zip" &&
          `Up to ${maxUploadMb}MB, uploaded straight to the scan server. Folders are compressed in your browser, skipping ${[...EXCLUDED_DIRS].slice(0, 4).join(", ")} and other build output. The archive is deleted once the scan finishes.`}
        {source === "local" &&
          "Absolute path to a repo or folder on the machine running the backend. Local scans are enabled on this backend via ALLOW_LOCAL_SCANS."}
      </p>
    </main>
  );
}
