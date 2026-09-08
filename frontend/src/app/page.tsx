"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { createScan, getCapabilities } from "@/lib/api";

type Source = "git" | "local";

export default function Home() {
  const [source, setSource] = useState<Source>("git");
  const [target, setTarget] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  // null until the backend answers; the local tab stays hidden until then so a
  // deployment with local scans off never flashes a source it would reject.
  const [localAllowed, setLocalAllowed] = useState<boolean | null>(null);
  const router = useRouter();

  useEffect(() => {
    let active = true;
    getCapabilities().then((caps) => {
      if (active) setLocalAllowed(caps.local_scans);
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

  const tabClass = (active: boolean) =>
    `rounded-md px-3 py-1.5 text-sm font-medium ${
      active
        ? "bg-neutral-900 text-white dark:bg-neutral-100 dark:text-neutral-900"
        : "text-neutral-500 hover:text-neutral-900 dark:hover:text-neutral-100"
    }`;

  return (
    <main className="mx-auto flex w-full max-w-2xl flex-1 flex-col justify-center px-6">
      <h1 className="text-3xl font-bold tracking-tight">VulnScan Code Auditor</h1>
      <p className="mt-2 text-neutral-500">
        Scan a public git repository with Trivy, Semgrep, and Gitleaks, then let
        an LLM triage the findings and suggest fixes.
      </p>

      {localAllowed && (
        <div className="mt-8 flex gap-1">
          <button type="button" onClick={() => switchSource("git")} className={tabClass(source === "git")}>
            Git URL
          </button>
          <button type="button" onClick={() => switchSource("local")} className={tabClass(source === "local")}>
            Local path
          </button>
        </div>
      )}

      <form onSubmit={onSubmit} className={`${localAllowed ? "mt-3" : "mt-8"} flex gap-2`}>
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

      {error && <p className="mt-3 text-sm text-red-600">{error}</p>}

      <p className="mt-6 text-xs text-neutral-400">
        {source === "git"
          ? "Only https git URLs are accepted. Scanning runs in an isolated sandbox. No tool finds every vulnerability — the goal is prioritization and low false positives."
          : "Absolute path to a repo or folder on the machine running the backend. Local scans are enabled on this backend via ALLOW_LOCAL_SCANS."}
      </p>
    </main>
  );
}
