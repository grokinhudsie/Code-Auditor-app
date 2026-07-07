"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { createScan } from "@/lib/api";

type Source = "git" | "local";

export default function Home() {
  const [source, setSource] = useState<Source>("git");
  const [target, setTarget] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const router = useRouter();

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
    <main className="mx-auto flex min-h-screen max-w-2xl flex-col justify-center px-6">
      <h1 className="text-3xl font-bold tracking-tight">VulnScan Code Auditor</h1>
      <p className="mt-2 text-neutral-500">
        Scan a public git repository or a locally stored repo with Trivy,
        Semgrep, and Gitleaks, then let an LLM triage the findings and suggest
        fixes.
      </p>

      <div className="mt-8 flex gap-1">
        <button type="button" onClick={() => switchSource("git")} className={tabClass(source === "git")}>
          Git URL
        </button>
        <button type="button" onClick={() => switchSource("local")} className={tabClass(source === "local")}>
          Local path
        </button>
      </div>

      <form onSubmit={onSubmit} className="mt-3 flex gap-2">
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
          : "Absolute path to a repo or folder on the machine running the backend. Requires ALLOW_LOCAL_SCANS on the backend, so this only works with a locally run stack."}
      </p>
    </main>
  );
}
