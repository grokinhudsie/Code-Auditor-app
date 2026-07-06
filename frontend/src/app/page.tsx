"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { createScan } from "@/lib/api";

export default function Home() {
  const [gitUrl, setGitUrl] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const router = useRouter();

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const { scan_id } = await createScan(gitUrl.trim());
      router.push(`/scans/${scan_id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong");
      setSubmitting(false);
    }
  }

  return (
    <main className="mx-auto flex min-h-screen max-w-2xl flex-col justify-center px-6">
      <h1 className="text-3xl font-bold tracking-tight">VulnScanner</h1>
      <p className="mt-2 text-neutral-500">
        Scan a public git repository with Trivy, Semgrep, and Gitleaks, then let
        an LLM triage the findings and suggest fixes.
      </p>

      <form onSubmit={onSubmit} className="mt-8 flex gap-2">
        <input
          type="url"
          required
          value={gitUrl}
          onChange={(e) => setGitUrl(e.target.value)}
          placeholder="https://github.com/owner/repo.git"
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
        Only https git URLs are accepted. Scanning runs in an isolated sandbox.
        No tool finds every vulnerability — the goal is prioritization and low
        false positives.
      </p>
    </main>
  );
}
