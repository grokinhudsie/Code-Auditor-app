"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  createScan,
  deleteProject,
  listProjects,
  listScans,
  upsertProject,
  type Project,
  type ScanSummary,
} from "@/lib/api";

type Group = {
  target: string;
  sourceType: string;
  scans: ScanSummary[];
  project: Project | null;
};

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

function GroupCard({
  group,
  onChanged,
  onError,
}: {
  group: Group;
  onChanged: () => void;
  onError: (message: string) => void;
}) {
  const [editing, setEditing] = useState(false);
  const [name, setName] = useState(group.project?.name ?? "");
  const [busy, setBusy] = useState(false);
  const router = useRouter();

  async function run(action: () => Promise<void>) {
    setBusy(true);
    try {
      await action();
    } catch (err) {
      onError(err instanceof Error ? err.message : "Something went wrong");
    } finally {
      setBusy(false);
    }
  }

  async function saveLabel(e: React.FormEvent) {
    e.preventDefault();
    await run(async () => {
      await upsertProject(group.target, name.trim());
      setEditing(false);
      onChanged();
    });
  }

  async function removeLabel() {
    if (!group.project) return;
    await run(async () => {
      await deleteProject(group.project!.id);
      setName("");
      setEditing(false);
      onChanged();
    });
  }

  async function rescan() {
    await run(async () => {
      const { scan_id } = await createScan(
        group.sourceType === "git"
          ? { git_url: group.target }
          : { local_path: group.target }
      );
      router.push(`/scans/${scan_id}`);
    });
  }

  return (
    <section className="rounded-lg border border-neutral-200 dark:border-neutral-800">
      <div className="flex flex-wrap items-center gap-2 border-b border-neutral-200 px-4 py-3 dark:border-neutral-800">
        <div className="min-w-0 flex-1">
          {group.project && !editing ? (
            <>
              <h2 className="text-sm font-semibold">{group.project.name}</h2>
              <p className="break-all text-xs text-neutral-500">{group.target}</p>
            </>
          ) : (
            <h2 className="break-all text-sm font-semibold">{group.target}</h2>
          )}
        </div>
        {editing ? (
          <form onSubmit={saveLabel} className="flex items-center gap-2">
            <input
              autoFocus
              required
              maxLength={100}
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Project name"
              className="rounded-md border border-neutral-300 px-2 py-1 text-xs outline-none focus:border-neutral-900 dark:border-neutral-700 dark:bg-neutral-900 dark:focus:border-neutral-100"
            />
            <button
              type="submit"
              disabled={busy}
              className="rounded border border-neutral-300 px-2 py-1 text-xs font-medium text-neutral-600 hover:bg-neutral-100 disabled:opacity-50 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
            >
              Save
            </button>
            <button
              type="button"
              onClick={() => setEditing(false)}
              className="text-xs text-neutral-500 hover:underline"
            >
              Cancel
            </button>
          </form>
        ) : (
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setEditing(true)}
              className="text-xs text-neutral-500 hover:underline"
            >
              {group.project ? "Rename" : "Name this project"}
            </button>
            {group.project && (
              <button
                type="button"
                onClick={removeLabel}
                disabled={busy}
                className="text-xs text-neutral-500 hover:underline disabled:opacity-50"
              >
                Remove label
              </button>
            )}
            <button
              type="button"
              onClick={rescan}
              disabled={busy}
              className="rounded border border-neutral-300 px-2 py-1 text-xs font-medium text-neutral-600 hover:bg-neutral-100 disabled:opacity-50 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
            >
              {busy ? "…" : "Rescan"}
            </button>
          </div>
        )}
      </div>
      <ul>
        {group.scans.map((s) => (
          <li
            key={s.id}
            className="border-b border-neutral-100 last:border-b-0 dark:border-neutral-900"
          >
            <Link
              href={`/scans/${s.id}`}
              className="flex items-center gap-3 px-4 py-2 text-sm hover:bg-neutral-50 dark:hover:bg-neutral-900"
            >
              <span className="w-36 shrink-0 text-xs text-neutral-500">
                {s.created_at ? new Date(s.created_at).toLocaleString() : "—"}
              </span>
              <StatusBadge status={s.status} />
              <span className="text-xs text-neutral-400">
                {s.finding_count} finding{s.finding_count === 1 ? "" : "s"}
              </span>
            </Link>
          </li>
        ))}
      </ul>
    </section>
  );
}

export default function HistoryPage() {
  const [groups, setGroups] = useState<Group[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [refresh, setRefresh] = useState(0);
  const router = useRouter();

  useEffect(() => {
    let active = true;
    (async () => {
      try {
        const [scans, projects] = await Promise.all([listScans(), listProjects()]);
        if (!active) return;
        const byTarget = new Map<string, Group>();
        for (const s of scans) {
          const group = byTarget.get(s.target) ?? {
            target: s.target,
            sourceType: s.source_type,
            scans: [],
            project: projects.find((p) => p.target === s.target) ?? null,
          };
          group.scans.push(s);
          byTarget.set(s.target, group);
        }
        setGroups([...byTarget.values()]);
        setError(null);
      } catch (err) {
        if (!active) return;
        if (err instanceof Error && err.cause === 401) {
          router.push("/login?next=/history");
          return;
        }
        setError(err instanceof Error ? err.message : "Failed to load history");
      }
    })();
    return () => {
      active = false;
    };
  }, [refresh, router]);

  return (
    <main className="mx-auto w-full max-w-3xl px-6 py-10">
      <h1 className="text-xl font-semibold">Scan history</h1>
      <p className="mt-1 text-sm text-neutral-500">
        Your scans, grouped by repository. Name a group to label it as a project.
      </p>

      {error && <p className="mt-4 text-sm text-red-600">{error}</p>}
      {!error && groups === null && (
        <p className="mt-4 text-neutral-500">Loading…</p>
      )}
      {groups !== null && groups.length === 0 && (
        <p className="mt-4 text-neutral-500">
          No scans yet.{" "}
          <Link href="/" className="underline">
            Run one
          </Link>{" "}
          while signed in and it will show up here.
        </p>
      )}

      <div className="mt-6 space-y-6">
        {groups?.map((g) => (
          <GroupCard
            key={g.target}
            group={g}
            onChanged={() => setRefresh((n) => n + 1)}
            onError={setError}
          />
        ))}
      </div>
    </main>
  );
}
