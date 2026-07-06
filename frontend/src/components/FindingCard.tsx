"use client";

import { useState } from "react";
import type { Finding } from "@/lib/api";

const SEV_COLOR: Record<string, string> = {
  critical: "bg-red-600 text-white",
  high: "bg-orange-500 text-white",
  medium: "bg-amber-400 text-black",
  low: "bg-yellow-200 text-black",
  info: "bg-neutral-200 text-black dark:bg-neutral-700 dark:text-white",
};

function DiffView({ patch }: { patch: string }) {
  return (
    <pre className="overflow-x-auto rounded bg-neutral-950 p-3 text-xs leading-relaxed text-neutral-100">
      {patch.split("\n").map((line, i) => {
        let cls = "text-neutral-300";
        if (line.startsWith("+") && !line.startsWith("+++")) cls = "text-green-400";
        else if (line.startsWith("-") && !line.startsWith("---")) cls = "text-red-400";
        else if (line.startsWith("@@")) cls = "text-cyan-400";
        return (
          <div key={i} className={cls}>
            {line || " "}
          </div>
        );
      })}
    </pre>
  );
}

export function FindingCard({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false);
  const sev = finding.triaged_severity ?? finding.raw_severity;

  return (
    <div className="rounded-lg border border-neutral-200 dark:border-neutral-800">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-start gap-3 px-4 py-3 text-left"
      >
        <span
          className={`mt-0.5 rounded px-2 py-0.5 text-xs font-semibold uppercase ${SEV_COLOR[sev] ?? SEV_COLOR.info}`}
        >
          {sev}
        </span>
        <span className="flex-1">
          <span className="block text-sm font-medium">{finding.title}</span>
          <span className="mt-0.5 block text-xs text-neutral-500">
            {finding.scanner} · {finding.rule_id}
            {finding.file_path && (
              <>
                {" · "}
                {finding.file_path}
                {finding.start_line ? `:${finding.start_line}` : ""}
              </>
            )}
          </span>
        </span>
        <span className="text-neutral-400">{open ? "−" : "+"}</span>
      </button>

      {open && (
        <div className="space-y-3 border-t border-neutral-200 px-4 py-3 dark:border-neutral-800">
          {finding.explanation && (
            <p className="text-sm text-neutral-700 dark:text-neutral-300">
              {finding.explanation}
            </p>
          )}

          {finding.cve_ids.length > 0 && (
            <p className="text-xs text-neutral-500">
              CVEs: {finding.cve_ids.join(", ")}
            </p>
          )}

          {finding.raw_severity !== sev && (
            <p className="text-xs text-neutral-500">
              Scanner rated <b>{finding.raw_severity}</b>; triaged to <b>{sev}</b>.
            </p>
          )}

          {finding.code_snippet && !finding.suggested_patch && (
            <pre className="overflow-x-auto rounded bg-neutral-100 p-3 text-xs dark:bg-neutral-900">
              {finding.code_snippet}
            </pre>
          )}

          {finding.suggested_patch && (
            <div>
              <p className="mb-1 text-xs font-semibold text-neutral-500">
                Suggested fix (verified to apply cleanly — review before using):
              </p>
              <DiffView patch={finding.suggested_patch} />
              {finding.patch_rationale && (
                <p className="mt-2 text-xs text-neutral-500">
                  {finding.patch_rationale}
                </p>
              )}
            </div>
          )}

          {finding.references.length > 0 && (
            <ul className="text-xs">
              {finding.references.slice(0, 5).map((r) => (
                <li key={r}>
                  <a
                    href={r}
                    target="_blank"
                    rel="noreferrer"
                    className="text-blue-600 hover:underline dark:text-blue-400"
                  >
                    {r}
                  </a>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}
