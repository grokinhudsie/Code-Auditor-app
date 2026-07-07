"use client";

import { useEffect, useRef } from "react";
import type { Finding, Scan } from "@/lib/api";
import {
  download,
  exportFilename,
  exportText,
  FORMAT_LABEL,
  type ExportFormat,
} from "@/lib/export";

const FORMATS: ExportFormat[] = ["json", "sarif", "markdown", "agent"];

export function ExportMenu({
  scan,
  findings,
  label,
}: {
  scan: Scan;
  findings: Finding[];
  label: string;
}) {
  const ref = useRef<HTMLDetailsElement>(null);

  useEffect(() => {
    function close(e: MouseEvent) {
      if (ref.current?.open && !ref.current.contains(e.target as Node)) {
        ref.current.open = false;
      }
    }
    document.addEventListener("click", close);
    return () => document.removeEventListener("click", close);
  }, []);

  function onExport(format: ExportFormat) {
    const single = findings.length === 1 ? findings[0] : undefined;
    download(
      exportFilename(format, scan, single),
      format,
      exportText(format, scan, findings)
    );
    if (ref.current) ref.current.open = false;
  }

  return (
    <details ref={ref} className="relative inline-block">
      <summary className="cursor-pointer list-none rounded border border-neutral-300 px-2 py-1 text-xs font-medium text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800">
        {label} ▾
      </summary>
      <div className="absolute right-0 z-10 mt-1 w-40 rounded-md border border-neutral-200 bg-white py-1 shadow-lg dark:border-neutral-700 dark:bg-neutral-900">
        {FORMATS.map((format) => (
          <button
            key={format}
            type="button"
            onClick={() => onExport(format)}
            className="block w-full px-3 py-1.5 text-left text-xs text-neutral-700 hover:bg-neutral-100 dark:text-neutral-200 dark:hover:bg-neutral-800"
          >
            {FORMAT_LABEL[format]}
          </button>
        ))}
      </div>
    </details>
  );
}
