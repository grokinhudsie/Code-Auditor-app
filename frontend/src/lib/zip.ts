// Client-side zipping for the "scan a folder" flow.
//
// The browser hands us a flat File[] (each carrying webkitRelativePath) and we
// build the archive here rather than asking the user to zip it themselves. The
// exclusions matter more than convenience: node_modules alone routinely dwarfs
// the upload cap, and scanning it produces findings about code the user doesn't
// own.
import { AsyncZipDeflate, Zip } from "fflate";

export const EXCLUDED_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  ".next",
  "out",
  "venv",
  ".venv",
  "__pycache__",
  ".turbo",
  "target",
  "vendor",
  ".cache",
  "coverage",
  // Local databases and tool state: not source, often large, and their binary
  // files are exactly what a code scanner has nothing useful to say about.
  ".pglite",
  ".wrangler",
  ".svelte-kit",
  ".astro",
  ".nuxt",
  ".output",
  ".parcel-cache",
  ".pytest_cache",
  ".mypy_cache",
  ".ruff_cache",
  ".gradle",
  ".terraform",
  "Pods",
]);

export type ZipResult = {
  blob: Blob;
  name: string;
  fileCount: number;
  skipped: number;
};

function relativePath(file: File): string {
  // webkitRelativePath is "<picked folder>/a/b.ts"; strip the folder itself so
  // the archive contains the tree, not a wrapper directory.
  const full = file.webkitRelativePath || file.name;
  const slash = full.indexOf("/");
  return slash === -1 ? full : full.slice(slash + 1);
}

function isExcluded(file: File): boolean {
  const full = file.webkitRelativePath || file.name;
  return full.split("/").some((segment) => EXCLUDED_DIRS.has(segment));
}

/**
 * Zip a picked folder.
 *
 * Uses fflate's streaming Zip rather than the one-shot zip() helper: one-shot
 * needs every file resident in memory at once, which a large folder will not
 * survive. This keeps one file in flight and deflates off the main thread.
 *
 * `maxBytes` guards the *raw* input so we fail fast on an obviously hopeless
 * folder instead of spending a minute compressing it.
 */
export function zipFolder(
  files: File[],
  maxBytes: number,
  onProgress?: (fraction: number) => void
): Promise<ZipResult> {
  const kept = files.filter((f) => !isExcluded(f));
  const skipped = files.length - kept.length;

  if (kept.length === 0) {
    return Promise.reject(
      new Error("That folder has no scannable files (everything was excluded).")
    );
  }

  const rawBytes = kept.reduce((sum, f) => sum + f.size, 0);
  if (rawBytes > maxBytes) {
    const mb = Math.ceil(rawBytes / (1024 * 1024));
    return Promise.reject(
      new Error(
        `That folder is ${mb}MB before compression, which is too large. Scan a subfolder, or zip it yourself excluding build output.`
      )
    );
  }

  const first = files[0];
  const rootName = (first.webkitRelativePath || "").split("/")[0] || "folder";

  return new Promise<ZipResult>((resolve, reject) => {
    const chunks: Uint8Array[] = [];
    let done = 0;
    let settled = false;

    const fail = (err: Error) => {
      if (settled) return;
      settled = true;
      reject(err);
    };

    const zip = new Zip((err, chunk, final) => {
      if (err) return fail(err);
      chunks.push(chunk);
      if (final && !settled) {
        settled = true;
        resolve({
          blob: new Blob(chunks as BlobPart[], { type: "application/zip" }),
          name: `${rootName}.zip`,
          fileCount: kept.length,
          skipped,
        });
      }
    });

    // Sequential: fflate's Zip expects one file streamed at a time, and it also
    // keeps peak memory to a single file.
    const addNext = async (index: number): Promise<void> => {
      if (settled) return;
      if (index >= kept.length) {
        zip.end();
        return;
      }
      const file = kept[index];
      const entry = new AsyncZipDeflate(relativePath(file), { level: 6 });
      zip.add(entry);
      try {
        const buffer = new Uint8Array(await file.arrayBuffer());
        entry.push(buffer, true);
      } catch {
        return fail(new Error(`Could not read ${file.name}`));
      }
      done += 1;
      onProgress?.(done / kept.length);
      return addNext(index + 1);
    };

    void addNext(0).catch((err) =>
      fail(err instanceof Error ? err : new Error("Could not build the archive"))
    );
  });
}
