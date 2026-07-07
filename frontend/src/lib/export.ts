import type { Finding, Scan } from "@/lib/api";

export type ExportFormat = "json" | "sarif" | "markdown" | "agent";

export const FORMAT_LABEL: Record<ExportFormat, string> = {
  json: "JSON",
  sarif: "SARIF",
  markdown: "Markdown",
  agent: "Agent task file",
};

function target(scan: Scan): string {
  return scan.git_url ?? scan.local_path ?? "unknown target";
}

function severity(f: Finding): string {
  return f.triaged_severity ?? f.raw_severity;
}

function location(f: Finding): string {
  if (!f.file_path) return "no file location (dependency-level finding)";
  const lines =
    f.start_line != null
      ? f.end_line != null && f.end_line !== f.start_line
        ? `:${f.start_line}-${f.end_line}`
        : `:${f.start_line}`
      : "";
  return `${f.file_path}${lines}`;
}

export function toJson(scan: Scan, findings: Finding[]): string {
  return JSON.stringify(
    {
      generator: "vulnscan-code-auditor",
      exported_at: new Date().toISOString(),
      scan: {
        id: scan.id,
        source_type: scan.source_type,
        git_url: scan.git_url,
        local_path: scan.local_path,
        status: scan.status,
        created_at: scan.created_at,
      },
      findings,
    },
    null,
    2
  );
}

// GitHub code scanning renders severity from this rule property.
const SECURITY_SEVERITY: Record<string, string> = {
  critical: "9.5",
  high: "8.0",
  medium: "5.0",
  low: "3.0",
  info: "1.0",
};

function sarifLevel(sev: string): string {
  if (sev === "critical" || sev === "high") return "error";
  if (sev === "medium") return "warning";
  return "note";
}

export function toSarif(scan: Scan, findings: Finding[]): string {
  const byScanner = new Map<string, Finding[]>();
  for (const f of findings) {
    const list = byScanner.get(f.scanner) ?? [];
    list.push(f);
    byScanner.set(f.scanner, list);
  }

  const srcRoot = scan.git_url ?? (scan.local_path ? `file://${scan.local_path}` : undefined);

  const runs = [...byScanner.entries()].map(([scanner, fs]) => {
    const ruleIndex = new Map<string, number>();
    const rules: object[] = [];
    for (const f of fs) {
      if (ruleIndex.has(f.rule_id)) continue;
      ruleIndex.set(f.rule_id, rules.length);
      rules.push({
        id: f.rule_id,
        name: f.rule_id,
        shortDescription: { text: f.title },
        ...(f.references[0] ? { helpUri: f.references[0] } : {}),
        properties: {
          tags: [f.category, ...f.cve_ids],
          "security-severity": SECURITY_SEVERITY[severity(f)] ?? "1.0",
        },
      });
    }

    return {
      tool: { driver: { name: scanner, rules } },
      ...(srcRoot ? { originalUriBaseIds: { SRCROOT: { uri: srcRoot } } } : {}),
      results: fs.map((f) => ({
        ruleId: f.rule_id,
        ruleIndex: ruleIndex.get(f.rule_id),
        level: sarifLevel(severity(f)),
        message: {
          text: f.explanation ? `${f.title}\n\n${f.explanation}` : f.title,
        },
        ...(f.file_path
          ? {
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: f.file_path, uriBaseId: "SRCROOT" },
                    ...(f.start_line != null
                      ? {
                          region: {
                            startLine: f.start_line,
                            ...(f.end_line != null ? { endLine: f.end_line } : {}),
                            ...(f.code_snippet ? { snippet: { text: f.code_snippet } } : {}),
                          },
                        }
                      : {}),
                  },
                },
              ],
            }
          : {}),
        partialFingerprints: { vulnscanFindingId: f.id },
        properties: {
          category: f.category,
          raw_severity: f.raw_severity,
          triaged_severity: f.triaged_severity,
          likely_false_positive: f.likely_false_positive,
          cve_ids: f.cve_ids,
          suggested_patch: f.suggested_patch,
          patch_rationale: f.patch_rationale,
        },
      })),
    };
  });

  return JSON.stringify(
    {
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      version: "2.1.0",
      runs,
    },
    null,
    2
  );
}

function severitySummary(findings: Finding[]): string {
  const order = ["critical", "high", "medium", "low", "info"];
  const counts = new Map<string, number>();
  for (const f of findings) {
    const s = severity(f);
    counts.set(s, (counts.get(s) ?? 0) + 1);
  }
  const rows = order
    .filter((s) => counts.has(s))
    .map((s) => `| ${s} | ${counts.get(s)} |`);
  return ["| Severity | Count |", "|---|---|", ...rows].join("\n");
}

function findingSection(f: Finding, heading: string): string {
  const parts = [
    heading,
    "",
    `- **Location:** \`${location(f)}\``,
    `- **Scanner / rule:** ${f.scanner} / ${f.rule_id}`,
  ];
  if (f.cve_ids.length > 0) parts.push(`- **CVEs:** ${f.cve_ids.join(", ")}`);
  if (f.raw_severity !== severity(f))
    parts.push(`- **Severity:** scanner said ${f.raw_severity}, triaged to ${severity(f)}`);
  if (f.explanation) parts.push("", f.explanation);
  if (f.code_snippet && !f.suggested_patch)
    parts.push("", "```", f.code_snippet, "```");
  if (f.suggested_patch) parts.push("", "```diff", f.suggested_patch, "```");
  if (f.patch_rationale) parts.push("", `*Rationale:* ${f.patch_rationale}`);
  if (f.references.length > 0)
    parts.push("", "References:", ...f.references.slice(0, 5).map((r) => `- ${r}`));
  return parts.join("\n");
}

export function toMarkdown(scan: Scan, findings: Finding[]): string {
  const sections = findings.map((f) =>
    findingSection(f, `## [${severity(f).toUpperCase()}] ${f.title}`)
  );
  return [
    `# Security scan report — ${target(scan)}`,
    `Scan \`${scan.id}\`${scan.created_at ? `, ${scan.created_at}` : ""}. ${findings.length} finding${findings.length === 1 ? "" : "s"}.`,
    severitySummary(findings),
    ...sections,
  ].join("\n\n") + "\n";
}

export function toAgentTaskFile(scan: Scan, findings: Finding[]): string {
  const tasks = findings.map((f, i) => {
    const body = findingSection(
      f,
      `## Task ${i + 1} — [${severity(f).toUpperCase()}] ${f.title}`
    );
    return f.suggested_patch
      ? body
      : `${body}\n\n**Fix:** no automated patch — remediate based on the explanation and references above.`;
  });

  return [
    `# Security fix tasks for ${target(scan)}`,
    `You are a coding agent working in a checkout of the repository above (scan \`${scan.id}\`${scan.created_at ? `, scanned ${scan.created_at}` : ""}). Apply each fix below, then verify it.`,
    "## Instructions",
    [
      "1. For each task, open the file at the given location and confirm the vulnerable code matches the snippet or diff context. If the code has drifted since the scan, adapt the fix — do not apply a diff blindly.",
      "2. Where a unified diff is provided it was verified to apply cleanly at scan time; try `git apply` first, fall back to editing manually.",
      "3. After each fix, build the project and run its tests. Do not batch-commit unverified changes.",
      "4. If you determine a task is a false positive, skip it and explain why.",
    ].join("\n"),
    ...tasks,
  ].join("\n\n") + "\n";
}

const MIME: Record<ExportFormat, string> = {
  json: "application/json",
  sarif: "application/sarif+json",
  markdown: "text/markdown",
  agent: "text/markdown",
};

const EXT: Record<ExportFormat, string> = {
  json: "json",
  sarif: "sarif",
  markdown: "md",
  agent: "md",
};

export function exportText(format: ExportFormat, scan: Scan, findings: Finding[]): string {
  switch (format) {
    case "json":
      return toJson(scan, findings);
    case "sarif":
      return toSarif(scan, findings);
    case "markdown":
      return toMarkdown(scan, findings);
    case "agent":
      return toAgentTaskFile(scan, findings);
  }
}

export function exportFilename(
  format: ExportFormat,
  scan: Scan,
  finding?: Finding
): string {
  const suffix = finding ? `-${finding.id.slice(0, 8)}` : "";
  const agent = format === "agent" ? "-agent-tasks" : "";
  return `vulnscan-${scan.id}${suffix}${agent}.${EXT[format]}`;
}

export function download(filename: string, format: ExportFormat, text: string): void {
  const blob = new Blob([text], { type: MIME[format] });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
