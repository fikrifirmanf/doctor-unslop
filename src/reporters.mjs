import { SEVERITIES } from "./report.mjs";

const SARIF_LEVEL = { critical: "error", high: "error", medium: "warning", low: "note", info: "note" };
const pct = (x) => (x === null || x === undefined ? "n/a" : `${(x * 100).toFixed(1)}%`);

export function json(report) {
  return JSON.stringify(report, null, 2);
}

/** SARIF 2.1.0 for GitHub Code Scanning. Findings without a file location use the workspace root. */
export function sarif(report) {
  const rules = [...new Map(report.findings.map((f) => [f.rule_id, f])).values()].map((f) => ({
    id: f.rule_id,
    shortDescription: { text: f.rule_id },
    help: { text: f.fix_hint },
    defaultConfiguration: { level: SARIF_LEVEL[f.severity] },
  }));
  return JSON.stringify(
    {
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      version: "2.1.0",
      runs: [
        {
          tool: { driver: { name: "doctor-unslop", informationUri: "https://github.com/fikrifirmanf/doctor-unslop", rules } },
          results: report.findings.map((f) => ({
            ruleId: f.rule_id,
            level: SARIF_LEVEL[f.severity],
            message: { text: `${f.target}: ${f.message}. ${f.fix_hint}` },
            partialFingerprints: { doctorUnslopId: f.id },
            locations: [{ physicalLocation: { artifactLocation: { uri: f.location?.file ?? "." }, ...(f.location?.line ? { region: { startLine: f.location.line } } : {}) } }],
          })),
        },
      ],
    },
    null,
    2,
  );
}

export function pretty(report) {
  const out = [];
  const bench = report.benchmarks ?? [];
  const loops = report.loops ?? null;
  for (const s of report.servers ?? []) {
    out.push(`stdio ${s.name.padEnd(18)} ${s.ok ? `ok  ${String(s.cold_start_ms + s.list_ms).padStart(5)}ms  ${s.tools} tools` : `FAILED  ${s.error}`}`);
  }
  if (report.tokens) out.push(`tokens: ~${report.tokens.total} estimated across the fleet (budget ${report.tokens.budget})`);
  for (const r of bench) {
    const m = r.metrics;
    out.push(`bench ${r.server}: precision ${pct(m.precision)}  recall ${pct(m.recall)}  FPR ${pct(m.false_positive_rate)}  (tp ${m.tp} fp ${m.fp} tn ${m.tn} fn ${m.fn})`);
    for (const c of r.cases.filter((c) => c.result === "false_positive" || c.result === "missed")) {
      out.push(`  ${c.result === "missed" ? "missed" : "false+"} ${c.file}  ${c.result === "missed" ? `missing ${c.missed.join(", ")}` : `fired ${c.fired.join(", ")}`}`);
    }
  }
  if (loops?.metrics?.records !== undefined) {
    out.push(`loops: ${loops.metrics.records} records, ${loops.metrics.sequences} multi-audit sequences, avg retries ${loops.metrics.avg_retries_to_pass ?? "n/a"}, convergence ${pct(loops.metrics.convergence_rate)}${loops.malformed_lines ? `, ${loops.malformed_lines} malformed lines skipped` : ""}`);
  }
  if (out.length) out.push("");
  for (const f of report.findings) {
    out.push(`${f.severity.toUpperCase().padEnd(8)} ${f.rule_id.padEnd(9)} ${f.target}  ${f.message}`);
    out.push(`         ${" ".repeat(9)} evidence: ${f.evidence}`);
    out.push(`         ${" ".repeat(9)} fix: ${f.fix_hint}`);
  }
  for (const e of report.errors ?? []) out.push(`ERROR    ${e.target}: ${e.message}`);
  const c = report.summary.counts;
  out.push("", `${report.summary.status.toUpperCase()}  health ${report.summary.health_score}/100  ${SEVERITIES.map((s) => `${s} ${c[s]}`).join("  ")}`);
  return out.join("\n");
}
