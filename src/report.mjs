import { createHash } from "node:crypto";

export const SCHEMA_VERSION = "1.0.0";
export const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const RANK = Object.fromEntries(SEVERITIES.map((s, i) => [s, SEVERITIES.length - i]));
const WEIGHT = { critical: 30, high: 15, medium: 7, low: 2, info: 0 };

/** Maps the servers' legacy two-level severity onto the five-level scale. */
export function normalizeSeverity(s) {
  if (s === "ERROR") return "high";
  if (s === "WARN") return "medium";
  return SEVERITIES.includes(s) ? s : null;
}

export const atLeast = (sev, threshold) => (RANK[sev] ?? 0) >= (RANK[threshold] ?? 0);

/** Deterministic id: same rule + target + evidence gives the same id on every run. */
export function finding({ rule_id, category, severity, target, message, evidence, fix_hint, location = null }) {
  const h = createHash("sha256").update(`${rule_id}|${target}|${evidence}`).digest("hex").slice(0, 4);
  return {
    id: `fnd_${rule_id.toLowerCase().replace(/[^a-z0-9]/g, "")}_${h}`,
    rule_id,
    category,
    severity,
    target,
    message,
    location,
    evidence,
    fix_hint,
    patch_available: false,
  };
}

export function healthScore(counts) {
  const penalty = SEVERITIES.reduce((sum, s) => sum + WEIGHT[s] * (counts[s] ?? 0), 0);
  const score = Math.max(0, 100 - penalty);
  const status = counts.critical > 0 || score < 60 ? "fail" : score >= 85 ? "healthy" : "warn";
  return { score, status };
}

/** Builds the unified report envelope from check results. */
export function buildReport({ workspace, findings, errors = [], servers = [], metrics = {}, now = new Date() }) {
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
  for (const f of findings) counts[f.severity]++;
  const { score, status } = healthScore(counts);
  const sorted = [...findings].sort((a, b) => RANK[b.severity] - RANK[a.severity] || a.rule_id.localeCompare(b.rule_id) || a.target.localeCompare(b.target));
  return {
    schema_version: SCHEMA_VERSION,
    tool: "doctor-unslop",
    generated_at: now.toISOString(),
    workspace,
    summary: { health_score: score, status, servers_scanned: servers.length, quality_metrics: metrics, counts },
    findings: sorted,
    ...(errors.length ? { errors } : {}),
  };
}

/** 2 = critical finding, 3 = runtime/config error, 1 = finding at or above failOn, 0 = healthy. */
export function exitCode(report, failOn = "high") {
  if (report.summary.counts.critical > 0) return 2;
  if (report.errors?.length) return 3;
  return report.findings.some((f) => atLeast(f.severity, failOn)) ? 1 : 0;
}
