import fs from "node:fs/promises";
import { finding } from "./report.mjs";

export const MIN_SEQUENCES = 5;
export const MIN_OSCILLATIONS = 2;

/** Parses JSONL telemetry. Malformed lines are counted, not fatal. */
export function parseTelemetry(text) {
  const records = [];
  let malformed = 0;
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      const r = JSON.parse(line);
      if (typeof r.session_id === "string" && typeof r.file_hash === "string" && Array.isArray(r.triggered_rules) && Number.isFinite(Date.parse(r.ts))) records.push(r);
      else malformed++;
    } catch {
      malformed++;
    }
  }
  return { records, malformed };
}

/** Groups records into per-(server, session, file) sequences ordered by iteration, then time. */
export function sequences(records) {
  const groups = new Map();
  for (const r of records) {
    const key = `${r.server ?? "?"}\u0000${r.session_id}\u0000${r.file_hash}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(r);
  }
  return [...groups.values()].map((seq) => seq.sort((a, b) => (a.iteration ?? 0) - (b.iteration ?? 0) || Date.parse(a.ts) - Date.parse(b.ts)));
}

/**
 * Per-rule retry stats. Only sequences with 2+ audits count: after a single audit we cannot tell
 * whether the agent fixed the finding or stopped checking.
 *   retries(r)     = audits in the sequence where r fired
 *   converged(r)   = r is absent from the sequence's last audit
 */
export function ruleStats(seqs) {
  const stats = {};
  for (const seq of seqs) {
    if (seq.length < 2) continue;
    const server = seq[0].server ?? "?";
    const last = new Set(seq.at(-1).triggered_rules);
    const fired = new Map();
    for (const r of seq) for (const id of new Set(r.triggered_rules)) fired.set(id, (fired.get(id) ?? 0) + 1);
    for (const [id, k] of fired) {
      const s = (stats[`${server}\u0000${id}`] ??= { server, rule_id: id, sequences: 0, retries: 0, converged: 0 });
      s.sequences++;
      s.retries += k;
      if (!last.has(id)) s.converged++;
    }
  }
  return Object.values(stats).map((s) => ({ ...s, avg_retries: Number((s.retries / s.sequences).toFixed(2)), convergence_rate: Number((s.converged / s.sequences).toFixed(4)) }));
}

/** LOOP-002 pattern: A fires, the next audit clears A but fires B (new), the one after fires A again. */
export function oscillations(seqs) {
  const pairs = new Map();
  for (const seq of seqs) {
    const seen = new Set();
    for (let i = 0; i + 2 < seq.length; i++) {
      const [x, y, z] = [new Set(seq[i].triggered_rules), new Set(seq[i + 1].triggered_rules), new Set(seq[i + 2].triggered_rules)];
      for (const a of x) {
        if (y.has(a) || !z.has(a)) continue;
        for (const b of y) {
          if (x.has(b) || b === a) continue;
          const key = `${seq[0].server ?? "?"}\u0000${a}\u0000${b}`;
          if (seen.has(key)) continue;
          seen.add(key);
          pairs.set(key, (pairs.get(key) ?? 0) + 1);
        }
      }
    }
  }
  return [...pairs].map(([key, count]) => {
    const [server, a, b] = key.split("\u0000");
    return { server, rule_a: a, rule_b: b, sequences: count };
  });
}

export function analyzeLoops(records, { windowDays = 14, maxRetries = 3, minConvergence = 0.7, now = new Date() } = {}) {
  const since = now.getTime() - windowDays * 86_400_000;
  const recent = records.filter((r) => Date.parse(r.ts) >= since);
  const seqs = sequences(recent);
  const stats = ruleStats(seqs);
  const findings = [];
  for (const s of stats) {
    if (s.sequences < MIN_SEQUENCES) continue;
    if (s.avg_retries <= maxRetries && s.convergence_rate >= minConvergence) continue;
    findings.push(finding({
      rule_id: "LOOP-001",
      category: "loops",
      severity: "high",
      target: s.server,
      message: `Rule ${s.rule_id} averages ${s.avg_retries} agent retries with ${(s.convergence_rate * 100).toFixed(0)}% convergence over the last ${windowDays} days`,
      evidence: `avg_retries=${s.avg_retries}, sequences=${s.sequences}, non_converged=${s.sequences - s.converged}`,
      fix_hint: `Make ${s.rule_id}'s fix_hint name the exact replacement, or relax the match if the flagged code is acceptable.`,
    }));
  }
  for (const o of oscillations(seqs)) {
    if (o.sequences < MIN_OSCILLATIONS) continue;
    findings.push(finding({
      rule_id: "LOOP-002",
      category: "loops",
      severity: "medium",
      target: o.server,
      message: `Fixing ${o.rule_a} triggers ${o.rule_b}, and fixing that brings ${o.rule_a} back`,
      evidence: `${o.rule_a} -> ${o.rule_b} -> ${o.rule_a} in ${o.sequences} file sequences`,
      fix_hint: `Change one of ${o.rule_a} or ${o.rule_b} so code that satisfies one cannot trip the other, and say so in both fix_hints.`,
    }));
  }
  const counted = seqs.filter((s) => s.length >= 2);
  const withFindings = counted.filter((s) => s.some((r) => r.triggered_rules.length));
  const metrics = {
    records: recent.length,
    sequences: counted.length,
    avg_retries_to_pass: withFindings.length ? Number((withFindings.reduce((n, s) => n + s.filter((r) => r.passed === false).length, 0) / withFindings.length).toFixed(2)) : null,
    convergence_rate: withFindings.length ? Number((withFindings.filter((s) => s.at(-1).passed !== false).length / withFindings.length).toFixed(4)) : null,
  };
  return { stats, findings, metrics };
}

export async function loops({ telemetryLog, ...opts }) {
  const text = await fs.readFile(telemetryLog, "utf8").catch(() => null);
  if (text === null) {
    return {
      findings: [finding({ rule_id: "LOOP-000", category: "loops", severity: "info", target: telemetryLog, message: "No telemetry log yet, so retry loops were not analyzed", evidence: "file not found", fix_hint: "Run `doctor-unslop init` in the workspace, then use the unslop MCP servers (unslop-core >= 1.1) to collect telemetry." })],
      stats: [],
      metrics: {},
      malformed: 0,
    };
  }
  const { records, malformed } = parseTelemetry(text);
  return { ...analyzeLoops(records, opts), malformed };
}
