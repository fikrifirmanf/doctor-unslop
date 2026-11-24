import fs from "node:fs/promises";
import path from "node:path";
import { execFile } from "node:child_process";
import { finding, normalizeSeverity } from "./report.mjs";

export const MIN_SAMPLE = 5;
const MAX_HINT = 200;
// Only these variables reach a probed server; secrets in the parent env are not inherited.
const ENV_ALLOW = ["PATH", "HOME", "TMPDIR", "SystemRoot", "LANG"];

const ratio = (a, b) => (b === 0 ? null : Number((a / b).toFixed(4)));
const pct = (x) => (x === null ? "n/a" : `${(x * 100).toFixed(1)}%`);

/** Reads and validates <fixturesDir>/<server>/expected.json for every server directory. */
export async function loadSuites(fixturesDir, only = []) {
  const suites = [];
  const errors = [];
  const entries = await fs.readdir(fixturesDir, { withFileTypes: true }).catch(() => null);
  if (!entries) return { suites, errors: [{ target: fixturesDir, message: "Fixtures directory not found. Run `doctor-unslop init` or pass --fixtures." }] };
  for (const e of entries.filter((d) => d.isDirectory()).sort((a, b) => a.name.localeCompare(b.name))) {
    if (only.length && !only.includes(e.name)) continue;
    const dir = path.join(fixturesDir, e.name);
    const file = path.join(dir, "expected.json");
    let spec;
    try {
      spec = JSON.parse(await fs.readFile(file, "utf8"));
    } catch (err) {
      errors.push({ target: e.name, message: `Cannot read ${file}: ${err.message}` });
      continue;
    }
    const problem = validateSpec(spec);
    if (problem) errors.push({ target: e.name, message: `${file}: ${problem}` });
    else suites.push({ ...spec, server: spec.server ?? e.name, dir });
  }
  for (const name of only) if (!suites.some((s) => s.server === name) && !errors.some((x) => x.target === name)) errors.push({ target: name, message: `No fixture suite for ${name} in ${fixturesDir}.` });
  return { suites, errors };
}

function validateSpec(spec) {
  if (!Array.isArray(spec.command) || !spec.command.length || !spec.command.every((c) => typeof c === "string")) return '"command" must be a non-empty string array, e.g. ["node", "../../../frontend-unslop/src/server.mjs"].';
  if (!Array.isArray(spec.cases) || !spec.cases.length) return '"cases" must be a non-empty array.';
  for (const c of spec.cases) {
    if (typeof c.file !== "string" || !["clean", "slop"].includes(c.kind)) return `case ${JSON.stringify(c)} needs "file" and "kind" ("clean" or "slop").`;
    if (c.kind === "slop" && (!Array.isArray(c.expected_rules) || !c.expected_rules.length)) return `slop case ${c.file} needs at least one expected_rules entry.`;
  }
  return null;
}

/** Runs `<command> audit <files...> --json` with cwd = suite dir. Exit code 1 (audit FAIL) is a normal result. */
export function runAudit(suite, { timeout = 5000 } = {}) {
  const [cmd, ...args] = suite.command.map((c) => (c.startsWith("./") || c.startsWith("../") ? path.resolve(suite.dir, c) : c));
  const env = Object.fromEntries(ENV_ALLOW.filter((k) => process.env[k] !== undefined).map((k) => [k, process.env[k]]));
  return new Promise((resolve) => {
    execFile(cmd, [...args, "audit", ...suite.cases.map((c) => c.file), "--json"], { cwd: suite.dir, env, timeout, maxBuffer: 20 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err && (err.killed || typeof err.code !== "number")) return resolve({ error: err.killed ? `timed out after ${timeout}ms` : err.message });
      try {
        resolve({ output: JSON.parse(stdout) });
      } catch {
        resolve({ error: `audit did not print JSON (exit ${err?.code ?? 0}): ${(stderr || stdout).trim().slice(0, 300)}` });
      }
    });
  });
}

const norm = (p) => p.split(path.sep).join("/").replace(/^\.\//, "");
const ruleOf = (f) => f.rule_id ?? f.rule;

/**
 * Scores one suite from the server's audit JSON. A clean case is a false positive when it has a
 * high (ERROR) finding; a slop case is a true positive only when every expected rule fired.
 */
export function scoreSuite(suite, output, { maxFpr = 0.05, minRecall = 0.85 } = {}) {
  const byFile = new Map();
  for (const f of output.findings ?? []) {
    const key = norm(f.file ?? "");
    if (!byFile.has(key)) byFile.set(key, []);
    byFile.get(key).push(f);
  }
  let tp = 0, fn = 0, fp = 0, tn = 0;
  const perRule = {};
  const rule = (id) => (perRule[id] ??= { expected: 0, caught: 0, clean_hits: 0, unexpected_slop_hits: 0 });
  const cases = suite.cases.map((c) => {
    const found = byFile.get(norm(c.file)) ?? [];
    const fired = [...new Set(found.map(ruleOf))].sort();
    if (c.kind === "clean") {
      const blocking = found.filter((f) => normalizeSeverity(f.severity) === "high" || normalizeSeverity(f.severity) === "critical");
      blocking.length ? fp++ : tn++;
      for (const id of fired) rule(id).clean_hits++;
      return { file: c.file, kind: c.kind, fired, result: blocking.length ? "false_positive" : "pass" };
    }
    const missed = c.expected_rules.filter((id) => !fired.includes(id));
    missed.length ? fn++ : tp++;
    for (const id of c.expected_rules) {
      rule(id).expected++;
      if (fired.includes(id)) rule(id).caught++;
    }
    for (const id of fired.filter((id) => !c.expected_rules.includes(id))) rule(id).unexpected_slop_hits++;
    return { file: c.file, kind: c.kind, fired, missed, result: missed.length ? "missed" : "caught" };
  });

  const metrics = { tp, fp, tn, fn, precision: ratio(tp, tp + fp), recall: ratio(tp, tp + fn), false_positive_rate: ratio(fp, fp + tn) };
  const findings = [];
  const cleanCount = fp + tn;
  const slopCount = tp + fn;
  const noisy = Object.entries(perRule).filter(([, r]) => r.clean_hits).sort((a, b) => b[1].clean_hits - a[1].clean_hits).map(([id, r]) => `${id}×${r.clean_hits}`);
  const weak = Object.entries(perRule).filter(([, r]) => r.caught < r.expected).map(([id, r]) => `${id} ${r.caught}/${r.expected}`);

  if (cleanCount < MIN_SAMPLE || slopCount < MIN_SAMPLE) {
    findings.push(finding({ rule_id: "QUAL-003", category: "quality", severity: "info", target: suite.server, message: `Fixture suite too small to score reliably (${cleanCount} clean, ${slopCount} slop; need ${MIN_SAMPLE} of each)`, evidence: `clean=${cleanCount}, slop=${slopCount}`, fix_hint: `Add fixtures until there are at least ${MIN_SAMPLE} clean and ${MIN_SAMPLE} slop cases.` }));
  }
  if (cleanCount >= MIN_SAMPLE && metrics.false_positive_rate > maxFpr) {
    findings.push(finding({ rule_id: "QUAL-001", category: "quality", severity: "high", target: suite.server, message: `False-positive rate ${pct(metrics.false_positive_rate)} on clean fixtures exceeds ${pct(maxFpr)}`, evidence: `fp=${fp}/${cleanCount}; noisy rules: ${noisy.join(", ") || "none"}`, fix_hint: `Narrow the noisiest rule (${noisy[0]?.split("×")[0] ?? "see cases"}) so the clean fixture passes, then re-run bench.` }));
  }
  if (slopCount >= MIN_SAMPLE && metrics.recall < minRecall) {
    findings.push(finding({ rule_id: "QUAL-002", category: "quality", severity: "medium", target: suite.server, message: `Recall ${pct(metrics.recall)} on slop fixtures is below ${pct(minRecall)}`, evidence: `missed=${fn}/${slopCount}; rules under target: ${weak.join(", ") || "none"}`, fix_hint: `Extend the rule that missed most (${weak[0]?.split(" ")[0] ?? "see cases"}) to match the missed fixture, then re-run bench.` }));
  }
  findings.push(...checkContract(suite, output));
  return { server: suite.server, metrics, per_rule: perRule, cases, findings };
}

const CONTRACT_SEVERITIES = new Set(["critical", "high", "medium", "low", "info", "ERROR", "WARN"]);

/**
 * PROTO-003: every finding on a fixture file has rule_id, severity, file, line (>= 1) and a fix_hint
 * string of at most 200 chars. PROTO-004 (low): the fix_hint only restates the message.
 */
export function checkContract(suite, output) {
  const caseFiles = new Set(suite.cases.map((c) => norm(c.file)));
  const missing = new Map();
  const restated = new Set();
  for (const f of output.findings ?? []) {
    if (!caseFiles.has(norm(f.file ?? ""))) continue;
    const id = ruleOf(f) ?? "(no rule id)";
    const gaps = [];
    if (typeof f.rule_id !== "string" || !f.rule_id) gaps.push("rule_id");
    if (!CONTRACT_SEVERITIES.has(f.severity)) gaps.push("severity");
    if (typeof f.file !== "string") gaps.push("file");
    if (!Number.isInteger(f.line) || f.line < 1) gaps.push("line");
    if (typeof f.fix_hint !== "string" || !f.fix_hint.trim() || f.fix_hint.length > MAX_HINT) gaps.push("fix_hint");
    if (gaps.length) missing.set(id, [...new Set([...(missing.get(id) ?? []), ...gaps])]);
    else if (f.fix_hint.trim() === (f.message ?? "").trim()) restated.add(id);
  }
  const out = [];
  if (missing.size) {
    const fields = [...new Set([...missing.values()].flat())];
    out.push(finding({ rule_id: "PROTO-003", category: "protocol", severity: "medium", target: suite.server, message: `Findings from ${missing.size} rule(s) break the 5-field violation contract (missing or invalid: ${fields.join(", ")})`, evidence: [...missing].slice(0, 8).map(([id, g]) => `${id}: ${g.join("+")}`).join("; "), fix_hint: "Upgrade the server to an unslop-core release that emits rule_id and fix_hint on every finding." }));
  }
  if (restated.size) {
    out.push(finding({ rule_id: "PROTO-004", category: "protocol", severity: "low", target: suite.server, message: `${restated.size} rule(s) return a fix_hint that only restates the problem`, evidence: [...restated].sort().join(", "), fix_hint: "Give each listed rule a `fix` field, or end its message with a sentence that says what to change." }));
  }
  return out;
}

/** Loads every suite, runs it and scores it. */
export async function bench({ fixturesDir, servers = [], timeout, maxFpr, minRecall }) {
  const { suites, errors } = await loadSuites(fixturesDir, servers);
  const results = [];
  for (const suite of suites) {
    const run = await runAudit(suite, { timeout });
    if (run.error) {
      errors.push({ target: suite.server, message: `Benchmark did not run: ${run.error}` });
      continue;
    }
    results.push(scoreSuite(suite, run.output, { maxFpr, minRecall }));
  }
  return { results, errors, findings: results.flatMap((r) => r.findings) };
}
