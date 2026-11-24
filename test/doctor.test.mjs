import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { scoreSuite, checkContract, bench } from "../src/bench.mjs";
import { parseTelemetry, sequences, ruleStats, oscillations, analyzeLoops } from "../src/loops.mjs";
import { healthScore, buildReport, exitCode, finding, normalizeSeverity } from "../src/report.mjs";
import { sarif } from "../src/reporters.mjs";
import { main } from "../src/cli.mjs";

const ok = (file, rule, severity = "ERROR") => ({ file, line: 3, rule, rule_id: rule, severity, message: `${rule} bad. Do the fix.`, fix_hint: "Do the fix." });

function suite(clean, slop) {
  return {
    server: "x-unslop",
    dir: "/tmp/x",
    cases: [
      ...Array.from({ length: clean }, (_, i) => ({ file: `clean/c${i}.tsx`, kind: "clean", expected_rules: [] })),
      ...Array.from({ length: slop }, (_, i) => ({ file: `slop/s${i}.tsx`, kind: "slop", expected_rules: ["R1"] })),
    ],
  };
}

test("scoreSuite counts fixture-level TP/FP/TN/FN and computes the spec formulas", () => {
  const s = suite(5, 5);
  const findings = [ok("slop/s0.tsx", "R1"), ok("slop/s1.tsx", "R1"), ok("slop/s2.tsx", "R1"), ok("clean/c0.tsx", "NOISY"), ok("clean/c1.tsx", "SOFT", "WARN")];
  const r = scoreSuite(s, { findings });
  assert.deepEqual([r.metrics.tp, r.metrics.fp, r.metrics.tn, r.metrics.fn], [3, 1, 4, 2]);
  assert.equal(r.metrics.precision, 0.75);
  assert.equal(r.metrics.recall, 0.6);
  assert.equal(r.metrics.false_positive_rate, 0.2);
  assert.equal(r.per_rule.NOISY.clean_hits, 1);
  assert.equal(r.per_rule.SOFT.clean_hits, 1, "WARN hits are tracked per rule even though they do not fail the case");
  assert.equal(r.per_rule.R1.caught, 3);
  const ids = r.findings.map((f) => f.rule_id).sort();
  assert.deepEqual(ids, ["QUAL-001", "QUAL-002"]);
  assert.match(r.findings.find((f) => f.rule_id === "QUAL-001").evidence, /NOISY×1/);
});

test("a slop case needs every expected rule to count as caught", () => {
  const s = { ...suite(0, 0), cases: [{ file: "slop/a.tsx", kind: "slop", expected_rules: ["R1", "R2"] }] };
  const r = scoreSuite(s, { findings: [ok("slop/a.tsx", "R1"), ok("slop/a.tsx", "EXTRA")] });
  assert.equal(r.metrics.fn, 1);
  assert.deepEqual(r.cases[0].missed, ["R2"]);
  assert.equal(r.per_rule.EXTRA.unexpected_slop_hits, 1);
});

test("small suites report QUAL-003 instead of a pass/fail rate", () => {
  const r = scoreSuite(suite(2, 2), { findings: [ok("clean/c0.tsx", "NOISY")] });
  assert.deepEqual(r.findings.map((f) => f.rule_id), ["QUAL-003"]);
});

test("checkContract flags legacy findings and restated hints, ignores non-fixture files", () => {
  const s = suite(1, 1);
  const legacy = { file: "slop/s0.tsx", line: 2, rule: "OLD", severity: "ERROR", message: "Old. Fix." };
  const restated = { ...ok("slop/s0.tsx", "SAME"), fix_hint: "SAME bad. Do the fix." };
  const elsewhere = { file: ".", line: 0, rule: "NO_FILES", severity: "ERROR", message: "x" };
  const out = checkContract(s, { findings: [legacy, restated, elsewhere, ok("slop/s0.tsx", "GOOD")] });
  assert.deepEqual(out.map((f) => f.rule_id), ["PROTO-003", "PROTO-004"]);
  assert.match(out[0].evidence, /^OLD: rule_id\+fix_hint$/);
  assert.equal(out[1].evidence, "SAME");
  assert.deepEqual(checkContract(s, { findings: [{ ...ok("slop/s0.tsx", "LONG"), fix_hint: "x".repeat(201) }] })[0].evidence, "LONG: fix_hint");
  assert.deepEqual(checkContract(s, { findings: [{ ...ok("slop/s0.tsx", "L0"), line: 0 }] })[0].evidence, "L0: line");
});

const rec = (session, iteration, rules, extra = {}) => ({ ts: `2026-11-20T00:00:0${iteration}Z`, session_id: session, server: "fe", file_hash: "f1", iteration, triggered_rules: rules, passed: rules.length === 0, ...extra });

test("parseTelemetry skips malformed lines", () => {
  const { records, malformed } = parseTelemetry(`${JSON.stringify(rec("s", 1, []))}\nnot json\n{"session_id":"s"}\n\n`);
  assert.equal(records.length, 1);
  assert.equal(malformed, 2);
});

test("ruleStats counts retries per sequence and ignores single-audit sequences", () => {
  const seqs = sequences([rec("a", 2, ["R"]), rec("a", 1, ["R"]), rec("a", 3, []), rec("b", 1, ["R"]), rec("c", 1, ["R"]), rec("c", 2, ["R"])]);
  const [r] = ruleStats(seqs);
  assert.equal(r.sequences, 2, "session b had one audit and is excluded");
  assert.equal(r.retries, 4);
  assert.equal(r.avg_retries, 2);
  assert.equal(r.convergence_rate, 0.5);
});

test("LOOP-001 needs a minimum sample and fires on low convergence", () => {
  const stuck = (s) => [rec(s, 1, ["SPACING"]), rec(s, 2, ["SPACING"])];
  const fixed = (s) => [rec(s, 1, ["SPACING"]), rec(s, 2, [])];
  const now = new Date("2026-11-24T00:00:00Z");
  assert.equal(analyzeLoops([...stuck("a"), ...stuck("b"), ...stuck("c"), ...fixed("d")], { now }).findings.length, 0, "4 sequences < minimum 5");
  const { findings, metrics } = analyzeLoops([...stuck("a"), ...stuck("b"), ...stuck("c"), ...fixed("d"), ...fixed("e")], { now });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].rule_id, "LOOP-001");
  assert.match(findings[0].message, /SPACING .* 40% convergence/);
  assert.equal(metrics.convergence_rate, 0.4);
  assert.equal(analyzeLoops([...stuck("a"), ...stuck("b"), ...stuck("c"), ...fixed("d"), ...fixed("e")], { now: new Date("2027-01-01T00:00:00Z") }).findings.length, 0, "old records fall outside the window");
});

test("oscillations detect A -> B -> A and LOOP-002 needs it in two sequences", () => {
  const flip = (s) => [rec(s, 1, ["A"]), rec(s, 2, ["B"]), rec(s, 3, ["A"])];
  assert.deepEqual(oscillations(sequences(flip("x"))), [{ server: "fe", rule_a: "A", rule_b: "B", sequences: 1 }]);
  assert.deepEqual(oscillations(sequences([rec("y", 1, ["A"]), rec("y", 2, ["A", "B"]), rec("y", 3, ["A"])])), [], "A never cleared, so it is not an oscillation");
  const now = new Date("2026-11-24T00:00:00Z");
  assert.equal(analyzeLoops(flip("x"), { now }).findings.length, 0);
  assert.deepEqual(analyzeLoops([...flip("x"), ...flip("y")], { now }).findings.map((f) => f.rule_id), ["LOOP-002"]);
});

test("health score, status and exit codes follow the spec", () => {
  assert.deepEqual(healthScore({ critical: 0, high: 1, medium: 0, low: 0 }), { score: 85, status: "healthy" });
  assert.deepEqual(healthScore({ critical: 0, high: 2, medium: 1, low: 0 }), { score: 63, status: "warn" });
  assert.deepEqual(healthScore({ critical: 1, high: 0, medium: 0, low: 0 }), { score: 70, status: "fail" });
  const f = (severity) => finding({ rule_id: "X-1", category: "c", severity, target: "t", message: "m", evidence: severity, fix_hint: "h" });
  assert.equal(exitCode(buildReport({ workspace: "/w", findings: [f("medium")] }), "high"), 0);
  assert.equal(exitCode(buildReport({ workspace: "/w", findings: [f("medium")] }), "medium"), 1);
  assert.equal(exitCode(buildReport({ workspace: "/w", findings: [f("low")], errors: [{ target: "t", message: "broke" }] })), 3);
  assert.equal(exitCode(buildReport({ workspace: "/w", findings: [f("critical")], errors: [{ target: "t", message: "broke" }] })), 2);
  assert.equal(normalizeSeverity("ERROR"), "high");
  assert.equal(normalizeSeverity("bogus"), null);
});

test("finding ids are stable across runs and differ by evidence", () => {
  const a = finding({ rule_id: "LOOP-001", category: "loops", severity: "high", target: "fe", message: "m", evidence: "e1", fix_hint: "h" });
  const b = finding({ rule_id: "LOOP-001", category: "loops", severity: "high", target: "fe", message: "other", evidence: "e1", fix_hint: "h" });
  const c = finding({ rule_id: "LOOP-001", category: "loops", severity: "high", target: "fe", message: "m", evidence: "e2", fix_hint: "h" });
  assert.equal(a.id, b.id);
  assert.notEqual(a.id, c.id);
  assert.match(a.id, /^fnd_loop001_[0-9a-f]{4}$/);
});

test("sarif output maps severities and keeps one rule entry per rule id", () => {
  const f = (severity, evidence) => finding({ rule_id: "QUAL-001", category: "quality", severity, target: "fe", message: "m", evidence, fix_hint: "h" });
  const doc = JSON.parse(sarif(buildReport({ workspace: "/w", findings: [f("high", "a"), f("high", "b")] })));
  assert.equal(doc.version, "2.1.0");
  assert.equal(doc.runs[0].tool.driver.rules.length, 1);
  assert.equal(doc.runs[0].results.length, 2);
  assert.equal(doc.runs[0].results[0].level, "error");
});

async function fakeServer(dir, body) {
  const script = path.join(dir, "server.mjs");
  await fs.writeFile(script, body);
  return script;
}

test("bench runs the server with a stripped env and reports timeouts as runtime errors", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "doctor-"));
  const suiteDir = path.join(dir, "fixtures", "fake-unslop");
  await fs.mkdir(suiteDir, { recursive: true });
  const script = await fakeServer(dir, `
    const files = process.argv.slice(3, -1);
    const leaked = process.env.DOCTOR_SECRET ? "LEAK" : "CLEAN";
    const findings = files.filter((f) => f.startsWith("slop/")).map((f) => ({ file: f, line: 1, rule: leaked, rule_id: leaked, severity: "ERROR", message: "m. fix.", fix_hint: "fix." }));
    console.log(JSON.stringify({ status: findings.length ? "FAIL" : "PASS", findings }));
    process.exitCode = findings.length ? 1 : 0;
  `);
  await fs.writeFile(path.join(suiteDir, "expected.json"), JSON.stringify({ command: ["node", script], cases: [{ file: "clean/a.tsx", kind: "clean", expected_rules: [] }, { file: "slop/b.tsx", kind: "slop", expected_rules: ["CLEAN"] }] }));
  process.env.DOCTOR_SECRET = "s3cret";
  try {
    const r = await bench({ fixturesDir: path.join(dir, "fixtures"), timeout: 5000 });
    assert.deepEqual(r.errors, []);
    assert.equal(r.results[0].server, "fake-unslop");
    assert.equal(r.results[0].metrics.tp, 1, "secret env var was not passed to the server");
    assert.equal(r.results[0].metrics.tn, 1, "exit code 1 from a failing audit is a normal result");
  } finally {
    delete process.env.DOCTOR_SECRET;
  }

  const slow = await fakeServer(dir, "setTimeout(() => {}, 10000);");
  await fs.writeFile(path.join(suiteDir, "expected.json"), JSON.stringify({ command: ["node", slow], cases: [{ file: "clean/a.tsx", kind: "clean", expected_rules: [] }] }));
  const t = await bench({ fixturesDir: path.join(dir, "fixtures"), timeout: 500 });
  assert.equal(t.results.length, 0);
  assert.match(t.errors[0].message, /timed out after 500ms/);
});

test("cli: bad config exits 3, init creates the opt-in directory, missing telemetry is info only", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "doctor-cli-"));
  assert.equal((await main(["bench", "--workspace", dir])).code, 3, "missing fixtures dir is a config error");
  assert.equal((await main(["scan", "--format", "xml"])).code, 3);
  assert.equal((await main(["scan", "--max-fpr", "2"])).code, 3);
  assert.equal((await main(["init", "--workspace", dir])).code, 0);
  assert.equal((await fs.readFile(path.join(dir, ".doctor-unslop", ".gitignore"), "utf8")).trim(), "telemetry.jsonl");
  assert.equal((await main(["init", "--workspace", dir])).code, 0, "init is idempotent");
  const loops = await main(["loops", "--workspace", dir, "--format", "json"]);
  assert.equal(loops.code, 0);
  assert.equal(JSON.parse(loops.stdout).findings[0].rule_id, "LOOP-000");
});
