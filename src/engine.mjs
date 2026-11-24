import fs from "node:fs/promises";
import path from "node:path";
import { bench } from "./bench.mjs";
import { loops } from "./loops.mjs";
import { discover, selectServers, CLIENTS } from "./discovery.mjs";
import { probe } from "./probe.mjs";
import { readLock, verifyPins, pinServer, buildLock } from "./lockfile.mjs";
import { protocolFindings, tokenFindings, conflictFindings, injectionFindings, unpinnedPackageFindings, parityFindings } from "./fleet.mjs";
import { buildReport, finding } from "./report.mjs";

export const CATEGORIES = ["security", "protocol", "parity", "tokens", "conflicts", "quality", "loops"];
const NEEDS_PROBE = new Set(["security", "protocol", "tokens", "conflicts"]);

export const defaults = (workspace, o = {}) => ({
  fixturesDir: path.resolve(workspace, o.fixturesDir ?? ".doctor-unslop/fixtures"),
  telemetryLog: path.resolve(workspace, o.telemetryLog ?? ".doctor-unslop/telemetry.jsonl"),
  lockfile: path.resolve(workspace, o.lockfile ?? ".doctor-unslop.lock.json"),
  maxFpr: o.maxFpr ?? 0.05,
  minRecall: o.minRecall ?? 0.85,
  maxRetries: o.maxRetries ?? 3,
  minConvergence: o.minConvergence ?? 0.7,
  windowDays: o.windowDays ?? 14,
  timeout: o.timeout ?? 5000,
  tokenBudget: o.tokenBudget ?? 4000,
  clients: o.clients ?? CLIENTS,
  servers: o.servers ?? [],
  allServers: o.allServers ?? false,
  benchServers: o.benchServers ?? [],
  home: o.home,
});

/** Discovers and probes the selected servers one at a time (parallel starts would skew latency). */
export async function probeFleet(workspace, opts) {
  const { clients, errors } = await discover({ workspace, clients: opts.clients, home: opts.home });
  const { servers, missing } = selectServers(clients, { names: opts.servers, all: opts.allServers });
  for (const name of missing) errors.push({ target: name, message: `No MCP server named ${name} in the ${opts.clients.join(", ")} configs.` });
  const probes = [];
  const skipped = [];
  for (const server of servers) {
    if (server.transport !== "stdio" || !server.command) {
      skipped.push(finding({ rule_id: "PROTO-005", category: "protocol", severity: "info", target: server.name, message: "Remote server skipped; v0.1 probes stdio servers only", evidence: server.url ?? "no command", fix_hint: "Check this server with its provider's tooling." }));
      continue;
    }
    probes.push({ server, result: await probe(server, { timeout: opts.timeout, cwd: workspace }) });
  }
  return { clients, servers, probes, skipped, errors };
}

/** Runs the requested categories and returns the unified report plus per-check detail. */
export async function runChecks({ workspace, categories = CATEGORIES, ...rest }) {
  const opts = defaults(workspace, rest);
  const want = new Set(categories);
  const findings = [];
  const errors = [];
  const detail = {};
  const metrics = {};

  if ([...want].some((c) => NEEDS_PROBE.has(c) || c === "parity")) {
    const fleet = [...want].some((c) => NEEDS_PROBE.has(c)) ? await probeFleet(workspace, opts) : await discover({ workspace, clients: opts.clients, home: opts.home }).then(({ clients, errors }) => ({ clients, errors, probes: [], skipped: [], servers: selectServers(clients, { names: opts.servers, all: opts.allServers }).servers }));
    errors.push(...fleet.errors);
    const ok = fleet.probes.filter((p) => p.result.ok);
    if (want.has("protocol")) findings.push(...fleet.skipped, ...fleet.probes.flatMap(({ server, result }) => protocolFindings(server, result)));
    if (want.has("tokens")) {
      const t = tokenFindings(ok, opts.tokenBudget);
      findings.push(...t.findings);
      detail.tokens = { estimated: true, total: t.total, budget: opts.tokenBudget, servers: t.perServer };
      metrics.fleet_schema_tokens = t.total;
    }
    if (want.has("conflicts")) findings.push(...conflictFindings(ok));
    if (want.has("security")) {
      findings.push(...ok.flatMap(({ server, result }) => injectionFindings(server, result)));
      findings.push(...unpinnedPackageFindings(fleet.clients.flatMap((c) => c.servers).filter((s) => fleet.servers.some((x) => x.name === s.name))));
      const { lock, error } = await readLock(opts.lockfile);
      if (error) errors.push({ target: opts.lockfile, message: error });
      else if (!lock) findings.push(finding({ rule_id: "SEC-004", category: "security", severity: "info", target: path.basename(opts.lockfile), message: "No lockfile, so tool changes since the last review cannot be detected", evidence: "lockfile not found", fix_hint: "Run `doctor-unslop pin` and commit .doctor-unslop.lock.json." }));
      else findings.push(...ok.flatMap(({ server, result }) => verifyPins(lock, server, result, path.relative(workspace, opts.lockfile))));
    }
    if (want.has("parity")) findings.push(...parityFindings(fleet.clients, fleet.servers));
    detail.servers = fleet.probes.map(({ server, result }) => ({ name: server.name, client: server.client, command: [server.command, ...server.args].join(" "), ok: result.ok, cold_start_ms: result.cold_start_ms, list_ms: result.list_ms, tools: result.tools.length, ...(result.error ? { error: result.error } : {}) }));
    detail.clients = fleet.clients.map((c) => ({ client: c.client, file: c.file, servers: c.servers.length }));
  }

  if (want.has("quality")) {
    const b = await bench({ ...opts, servers: opts.benchServers });
    findings.push(...b.findings);
    errors.push(...b.errors);
    detail.benchmarks = b.results.map(({ findings: _, ...r }) => r);
    const agg = b.results.reduce((a, r) => ({ tp: a.tp + r.metrics.tp, fp: a.fp + r.metrics.fp, tn: a.tn + r.metrics.tn, fn: a.fn + r.metrics.fn }), { tp: 0, fp: 0, tn: 0, fn: 0 });
    const ratio = (x, y) => (y ? Number((x / y).toFixed(4)) : null);
    Object.assign(metrics, { precision: ratio(agg.tp, agg.tp + agg.fp), recall: ratio(agg.tp, agg.tp + agg.fn), false_positive_rate: ratio(agg.fp, agg.fp + agg.tn) });
  }
  if (want.has("loops")) {
    const l = await loops(opts);
    findings.push(...l.findings);
    detail.loops = { metrics: l.metrics, rules: l.stats, malformed_lines: l.malformed };
    if (l.metrics.records !== undefined) Object.assign(metrics, { avg_retries_to_pass: l.metrics.avg_retries_to_pass, convergence_rate: l.metrics.convergence_rate });
  }

  const servers = new Set([...(detail.servers ?? []).map((s) => s.name), ...(detail.benchmarks ?? []).map((b) => b.server)]);
  const report = buildReport({ workspace, findings, errors, servers: [...servers], metrics });
  return { report: { ...report, ...detail }, opts };
}

/** CLI only: probes the selected servers and writes their pins. Servers that fail to start are not pinned. */
export async function pin({ workspace, ...rest }) {
  const opts = defaults(workspace, rest);
  const fleet = await probeFleet(workspace, opts);
  const { lock: previous, error } = await readLock(opts.lockfile);
  if (error) return { error };
  const pins = {};
  const failed = [];
  for (const { server, result } of fleet.probes) {
    if (result.ok) pins[server.name] = pinServer(server, result);
    else failed.push(`${server.name}: ${result.error}`);
  }
  const lock = buildLock(previous, pins);
  if (Object.keys(pins).length) await fs.writeFile(opts.lockfile, JSON.stringify(lock, null, 2) + "\n");
  return { lockfile: opts.lockfile, pinned: Object.keys(pins), tools: Object.values(pins).reduce((n, p) => n + Object.keys(p.tools).length, 0), failed, errors: fleet.errors };
}
