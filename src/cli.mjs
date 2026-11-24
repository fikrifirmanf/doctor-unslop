#!/usr/bin/env node
import fs from "node:fs/promises";
import path from "node:path";
import { readFileSync, realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { runChecks, pin, CATEGORIES } from "./engine.mjs";
import { CLIENTS } from "./discovery.mjs";
import { exitCode, SEVERITIES } from "./report.mjs";
import { json, sarif, pretty } from "./reporters.mjs";

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));

const COMMANDS = {
  scan: CATEGORIES,
  security: ["security"],
  stdio: ["protocol"],
  parity: ["parity"],
  tokens: ["tokens"],
  conflicts: ["conflicts"],
  bench: ["quality"],
  loops: ["loops"],
};

const HELP = `doctor-unslop ${pkg.version}

Usage:
  doctor-unslop init               create .doctor-unslop/ (turns on telemetry from unslop servers)
  doctor-unslop scan               run every check
  doctor-unslop security           SEC-004 pins, SEC-005 injection patterns, SEC-008 unpinned npx packages
  doctor-unslop stdio [server...]  handshake, stdout pollution and cold-start latency (PROTO-001/002/005)
  doctor-unslop parity             config drift and dead binary paths across clients (CFG-001)
  doctor-unslop tokens             estimated tool-schema context cost (TOK-001)
  doctor-unslop conflicts          tool names registered by more than one server (CONF-001)
  doctor-unslop bench [server...]  score clean-vs-slop fixtures and the violation contract
  doctor-unslop loops              find rules that keep agents in fix-verify loops
  doctor-unslop pin [server...]    write tool hashes to the lockfile (the only command that edits config)
  doctor-unslop serve              start the read-only MCP server over stdio

Options:
  --workspace <path>      workspace root (default: cwd)
  --clients <list>        ${CLIENTS.join(",")} (default: all)
  --servers <list>        server names to probe (default: names containing "unslop")
  --all-servers           probe every configured stdio server
  --fixtures <dir>        fixture root (default: <workspace>/.doctor-unslop/fixtures)
  --telemetry-log <path>  telemetry JSONL (default: <workspace>/.doctor-unslop/telemetry.jsonl)
  --lockfile <path>       pin lockfile (default: <workspace>/.doctor-unslop.lock.json)
  --format <fmt>          pretty | json | sarif (default: pretty)
  --fail-on <sev>         critical | high | medium | low (default: high)
  --token-budget <n>      TOK-001 fleet budget in estimated tokens (default: 4000)
  --max-fpr <rate>        QUAL-001 threshold (default: 0.05)
  --min-recall <rate>     QUAL-002 threshold (default: 0.85)
  --max-retries <n>       LOOP-001 average-retries threshold (default: 3)
  --min-convergence <r>   LOOP-001 convergence threshold (default: 0.7)
  --window-days <n>       telemetry window (default: 14)
  --timeout <ms>          per-server probe or audit timeout (default: 5000)

Probes start each server with only PATH, HOME, TMPDIR and LANG from your environment, plus the env
block from that server's own config entry. Servers launched with npx may download from the registry.

Exit codes: 0 healthy, 1 findings at or above --fail-on, 2 critical finding, 3 runtime or config error.`;

const OPTIONS = {
  workspace: { type: "string" },
  clients: { type: "string" },
  servers: { type: "string" },
  "all-servers": { type: "boolean" },
  fixtures: { type: "string" },
  "telemetry-log": { type: "string" },
  lockfile: { type: "string" },
  format: { type: "string", default: "pretty" },
  "fail-on": { type: "string", default: "high" },
  "token-budget": { type: "string", default: "4000" },
  "max-fpr": { type: "string", default: "0.05" },
  "min-recall": { type: "string", default: "0.85" },
  "max-retries": { type: "string", default: "3" },
  "min-convergence": { type: "string", default: "0.7" },
  "window-days": { type: "string", default: "14" },
  timeout: { type: "string", default: "5000" },
  help: { type: "boolean", short: "h" },
  version: { type: "boolean", short: "v" },
};

class UsageError extends Error {}

function num(name, value, { min = 0, max = Infinity } = {}) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < min || n > max) throw new UsageError(`--${name} must be a number between ${min} and ${max}, got "${value}".`);
  return n;
}

const list = (s) => (s ? s.split(",").map((x) => x.trim()).filter(Boolean) : []);

async function init(workspace) {
  const dir = path.join(workspace, ".doctor-unslop");
  await fs.mkdir(path.join(dir, "fixtures"), { recursive: true });
  await fs.writeFile(path.join(dir, ".gitignore"), "telemetry.jsonl\n", { flag: "wx" }).catch((e) => (e.code === "EEXIST" ? null : Promise.reject(e)));
  return `Created ${path.relative(process.cwd(), dir) || dir}/ (fixtures/, .gitignore for telemetry.jsonl).
unslop servers on unslop-core >= 1.1 now append one line per audited file to telemetry.jsonl.
Add a suite at fixtures/<server>/expected.json, then run: doctor-unslop bench`;
}

function options(o, positionals, cmd) {
  if (!["json", "sarif", "pretty"].includes(o.format)) throw new UsageError("--format must be pretty, json or sarif.");
  if (!SEVERITIES.slice(0, 4).includes(o["fail-on"])) throw new UsageError("--fail-on must be critical, high, medium or low.");
  const clients = o.clients ? list(o.clients) : CLIENTS;
  const bad = clients.filter((c) => !CLIENTS.includes(c));
  if (bad.length) throw new UsageError(`Unknown client(s): ${bad.join(", ")}. Use ${CLIENTS.join(", ")}.`);
  const named = [...list(o.servers), ...(cmd === "stdio" || cmd === "pin" ? positionals : [])];
  return {
    fixturesDir: o.fixtures,
    telemetryLog: o["telemetry-log"],
    lockfile: o.lockfile,
    clients,
    servers: named,
    allServers: Boolean(o["all-servers"]),
    benchServers: cmd === "bench" ? positionals : [],
    tokenBudget: num("token-budget", o["token-budget"], { min: 500 }),
    maxFpr: num("max-fpr", o["max-fpr"], { max: 1 }),
    minRecall: num("min-recall", o["min-recall"], { max: 1 }),
    maxRetries: num("max-retries", o["max-retries"], { min: 1 }),
    minConvergence: num("min-convergence", o["min-convergence"], { max: 1 }),
    windowDays: num("window-days", o["window-days"], { min: 1, max: 90 }),
    timeout: num("timeout", o.timeout, { min: 500, max: 30000 }),
  };
}

export async function main(argv = process.argv.slice(2)) {
  let parsed;
  try {
    parsed = parseArgs({ args: argv, options: OPTIONS, allowPositionals: true });
  } catch (e) {
    return { code: 3, stderr: `${e.message}\n\nRun doctor-unslop --help.` };
  }
  const { values: o, positionals } = parsed;
  if (o.version) return { code: 0, stdout: pkg.version };
  const [cmd = "scan", ...rest] = positionals;
  if (o.help || cmd === "help") return { code: 0, stdout: HELP };

  try {
    const workspace = path.resolve(o.workspace ?? process.cwd());
    if (cmd === "init") return { code: 0, stdout: await init(workspace) };
    if (cmd === "serve") {
      const { serve } = await import("./mcp.mjs");
      await serve({ version: pkg.version });
      return { code: null };
    }
    if (cmd !== "pin" && !COMMANDS[cmd]) throw new UsageError(`Unknown command "${cmd}".`);
    const opts = options(o, rest, cmd);

    if (cmd === "pin") {
      const r = await pin({ workspace, ...opts });
      if (r.error) return { code: 3, stderr: r.error };
      const lines = [
        r.pinned.length ? `Pinned ${r.tools} tools from ${r.pinned.length} server(s) to ${path.relative(process.cwd(), r.lockfile) || r.lockfile}: ${r.pinned.join(", ")}` : "Nothing pinned.",
        ...r.failed.map((f) => `not pinned (probe failed) ${f}`),
        ...r.errors.map((e) => `ERROR ${e.target}: ${e.message}`),
      ];
      return { code: r.failed.length || r.errors.length || !r.pinned.length ? 3 : 0, stdout: lines.join("\n") };
    }

    const { report } = await runChecks({ workspace, categories: COMMANDS[cmd], ...opts });
    const text = o.format === "json" ? json(report) : o.format === "sarif" ? sarif(report) : pretty(report);
    return { code: exitCode(report, o["fail-on"]), stdout: text };
  } catch (e) {
    if (e instanceof UsageError) return { code: 3, stderr: `${e.message}\n\nRun doctor-unslop --help.` };
    return { code: 3, stderr: `doctor-unslop crashed: ${e.stack ?? e.message}` };
  }
}

const isEntry = () => {
  try {
    return realpathSync(process.argv[1]) === fileURLToPath(import.meta.url);
  } catch {
    return false;
  }
};

if (isEntry()) {
  const { code, stdout, stderr } = await main();
  if (stdout) process.stdout.write(stdout + "\n");
  if (stderr) process.stderr.write(stderr + "\n");
  if (code !== null) process.exitCode = code;
}
