import fs from "node:fs";
import path from "node:path";
import { finding } from "./report.mjs";
import { estimateTokens } from "./lockfile.mjs";

export const LATENCY_MS = 2000;
export const TOOL_TOKENS = 400;

/** PROTO-005 handshake failure, PROTO-001 stdout pollution, PROTO-002 slow start. */
export function protocolFindings(server, p) {
  const out = [];
  const cmd = [server.command, ...server.args].join(" ");
  if (p.error) {
    out.push(finding({ rule_id: "PROTO-005", category: "protocol", severity: "high", target: server.name, message: `Server failed the stdio handshake: ${p.error}`, evidence: `${cmd}${p.stderr ? ` | stderr: ${p.stderr.trim().split("\n").at(-1)}` : ""}`, fix_hint: "Run the command by hand to see why it fails, fix the path or install, then re-run `doctor-unslop stdio`." }));
  }
  if (p.noise.length) {
    out.push(finding({ rule_id: "PROTO-001", category: "protocol", severity: "high", target: server.name, message: "Non-JSON-RPC output on stdout corrupts the stdio transport", evidence: p.noise.slice(0, 2).join(" | "), fix_hint: "Send logs to stderr (console.error) so stdout carries only JSON-RPC messages." }));
  }
  const total = (p.cold_start_ms ?? 0) + (p.list_ms ?? 0);
  if (!p.error && total > LATENCY_MS) {
    const viaNpx = /(^|\/)npx$/.test(server.command ?? "");
    out.push(finding({ rule_id: "PROTO-002", category: "protocol", severity: "medium", target: server.name, message: `Cold start to tools/list took ${total}ms (limit ${LATENCY_MS}ms)`, evidence: `initialize=${p.cold_start_ms}ms, tools/list=${p.list_ms}ms${viaNpx ? ", launched via npx" : ""}`, fix_hint: viaNpx ? "Install the package globally or pin a version so npx skips its registry check on every start." : "Defer heavy imports until the first tool call so initialize answers quickly." }));
  }
  return out;
}

/** TOK-001: a single tool over 400 estimated tokens, or the whole fleet over the budget. */
export function tokenFindings(probes, budget = 4000) {
  const out = [];
  const perServer = [];
  for (const { server, result } of probes) {
    let sum = 0;
    for (const tool of result.tools) {
      const n = estimateTokens(tool);
      sum += n;
      if (n > TOOL_TOKENS) out.push(finding({ rule_id: "TOK-001", category: "tokens", severity: "medium", target: server.name, message: `Tool ${tool.name} costs about ${n} tokens of context (limit ${TOOL_TOKENS})`, evidence: `~${n} tokens, description ${tool.description?.length ?? 0} chars`, fix_hint: "Shorten the description to what the agent needs to choose and call the tool; move detail into the skill." }));
    }
    perServer.push({ server: server.name, tools: result.tools.length, estimated_tokens: sum });
  }
  const total = perServer.reduce((n, s) => n + s.estimated_tokens, 0);
  if (total > budget) {
    out.push(finding({ rule_id: "TOK-001", category: "tokens", severity: "medium", target: "fleet", message: `Fleet tool schemas cost about ${total} tokens (budget ${budget})`, evidence: perServer.sort((a, b) => b.estimated_tokens - a.estimated_tokens).map((s) => `${s.server}~${s.estimated_tokens}`).join(", "), fix_hint: "Disable servers a project does not use, or trim the largest server's descriptions." }));
  }
  return { findings: out, perServer, total };
}

/** CONF-001: the same tool name on two or more servers. */
export function conflictFindings(probes) {
  const owners = new Map();
  for (const { server, result } of probes) for (const t of result.tools) owners.set(t.name, [...(owners.get(t.name) ?? []), server.name]);
  return [...owners]
    .filter(([, s]) => s.length > 1)
    .map(([tool, servers]) =>
      finding({ rule_id: "CONF-001", category: "conflicts", severity: "medium", target: servers.join("+"), message: `Tool name ${tool} is registered by ${servers.length} servers`, evidence: `${tool}: ${servers.join(", ")} (clients that prefix tool names with the server name are not affected)`, fix_hint: `Rename the tool per server (e.g. ${servers[0].replace(/-unslop$/, "")}_${tool}) or keep it in one server, and update the skills that mention it.` }),
    );
}

// Directive and exfiltration phrases that have no business in a tool description.
const INJECTION = [
  [/ignore (?:all |any )?(?:previous|prior|above|earlier) (?:instructions|prompts|rules)/i, "overrides earlier instructions"],
  [/(?:do not|don't|never) (?:tell|inform|mention|reveal|show)\b[^.]{0,40}\b(?:user|human)/i, "hides behaviour from the user"],
  [/<\/?(?:important|system|instructions?|secret)>/i, "pseudo-system tag"],
  [/\bexfiltrat|\b(?:send|post|upload) (?:it|this|them|the [a-z ]{1,30}) to https?:\/\//i, "sends data to a URL"],
  [/~\/\.ssh|\bid_rsa\b|\.aws\/credentials|\.npmrc\b|\bprivate key\b/i, "mentions credential files"],
  [/[​-‏‪-‮⁠-⁤﻿]/, "hidden Unicode characters"],
];

function* strings(value, at = "description") {
  if (typeof value === "string") yield [at, value];
  else if (Array.isArray(value)) for (const [i, v] of value.entries()) yield* strings(v, `${at}[${i}]`);
  else if (value && typeof value === "object") for (const [k, v] of Object.entries(value)) yield* strings(v, `${at}.${k}`);
}

/** SEC-005: injection patterns in a tool's description or anywhere in its input schema. */
export function injectionFindings(server, result) {
  const out = [];
  for (const tool of result.tools) {
    const hits = [];
    for (const [where, text] of [["description", tool.description ?? ""], ...strings(tool.inputSchema ?? {}, "inputSchema")]) {
      for (const [re, why] of INJECTION) if (re.test(text)) hits.push(`${why} in ${where}`);
    }
    if (hits.length) out.push(finding({ rule_id: "SEC-005", category: "security", severity: "high", target: server.name, message: `Tool ${tool.name} has prompt-injection patterns in its metadata`, evidence: [...new Set(hits)].join("; "), fix_hint: "Read the tool's full description and schema; remove the server unless every flagged phrase is legitimate." }));
  }
  return out;
}

/**
 * SEC-008: servers launched from an unversioned or @latest npm package can change on any publish.
 * One fleet-level finding, because the fix is one install decision, not one per client.
 */
export function unpinnedPackageFindings(servers) {
  const hits = new Map();
  for (const s of servers) {
    if (!/(^|[\\/])npx(\.cmd)?$/.test(s.command ?? "")) continue;
    const pkg = s.args.find((a) => !a.startsWith("-"));
    if (!pkg) continue;
    const at = pkg.lastIndexOf("@");
    const version = at > 0 ? pkg.slice(at + 1) : null;
    if (version && version !== "latest") continue;
    const name = at > 0 ? pkg.slice(0, at) : pkg;
    hits.set(name, [...new Set([...(hits.get(name) ?? []), s.client])]);
  }
  if (!hits.size) return [];
  const clients = [...new Set([...hits.values()].flat())];
  return [finding({ rule_id: "SEC-008", category: "security", severity: "low", target: "fleet", message: `${hits.size} server(s) run through npx without a fixed version in ${clients.length} client(s), so every new publish runs unreviewed`, evidence: [...hits].map(([p, c]) => `${p} (${c.join(", ")})`).join("; "), fix_hint: "Pin versions in the client configs (package@x.y.z) and run `doctor-unslop security` in CI to catch tool changes." })];
}

const signature = (s) => JSON.stringify([s.transport, s.command, s.args, s.url, Object.keys(s.env).sort()]);

/**
 * CFG-001, grouped per client (one stale config is one root cause): selected servers the client lacks
 * (only for clients that run at least one of them), servers it launches differently from the canonical
 * definition, and absolute command paths that do not exist.
 */
export function parityFindings(clients, selected) {
  const names = new Set(selected.map((s) => s.name));
  const byClient = new Map();
  for (const c of clients) {
    if (!c.servers.some((s) => names.has(s.name))) continue;
    const m = byClient.get(c.client) ?? new Map();
    for (const s of c.servers) if (names.has(s.name) && !m.has(s.name)) m.set(s.name, s);
    byClient.set(c.client, m);
  }
  const launch = (s) => [s.command, ...s.args].join(" ");
  const out = [];
  for (const [client, m] of byClient) {
    const missing = selected.filter((s) => !m.has(s.name)).map((s) => s.name);
    const differs = selected.filter((s) => m.has(s.name) && signature(m.get(s.name)) !== signature(s));
    if (missing.length || differs.length) {
      const parts = [missing.length && `missing ${missing.length} server(s)`, differs.length && `launches ${differs.length} differently`].filter(Boolean);
      out.push(finding({
        rule_id: "CFG-001", category: "parity", severity: "medium", target: client,
        message: `${client} config drifts from the other clients: ${parts.join(", ")}`,
        evidence: [missing.length && `missing: ${missing.join(", ")}`, ...differs.map((s) => `${s.name}: "${launch(m.get(s.name))}" vs ${s.client} "${launch(s)}"`)].filter(Boolean).join(" | "),
        location: { file: [...clients].find((c) => c.client === client)?.file ?? null, line: 1, column: 1 },
        fix_hint: `Copy the listed entries into ${client}'s config from ${[...new Set([...missing.map((n) => selected.find((s) => s.name === n).client), ...differs.map((s) => s.client)])].join(", ")}.`,
      }));
    }
    for (const s of m.values()) {
      if (s.command && path.isAbsolute(s.command) && !fs.existsSync(s.command)) {
        out.push(finding({ rule_id: "CFG-001", category: "parity", severity: "high", target: s.name, message: `${client} launches ${s.name} from a path that does not exist`, evidence: `${client}: ${s.command}`, fix_hint: "Point the command at a stable binary (for fnm/nvm, a fixed install path rather than a per-shell multishell path)." }));
      }
    }
  }
  return out;
}
