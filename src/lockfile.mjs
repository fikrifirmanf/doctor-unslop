import fs from "node:fs/promises";
import { createHash } from "node:crypto";
import { finding } from "./report.mjs";

export const LOCKFILE_VERSION = 1;

/** JSON with object keys sorted at every level, so formatting and key order never change a hash. */
export function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(",")}}`;
  return JSON.stringify(value ?? null);
}

export const sha256 = (s) => createHash("sha256").update(s).digest("hex");

/** Rough token count (about 4 characters per token). Labelled as an estimate everywhere it appears. */
export const estimateTokens = (tool) => Math.ceil(canonical({ name: tool.name, description: tool.description ?? "", inputSchema: tool.inputSchema ?? {} }).length / 4);

export const commandHash = (server) => sha256(canonical([server.command, ...server.args])).slice(0, 32);

export function pinServer(server, probeResult) {
  return {
    transport: server.transport,
    command_hash: commandHash(server),
    tools: Object.fromEntries(
      [...probeResult.tools]
        .sort((a, b) => a.name.localeCompare(b.name))
        .map((t) => [t.name, { description_sha256: sha256(t.description ?? ""), schema_sha256: sha256(canonical(t.inputSchema ?? {})), estimated_tokens: estimateTokens(t) }]),
    ),
  };
}

/** Merges fresh pins into an existing lockfile; servers that were not probed keep their old pins. */
export function buildLock(previous, pins, now = new Date()) {
  return {
    lockfile_version: LOCKFILE_VERSION,
    pinned_at: now.toISOString(),
    hash_algorithm: "sha256",
    servers: Object.fromEntries(Object.entries({ ...(previous?.servers ?? {}), ...pins }).sort(([a], [b]) => a.localeCompare(b))),
  };
}

export async function readLock(file) {
  const text = await fs.readFile(file, "utf8").catch(() => null);
  if (text === null) return { lock: null };
  try {
    const lock = JSON.parse(text);
    if (lock.lockfile_version !== LOCKFILE_VERSION || typeof lock.servers !== "object") return { error: `${file}: unsupported lockfile (expected lockfile_version ${LOCKFILE_VERSION}).` };
    return { lock };
  } catch (e) {
    return { error: `${file}: ${e.message}` };
  }
}

const excerpt = (s) => (s ?? "").replace(/\s+/g, " ").slice(0, 160);

/**
 * SEC-004: compares live tools against the lockfile.
 * critical = a pinned tool's description or schema changed; high = an unpinned tool appeared;
 * medium = the launch command changed; low = a pinned tool disappeared.
 */
export function verifyPins(lock, server, probeResult, lockfile) {
  const pinned = lock?.servers?.[server.name];
  const sec = (severity, message, evidence) =>
    finding({ rule_id: "SEC-004", category: "security", severity, target: server.name, message, evidence, location: { file: lockfile, line: 1, column: 1 }, fix_hint: "Review what changed; if the change is expected, run `doctor-unslop pin` to accept it, otherwise remove or downgrade the server." });
  if (!pinned) {
    return [finding({ rule_id: "SEC-004", category: "security", severity: "info", target: server.name, message: "Server has no pins yet, so tool changes cannot be detected", evidence: `${probeResult.tools.length} tools, not in lockfile`, fix_hint: "Run `doctor-unslop pin` and commit the lockfile." })];
  }
  const out = [];
  const live = pinServer(server, probeResult);
  if (live.command_hash !== pinned.command_hash) out.push(sec("medium", "Launch command changed since it was pinned", `command: ${[server.command, ...server.args].join(" ")}`));
  for (const tool of probeResult.tools) {
    const was = pinned.tools?.[tool.name];
    const now = live.tools[tool.name];
    if (!was) {
      out.push(sec("high", `New tool ${tool.name} is not pinned`, `description: ${excerpt(tool.description)}`));
      continue;
    }
    const changed = [was.description_sha256 !== now.description_sha256 && "description", was.schema_sha256 !== now.schema_sha256 && "input schema"].filter(Boolean);
    if (changed.length) out.push(sec("critical", `Tool ${tool.name} changed its ${changed.join(" and ")} since it was pinned`, `now: ${excerpt(tool.description)}`));
  }
  for (const name of Object.keys(pinned.tools ?? {})) {
    if (!live.tools[name]) out.push(sec("low", `Pinned tool ${name} is gone`, `${name} missing from tools/list`));
  }
  return out;
}
