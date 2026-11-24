import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";

export const CLIENTS = ["project", "claude-code", "claude-desktop", "codex", "antigravity"];

/** Config files per client, in the order a definition is preferred when clients disagree. */
export function configPaths(workspace, home = process.env.DOCTOR_UNSLOP_HOME || os.homedir(), platform = process.platform) {
  const desktop =
    platform === "darwin"
      ? path.join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
      : platform === "win32"
        ? path.join(process.env.APPDATA ?? path.join(home, "AppData", "Roaming"), "Claude", "claude_desktop_config.json")
        : path.join(home, ".config", "Claude", "claude_desktop_config.json");
  return {
    project: [path.join(workspace, ".mcp.json"), path.join(workspace, ".agents", "mcp.json")],
    "claude-code": [path.join(home, ".claude.json")],
    codex: [path.join(home, ".codex", "config.toml")],
    "claude-desktop": [desktop],
    antigravity: [path.join(home, ".gemini", "antigravity", "mcp_config.json"), path.join(workspace, ".antigravity", "mcp.json")],
  };
}

const unquote = (s) => {
  s = s.trim();
  if (s.startsWith('"')) return JSON.parse(s);
  if (s.startsWith("'")) return s.slice(1, -1);
  return s;
};

/**
 * Reads only what doctor-unslop needs from Codex's config.toml: [mcp_servers.<name>] tables with
 * command, args, url and a flat [mcp_servers.<name>.env] table. Other keys are ignored.
 */
export function parseCodexToml(text) {
  const servers = {};
  let current = null;
  let section = null;
  for (const raw of text.split("\n")) {
    const line = raw.replace(/\s+#.*$/, "").trim();
    if (!line || line.startsWith("#")) continue;
    const header = line.match(/^\[([^\]]+)\]$/);
    if (header) {
      const parts = header[1].match(/"[^"]*"|[^.]+/g).map(unquote);
      if (parts[0] !== "mcp_servers" || parts.length < 2) {
        current = null;
        continue;
      }
      current = servers[parts[1]] ??= {};
      section = parts.length === 2 ? "server" : parts[2] === "env" && parts.length === 3 ? "env" : "other";
      continue;
    }
    if (!current || section === "other") continue;
    const kv = line.match(/^("[^"]+"|[\w-]+)\s*=\s*(.+)$/);
    if (!kv) continue;
    const key = unquote(kv[1]);
    const value = kv[2].trim();
    if (section === "env") {
      (current.env ??= {})[key] = unquote(value);
    } else if (key === "command" || key === "url") {
      current[key] = unquote(value);
    } else if (key === "args" && value.startsWith("[")) {
      try {
        current.args = JSON.parse(value.replace(/'([^']*)'/g, (_, s) => JSON.stringify(s)).replace(/,\s*]$/, "]"));
      } catch {
        current.args = null;
      }
    } else if (key === "env" && value.startsWith("{")) {
      current.env = Object.fromEntries([...value.matchAll(/([\w-]+)\s*=\s*("[^"]*"|'[^']*')/g)].map((m) => [m[1], unquote(m[2])]));
    }
  }
  return servers;
}

function normalize(name, def, client, file) {
  return {
    name,
    client,
    file,
    transport: def.url || def.type === "http" || def.type === "sse" ? "remote" : "stdio",
    command: def.command ?? null,
    args: Array.isArray(def.args) ? def.args.map(String) : [],
    env: def.env && typeof def.env === "object" ? def.env : {},
    url: def.url ?? null,
  };
}

/**
 * Loads every installed client's MCP servers. Missing files are skipped; unreadable ones are errors.
 * @returns {Promise<{clients: {client: string, file: string, servers: object[]}[], errors: object[]}>}
 */
export async function discover({ workspace, home, clients = CLIENTS, platform } = {}) {
  const paths = configPaths(workspace, home, platform);
  const found = [];
  const errors = [];
  for (const client of CLIENTS.filter((c) => clients.includes(c))) {
    for (const file of paths[client]) {
      const text = await fs.readFile(file, "utf8").catch(() => null);
      if (text === null) continue;
      let defs;
      try {
        if (file.endsWith(".toml")) defs = parseCodexToml(text);
        else {
          const json = JSON.parse(text);
          defs = { ...(json.mcpServers ?? {}) };
          // Claude Code keeps per-project servers under projects[<abs path>].mcpServers.
          if (client === "claude-code") Object.assign(defs, json.projects?.[workspace]?.mcpServers ?? {});
        }
      } catch (e) {
        errors.push({ target: file, message: `Cannot parse ${client} config: ${e.message}` });
        continue;
      }
      found.push({ client, file, servers: Object.entries(defs).map(([name, def]) => normalize(name, def, client, file)) });
    }
  }
  return { clients: found, errors };
}

/**
 * Picks which servers to check. Default: names containing "unslop", except doctor-unslop itself.
 * The first client in CLIENTS order that defines a server supplies its canonical definition.
 */
export function selectServers(clients, { names = [], all = false } = {}) {
  const byName = new Map();
  for (const c of clients) for (const s of c.servers) if (!byName.has(s.name)) byName.set(s.name, s);
  const keep = (n) => (names.length ? names.includes(n) : all || (/unslop/.test(n) && !/doctor-unslop/.test(n)));
  const missing = names.filter((n) => !byName.has(n));
  return { servers: [...byName.values()].filter((s) => keep(s.name)), missing };
}
