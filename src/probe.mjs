import { spawn } from "node:child_process";

// Only these variables reach a probed server, plus the env block from its own config entry.
export const ENV_ALLOW = ["PATH", "HOME", "TMPDIR", "LANG", "SystemRoot", "USERPROFILE", "APPDATA"];
export const PROTOCOL_VERSION = "2025-06-18";

export const probeEnv = (extra = {}) => ({
  ...Object.fromEntries(ENV_ALLOW.filter((k) => process.env[k] !== undefined).map((k) => [k, process.env[k]])),
  ...extra,
});

/** Masks long token-like runs so stdout noise can be shown without leaking a secret. */
export const redact = (s) => s.replace(/[A-Za-z0-9_\-+/]{24,}={0,2}/g, (m) => `${m.slice(0, 4)}…[${m.length}]`);

/**
 * Starts an MCP server over stdio, runs initialize + tools/list (all pages), then stops it.
 * Never throws; failures come back in `error`.
 */
export function probe(server, { timeout = 5000, cwd = process.cwd() } = {}) {
  return new Promise((resolve) => {
    const started = Date.now();
    const result = { name: server.name, ok: false, cold_start_ms: null, list_ms: null, tools: [], noise: [], server_info: null, error: null, stderr: "" };
    let child;
    try {
      child = spawn(server.command, server.args, { cwd, env: probeEnv(server.env), stdio: ["pipe", "pipe", "pipe"] });
    } catch (e) {
      result.error = `spawn failed: ${e.message}`;
      return resolve(result);
    }
    let buf = "";
    let nextId = 0;
    const pending = new Map();
    let done = false;

    const finish = (error = null) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      if (error) result.error = error;
      result.ok = !result.error;
      child.stdin.end();
      child.kill("SIGTERM");
      setTimeout(() => child.kill("SIGKILL"), 500).unref();
      result.stderr = redact(result.stderr.slice(-400));
      resolve(result);
    };
    const timer = setTimeout(() => finish(`no response within ${timeout}ms (${pending.size ? "waiting for " + [...pending.values()].map((p) => p.method).join(", ") : "startup"})`), timeout);

    const send = (method, params) =>
      new Promise((res, rej) => {
        const id = ++nextId;
        pending.set(id, { method, res, rej });
        child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
      });

    child.stdout.on("data", (d) => {
      buf += d;
      let i;
      while ((i = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, i).replace(/\r$/, "");
        buf = buf.slice(i + 1);
        if (!line.trim()) continue;
        let msg;
        try {
          msg = JSON.parse(line);
        } catch {
          msg = null;
        }
        if (!msg || msg.jsonrpc !== "2.0") {
          if (result.noise.length < 5) result.noise.push(redact(line.slice(0, 120)));
          continue;
        }
        const p = pending.get(msg.id);
        if (!p) continue;
        pending.delete(msg.id);
        msg.error ? p.rej(new Error(`${p.method}: ${msg.error.message}`)) : p.res(msg.result);
      }
    });
    child.stderr.on("data", (d) => {
      result.stderr = (result.stderr + d).slice(-2000);
    });
    child.stdin.on("error", () => {}); // EPIPE when the server dies first; the close handler reports it
    child.on("error", (e) => finish(`spawn failed: ${e.message}`));
    child.on("close", (code, signal) => finish(`server exited (${signal ?? `code ${code}`}) before the handshake finished`));

    (async () => {
      const init = await send("initialize", { protocolVersion: PROTOCOL_VERSION, capabilities: {}, clientInfo: { name: "doctor-unslop", version: "0.1.0" } });
      result.cold_start_ms = Date.now() - started;
      result.server_info = init?.serverInfo ?? null;
      child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
      const listStart = Date.now();
      let cursor;
      do {
        const page = await send("tools/list", cursor ? { cursor } : {});
        result.tools.push(...(page?.tools ?? []));
        cursor = page?.nextCursor;
      } while (cursor);
      result.list_ms = Date.now() - listStart;
      finish();
    })().catch((e) => finish(e.message));
  });
}
