import fs from "node:fs";
import path from "node:path";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { runChecks, CATEGORIES } from "./engine.mjs";

// Read-only by design: no tool writes a file. Pinning, init and any future patch apply stay in the CLI,
// so a prompt-injected agent cannot use this server to accept a tampered tool or rewrite a config.

const workspaceProp = { type: "string", description: "Absolute workspace path. Defaults to the server's cwd." };
const serversProp = { type: "array", items: { type: "string" }, description: "MCP server names. Defaults to names containing \"unslop\"." };

export const TOOLS = [
  {
    name: "doctor_scan",
    description: "Read-only health check of the unslop MCP fleet: security, protocol, parity, tokens, conflicts, fixture quality and retry loops. Starts each server briefly to read its tools.",
    inputSchema: {
      type: "object",
      properties: {
        workspace_path: workspaceProp,
        categories: { type: "array", items: { type: "string", enum: CATEGORIES }, description: "Defaults to all." },
        server_names: serversProp,
        min_severity: { type: "string", enum: ["critical", "high", "medium", "low", "info"], default: "low" },
      },
      additionalProperties: false,
    },
  },
  {
    name: "doctor_inspect_stdio",
    description: "Start one MCP server over stdio and report its handshake, cold-start latency, stdout pollution and tool count.",
    inputSchema: {
      type: "object",
      properties: { server_name: { type: "string" }, workspace_path: workspaceProp, timeout_ms: { type: "integer", minimum: 500, maximum: 30000, default: 5000 } },
      required: ["server_name"],
      additionalProperties: false,
    },
  },
  {
    name: "doctor_verify_pins",
    description: "Compare live tool names, descriptions and schemas against .doctor-unslop.lock.json to detect silent changes. Accepting a change needs the CLI: doctor-unslop pin.",
    inputSchema: { type: "object", properties: { workspace_path: workspaceProp, server_names: serversProp }, additionalProperties: false },
  },
];

const RANK = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

function workspaceOf(args) {
  const ws = args.workspace_path ?? process.cwd();
  if (!path.isAbsolute(ws) || !fs.existsSync(ws) || !fs.statSync(ws).isDirectory()) throw new Error(`workspace_path must be an existing absolute directory: ${ws}`);
  return ws;
}

/** Handles one tool call. Exported for tests. */
export async function callTool(name, args = {}) {
  const workspace = workspaceOf(args);
  if (name === "doctor_scan") {
    const bad = (args.categories ?? []).filter((c) => !CATEGORIES.includes(c));
    if (bad.length) throw new Error(`Unknown categories: ${bad.join(", ")}`);
    const { report } = await runChecks({ workspace, categories: args.categories?.length ? args.categories : CATEGORIES, servers: args.server_names ?? [] });
    const min = RANK[args.min_severity ?? "low"];
    return { ...report, findings: report.findings.filter((f) => RANK[f.severity] >= min) };
  }
  if (name === "doctor_inspect_stdio") {
    if (typeof args.server_name !== "string" || !args.server_name) throw new Error("server_name is required.");
    const { report } = await runChecks({ workspace, categories: ["protocol"], servers: [args.server_name], timeout: args.timeout_ms ?? 5000 });
    return { server: report.servers?.[0] ?? null, findings: report.findings, ...(report.errors ? { errors: report.errors } : {}) };
  }
  if (name === "doctor_verify_pins") {
    const { report } = await runChecks({ workspace, categories: ["security"], servers: args.server_names ?? [] });
    return { summary: report.summary, findings: report.findings.filter((f) => f.rule_id === "SEC-004"), ...(report.errors ? { errors: report.errors } : {}) };
  }
  throw new Error(`Unknown tool: ${name}`);
}

export async function serve({ version }) {
  const server = new Server({ name: "doctor-unslop", version }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));
  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    try {
      const out = await callTool(req.params.name, req.params.arguments ?? {});
      const failed = out.summary?.status === "fail" || out.errors?.length;
      return { content: [{ type: "text", text: JSON.stringify(out) }], isError: Boolean(failed) };
    } catch (e) {
      return { content: [{ type: "text", text: JSON.stringify({ error: e.message }) }], isError: true };
    }
  });
  await server.connect(new StdioServerTransport());
}
