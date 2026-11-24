# doctor-unslop

Health checks for the `*-unslop-mcp` servers:

- **Quality:** do the rules catch real slop without flagging clean code, and do the findings follow the shared violation contract?
- **Loops:** which rules keep coding agents stuck in fix-verify loops?
- **Fleet:** do the servers start cleanly, did a tool change since you reviewed it, and do your AI clients agree on the config?

It runs as a CLI and as a read-only MCP server.

## Commands

```bash
doctor-unslop init               # create .doctor-unslop/ and turn on telemetry
doctor-unslop scan               # every check
doctor-unslop security           # SEC-004 pins, SEC-005 injection patterns, SEC-008 unpinned npx packages
doctor-unslop stdio [server...]  # handshake, stdout pollution, cold-start latency
doctor-unslop parity             # config drift and dead binary paths across clients
doctor-unslop tokens             # estimated tool-schema context cost
doctor-unslop conflicts          # tool names registered by more than one server
doctor-unslop bench [server...]  # score fixture suites
doctor-unslop loops              # analyze retry telemetry
doctor-unslop pin [server...]    # write tool hashes to .doctor-unslop.lock.json
doctor-unslop serve              # read-only MCP server over stdio
```

Common options:

- `--format pretty|json|sarif`
- `--fail-on <severity>`
- `--servers a,b` (default: every configured server whose name contains `unslop`)
- `--all-servers`
- `--clients claude-code,codex,...`
- `--lockfile`, `--fixtures`, `--telemetry-log`
- `--timeout`, `--token-budget`

Run `doctor-unslop --help` for all options and their defaults.

Exit codes: `0` healthy, `1` a finding at or above `--fail-on`, `2` a critical finding (such as a tampered tool), `3` a runtime or config error.

## Where servers come from

| Client | Files read |
|---|---|
| project | `./.mcp.json`, `./.agents/mcp.json` |
| claude-code | `~/.claude.json` (top-level servers and `projects[<workspace>]`) |
| codex | `~/.codex/config.toml` (`[mcp_servers.*]`: command, args, env) |
| claude-desktop | `claude_desktop_config.json` in the OS app-support folder |
| antigravity | `~/.gemini/antigravity/mcp_config.json`, `./.antigravity/mcp.json` |

When clients disagree, the first client in this table supplies the definition that is probed.

Probes start each server with only `PATH`, `HOME`, `TMPDIR` and `LANG` from your environment, plus the `env` block from that server's own config entry. They time out after 5 s. Servers launched with `npx` may download from the registry. Remote (HTTP/SSE) servers are skipped.

## Pinning

`doctor-unslop pin` hashes each tool's description and input schema and writes the hashes to `.doctor-unslop.lock.json`. Keys are sorted before hashing, so reordering keys or reformatting never counts as a change. Commit the lockfile. After that, `security` reports:

| Change | Severity |
|---|---|
| A pinned tool's description or schema changed | critical (exit 2) |
| A new tool appeared | high |
| The launch command changed | medium |
| A pinned tool disappeared | low |

If a change is expected, such as your own release, review it and run `pin` again.

## MCP mode

`doctor-unslop serve` exposes three tools, about 450 estimated tokens in total:

- `doctor_scan`
- `doctor_inspect_stdio`
- `doctor_verify_pins`

They never write files. `pin` and `init` exist only in the CLI, so a prompt-injected agent cannot use doctor-unslop to accept a tampered tool.

## Fixture suites

One directory per server under `.doctor-unslop/fixtures/<server>/`:

```json
{
  "server": "frontend-unslop",
  "command": ["node", "../../../frontend-unslop/src/server.mjs"],
  "cases": [
    { "file": "clean/pricing-table.tsx", "kind": "clean", "expected_rules": [] },
    { "file": "slop/gradient-hero.tsx", "kind": "slop", "expected_rules": ["NO_AI_PURPLE_GRADIENT", "DEAD_LINK"] }
  ]
}
```

`bench` runs `<command> audit <files> --json` with the suite directory as cwd, using the same stripped environment as probes. Paths in `command` that start with `./` or `../` are resolved against that directory.

Scoring, per fixture file:

- A clean case is a **false positive** when it has an `ERROR` finding. `WARN` hits on clean files appear in `per_rule.clean_hits`.
- A slop case is a **true positive** only when every expected rule fired.
- Precision = TP/(TP+FP), recall = TP/(TP+FN), FPR = FP/(FP+TN).

## Rules

| Rule | Severity | Fires when |
|---|---|---|
| `SEC-004` | critical–low | Live tools differ from the lockfile (see Pinning); info when nothing is pinned yet |
| `SEC-005` | high | A tool's description or schema contains injection patterns: instruction overrides, "don't tell the user", pseudo-system tags, exfiltration URLs, credential paths, hidden Unicode |
| `SEC-008` | low | Servers run through `npx` without a fixed version (one fleet-level finding) |
| `PROTO-001` | high | Non-JSON-RPC output on stdout |
| `PROTO-002` | medium | `initialize` + `tools/list` takes more than 2000 ms |
| `PROTO-003` | medium | A finding lacks `rule_id`, `severity`, `file`, `line` ≥ 1, or a `fix_hint` of at most 200 chars |
| `PROTO-004` | low | A rule's `fix_hint` only repeats its message |
| `PROTO-005` | high | The server fails the stdio handshake (info for skipped remote servers) |
| `CFG-001` | medium / high | One finding per client that lacks a server or launches it differently; high for an absolute command path that does not exist |
| `TOK-001` | medium | A tool costs more than 400 estimated tokens, or the fleet exceeds `--token-budget` |
| `CONF-001` | medium | Two or more servers register the same tool name |
| `QUAL-001` | high | FPR on clean fixtures is above `--max-fpr` (needs 5+ clean cases) |
| `QUAL-002` | medium | Recall on slop fixtures is below `--min-recall` (needs 5+ slop cases) |
| `QUAL-003` | info | The suite is too small to score |
| `LOOP-001` | high | A rule averages more than `--max-retries` audits, or converges below `--min-convergence` (needs 5+ sequences) |
| `LOOP-002` | medium | Fixing rule A brings in rule B, and fixing B brings back A, in 2+ file sequences |
| `LOOP-000` | info | There is no telemetry log yet |

Token counts are estimates (about 4 characters per token), not real tokenizer output.

## Telemetry

Servers on `unslop-core` ≥ 1.1 append one line per audited file to `.doctor-unslop/telemetry.jsonl`, but only when that directory already exists (`doctor-unslop init` creates it). Each line holds a hash of the file's workspace-relative path, the rule IDs that fired, and whether the file passed. Source code, messages and paths are not stored.

One server process counts as one session, because a stdio MCP server is not told the client's session id. A file audited only once in a session is left out of the retry stats: one audit does not show whether the agent fixed the finding or stopped checking.
