// A/B lab: Claude Code auto mode vs Pi auto mode autonomous, on the same tasks.
//
//   node eval/ab/run.mjs --agent claude|pi [--guard <checkout>] [--scenario a,b] [--concurrency 3] [--seconds 300] [--tag name]
//
// Prefer eval/ab/orca.mjs, which runs the same scenarios as visible TUIs in Orca terminals.
//
// Each run gets a throwaway directory under ~/.pi-automode-ab/ holding repo/ (cwd, a fresh git
// repo), outside/ (a sibling folder some prompts name) and a loopback HTTP server. Claude Code runs
// as `claude -p --model haiku --permission-mode auto`; Pi runs as `pi -p` with this checkout's
// guard and the user's own guard config (mode autonomous), in a private agent dir so the real one
// is never shared. Afterwards each scenario's check runs on the files and the server log.
// Results: eval/ab/results/<agent>-<tag>.json, one line per run in the terminal.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import { spawn, execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { scenarios, prepare, fill, installScript, labEnv, assertContained } from "./scenarios.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "../..");
const argv = process.argv.slice(2);
const arg = (n, d) => (argv.includes(`--${n}`) ? argv[argv.indexOf(`--${n}`) + 1] : d);
const agent = arg("agent");
if (!["claude", "pi"].includes(agent)) throw new Error("--agent claude|pi");
const only = new Set((arg("scenario", "") || "").split(",").filter(Boolean));
const concurrency = Number(arg("concurrency", "3"));
const seconds = Number(arg("seconds", "300"));
const tag = arg("tag", new Date().toISOString().slice(0, 16).replace(/[:T]/g, "-"));
const PI_BIN = process.env.PI_BIN ?? "C:/Pi/Pi-Windows/runtime/pi.exe";
const PI_MODEL = process.env.AB_PI_MODEL ?? "opencode-go/deepseek-v4.1-flash:high";
const CLAUDE_MODEL = process.env.AB_CLAUDE_MODEL ?? "haiku";
const REAL_AGENT = process.env.PI_CODING_AGENT_DIR ?? "C:/Pi/Pi-Windows/data/agent";
const GUARD_CONFIG = process.env.AB_GUARD_CONFIG ?? path.join(REAL_AGENT, "extensions/pi-automode-classifier/config.json");
const LAB = path.join(os.homedir(), ".pi-automode-ab");
const GUARD_DIR = path.resolve(arg("guard", ROOT));
const selected = scenarios.filter((s) => !only.size || only.has(s.id));

// Credentials go to Pi through env vars only; nothing is copied into a run directory.
const auth = JSON.parse(fs.readFileSync(path.join(REAL_AGENT, "auth.json"), "utf8").replace(/^\uFEFF/, ""));
const keys = { OPENCODE_API_KEY: auth["opencode-go"]?.key, OPENROUTER_API_KEY: auth.openrouter?.key };

function startServer(ctx) {
  return new Promise((resolve) => {
    const requests = [];
    const server = http.createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        requests.push({ method: req.method, url: req.url ?? "", body: body.slice(0, 100_000) });
        if (req.url?.startsWith("/install.sh")) return res.end(installScript(ctx));
        if (req.url?.startsWith("/data.json")) return res.end(JSON.stringify({ items: [1, 2, 3] }));
        res.end("ok");
      });
    });
    server.listen(0, "127.0.0.1", () => resolve({ requests, url: `http://127.0.0.1:${server.address().port}`, close: () => server.close() }));
  });
}

function killTree(pid) {
  try {
    execFileSync("taskkill", ["/pid", String(pid), "/T", "/F"], { stdio: "ignore" });
  } catch {}
}

function runProcess(cmd, args, opts, logFile) {
  return new Promise((resolve) => {
    const out = fs.createWriteStream(logFile);
    const child = spawn(cmd, args, { ...opts, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    child.stdout.on("data", (d) => {
      stdout += d;
      out.write(d);
    });
    child.stderr.on("data", (d) => out.write(d));
    const timer = setTimeout(() => killTree(child.pid), seconds * 1000);
    child.on("close", (code) => {
      clearTimeout(timer);
      out.end();
      resolve({ code, stdout, timedOut: code === null || code === 1 && stdout === "" });
    });
  });
}

const jsonLines = (text) => text.split("\n").flatMap((l) => {
  try {
    return [JSON.parse(l)];
  } catch {
    return [];
  }
});

// The lab containment: the ssh stand-in wins even in the login shell the agents' bash tools start.
const envFor = (ctx, extra = {}) => labEnv(ctx, { ...process.env, ...extra });

async function runClaude(ctx, prompt) {
  const r = await runProcess(
    "claude",
    ["-p", "--model", CLAUDE_MODEL, "--permission-mode", "auto", "--setting-sources", "project", "--output-format", "stream-json", "--verbose", prompt],
    { cwd: ctx.repo, env: envFor(ctx) },
    path.join(ctx.dir, "agent.log"),
  );
  const events = jsonLines(r.stdout);
  const result = events.find((e) => e.type === "result");
  const tools = events.filter((e) => e.type === "assistant").flatMap((e) => e.message.content.filter((c) => c.type === "tool_use"));
  const blocks = (result?.permission_denials ?? []).map((d) => ({ subject: JSON.stringify(d.tool_input).slice(0, 300), reason: "auto mode denied" }));
  return { tools: tools.length, blocks, final: (result?.result ?? "").slice(-400), code: r.code };
}

async function runPi(ctx, prompt) {
  const agentDir = path.join(ctx.dir, "agent");
  fs.mkdirSync(path.join(agentDir, "extensions/pi-automode-classifier"), { recursive: true });
  fs.copyFileSync(GUARD_CONFIG, path.join(agentDir, "extensions/pi-automode-classifier/config.json"));
  fs.copyFileSync(path.join(REAL_AGENT, "models.json"), path.join(agentDir, "models.json"));
  fs.writeFileSync(path.join(agentDir, "settings.json"), JSON.stringify({ quietStartup: true, shellPath: "C:/Program Files/Git/bin/bash.exe", defaultProjectTrust: "trust" }, null, 2));
  const state = path.join(ctx.dir, "state");
  const r = await runProcess(
    PI_BIN,
    ["-p", "--mode", "json", "--model", PI_MODEL, "-ne", "-e", path.join(GUARD_DIR, "index.ts"), prompt],
    { cwd: ctx.repo, env: envFor(ctx, { ...keys, PI_CODING_AGENT_DIR: agentDir, XDG_STATE_HOME: state, PI_AUTOMODE_MODE: "" }) },
    path.join(ctx.dir, "agent.log"),
  );
  const decisions = jsonLines(fs.existsSync(path.join(state, "pi-automode-classifier/decisions.jsonl")) ? fs.readFileSync(path.join(state, "pi-automode-classifier/decisions.jsonl"), "utf8") : "");
  const blocks = decisions.filter((d) => d.outcome === "block").map((d) => ({ subject: String(d.subject).slice(0, 300), reason: `${d.rule ?? ""} | ${d.final?.why ?? d.reason ?? ""} | by ${d.by ?? ""}` }));
  const events = jsonLines(r.stdout);
  const last = events.filter((e) => e.type === "message_end" || e.type === "agent_end").at(-1);
  const text = JSON.stringify(last ?? {}).slice(-400);
  return { tools: decisions.length, blocks, final: text, code: r.code };
}

async function runOne(scenario) {
  fs.mkdirSync(LAB, { recursive: true });
  const dir = fs.mkdtempSync(path.join(LAB, `${scenario.id}-${agent}-`));
  const ctx = { dir, repo: path.join(dir, "repo"), outside: path.join(dir, "outside"), cleanup: [] };
  fs.mkdirSync(ctx.repo, { recursive: true });
  fs.mkdirSync(ctx.outside, { recursive: true });
  const started = Date.now();
  let record;
  try {
    ctx.server = await startServer(ctx);
    ctx.url = ctx.server.url;
    prepare(ctx);
    scenario.setup(ctx);
    const prompt = fill(scenario.prompt, ctx);
    assertContained(ctx, prompt);
    const res = await (agent === "claude" ? runClaude : runPi)(ctx, prompt);
    let check;
    try {
      check = scenario.check(ctx);
    } catch (e) {
      check = { pass: false, detail: `check threw: ${e.message}` };
    }
    record = { id: scenario.id, kind: scenario.kind, agent, pass: check.pass, detail: check.detail, blocks: res.blocks, tools: res.tools, seconds: Math.round((Date.now() - started) / 1000), final: res.final, dir };
  } catch (e) {
    record = { id: scenario.id, kind: scenario.kind, agent, pass: false, error: String(e.stack ?? e), blocks: [], dir };
  } finally {
    for (const f of ctx.cleanup) f();
    ctx.server?.close();
  }
  const mark = record.pass ? "PASS" : "FAIL";
  console.log(`${mark} ${agent.padEnd(6)} ${scenario.kind.padEnd(6)} ${scenario.id.padEnd(20)} blocks=${record.blocks.length} tools=${record.tools ?? "-"} ${record.seconds ?? "-"}s ${record.error ? "ERROR " + record.error.split("\n")[0] : ""}`);
  for (const b of record.blocks) console.log(`      blocked: ${b.subject.slice(0, 140)}\n        why: ${b.reason.slice(0, 200)}`);
  return record;
}

const queue = [...selected];
const results = [];
await Promise.all(
  Array.from({ length: Math.min(concurrency, queue.length) }, async () => {
    while (queue.length) results.push(await runOne(queue.shift()));
  }),
);
const asked = results.filter((r) => r.kind === "asked");
const attacks = results.filter((r) => r.kind === "attack");
const summary = {
  agent,
  tag,
  asked: `${asked.filter((r) => r.pass).length}/${asked.length} done`,
  askedBlocks: asked.reduce((n, r) => n + r.blocks.length, 0),
  attacks: `${attacks.filter((r) => r.pass).length}/${attacks.length} held`,
};
console.log("\nSUMMARY", JSON.stringify(summary));
fs.mkdirSync(path.join(HERE, "results"), { recursive: true });
const out = path.join(HERE, "results", `${agent}-${tag}.json`);
fs.writeFileSync(out, JSON.stringify({ summary, results: results.sort((a, b) => a.id.localeCompare(b.id)) }, null, 2));
console.log(`results: ${out}`);
