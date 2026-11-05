// Commands are inert strings. No command under test is executed.
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const agentDir = fs.mkdtempSync(path.join(os.tmpdir(), "pi-guard-mode-test-"));
process.env.PI_CODING_AGENT_DIR = agentDir;
delete process.env.PI_AUTOMODE_MODE;
const { default: extension } = await import("./index.ts");
const handlers = {}, commands = {}, shortcuts = {}, status = {};
const api = {
  on: (name, fn) => handlers[name] = fn,
  registerCommand: (name, command) => commands[name] = command,
  registerShortcut: (name, shortcut) => shortcuts[name] = shortcut,
};
const ctx = { cwd: process.cwd(), hasUI: false, ui: { notify() {}, setStatus: (key, value) => status[key] = value } };
const fresh = (overrides = {}) => {
  const h = {};
  extension({ on: (name, fn) => h[name] = fn, registerCommand() {} }, { log: false, decider: [], ...overrides });
  return h;
};
try {
  extension(api, { enabled: true, log: false, decider: [] });
  await handlers.session_start({}, ctx);
  assert.equal(status["pi-mode"], "AUTO SAFE");
  assert.equal(process.env.PI_AUTOMODE_MODE, "safe");
  const call = () => handlers.tool_call({ toolName: "bash", input: { command: "rm -rf /" } }, ctx);
  assert.equal((await call()).block, true);

  await commands.mode.handler("yolo", ctx);
  assert.equal(status["pi-mode"], "YOLO");
  assert.equal(process.env.PI_AUTOMODE_MODE, undefined, "a child of yolo does not inherit yolo");
  assert.equal(await call(), undefined);

  await commands.mode.handler("auto", ctx);
  assert.equal(status["pi-mode"], "AUTO SAFE", "/mode auto is an alias of safe");
  assert.equal((await call()).block, true);

  await commands.mode.handler("autonomous", ctx);
  assert.equal(status["pi-mode"], "AUTONOMOUS");
  assert.equal(process.env.PI_AUTOMODE_MODE, "autonomous");
  assert.equal((await call()).block, true);

  // Alt+M cycles safe, autonomous, yolo.
  await shortcuts["alt+m"].handler(ctx);
  assert.equal(status["pi-mode"], "YOLO");
  await shortcuts["alt+m"].handler(ctx);
  assert.equal(status["pi-mode"], "AUTO SAFE");
  await shortcuts["alt+m"].handler(ctx);
  assert.equal(status["pi-mode"], "AUTONOMOUS");

  // A new session restores the configured mode.
  await handlers.session_start({}, ctx);
  assert.equal(status["pi-mode"], "AUTO SAFE");

  await commands["automode-classifier"].handler("off", ctx);
  assert.equal(status["pi-mode"], "YOLO");
  await commands["automode-classifier"].handler("on", ctx);
  assert.equal(status["pi-mode"], "AUTO SAFE");
  assert.ok(commands.automode, "/automode is the short name");
  assert.equal((await call()).block, true);

  // Starting state.
  assert.equal((await fresh().tool_call({ toolName: "bash", input: { command: "rm -rf /" } }, ctx)).block, true);
  const started = {};
  extension({ on: (n, f) => started[n] = f, registerCommand() {} }, { log: false, decider: [], enabled: false, mode: "yolo" });
  assert.equal(await started.tool_call({ toolName: "bash", input: { command: "rm -rf /" } }, ctx), undefined);

  // A child Pi inherits safe or autonomous, and never yolo.
  process.env.PI_AUTOMODE_MODE = "autonomous";
  const child = {}, childStatus = {};
  extension({ on: (n, f) => child[n] = f, registerCommand() {} }, { log: false, decider: [] });
  await child.session_start({}, { ...ctx, ui: { notify() {}, setStatus: (k, v) => childStatus[k] = v } });
  assert.equal(childStatus["pi-mode"], "AUTONOMOUS");
  process.env.PI_AUTOMODE_MODE = "yolo";
  const child2 = {}, child2Status = {};
  extension({ on: (n, f) => child2[n] = f, registerCommand() {} }, { log: false, decider: [] });
  await child2.session_start({}, { ...ctx, ui: { notify() {}, setStatus: (k, v) => child2Status[k] = v } });
  assert.equal(child2Status["pi-mode"], "AUTO SAFE", "yolo in the environment is ignored");
  delete process.env.PI_AUTOMODE_MODE;

  // Autonomous with no decider at all still never prompts.
  const none = fresh({ mode: "autonomous" });
  let prompted = 0;
  const uiCtx = { ...ctx, hasUI: true, ui: { notify() {}, setStatus() {}, select: async () => (prompted++, "Allow once"), confirm: async () => (prompted++, true) } };
  const asked = await none.tool_call({ toolName: "bash", input: { command: "git push origin main" } }, uiCtx);
  assert.equal(asked.block, true);
  assert.equal(prompted, 0, "autonomous never calls a prompt");
  assert.match(asked.reason, /Blocked/);
  // Safe with no decider prompts, as before.
  const safeNone = fresh({ mode: "safe" });
  await safeNone.tool_call({ toolName: "bash", input: { command: "git push origin main" } }, uiCtx);
  assert.equal(prompted, 1);

  // Agent guidance follows the mode, and does not pile up.
  const guided = {};
  extension({ on: (n, f) => guided[n] = f, registerCommand() {} }, { log: false, decider: [], mode: "autonomous" });
  const options = { promptGuidelines: ["keep me"] };
  await guided.before_agent_start({ systemPromptOptions: options }, ctx);
  assert.ok(options.promptGuidelines.includes("keep me"));
  const n = options.promptGuidelines.length;
  assert.ok(options.promptGuidelines.some((g) => g.includes("unattended")));
  await guided.before_agent_start({ systemPromptOptions: options }, ctx);
  assert.equal(options.promptGuidelines.length, n);

  console.log("Modes, aliases, cycling, inheritance, session reset, no prompts in autonomous and agent guidance passed.");
} finally {
  delete process.env.PI_AUTOMODE_MODE;
  fs.rmSync(agentDir, { recursive: true, force: true });
}
