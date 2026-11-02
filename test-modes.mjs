// Commands are inert strings. No command under test is executed.
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const agentDir = fs.mkdtempSync(path.join(os.tmpdir(), "pi-guard-mode-test-"));
process.env.PI_CODING_AGENT_DIR = agentDir;
const { default: extension } = await import("./index.ts");
const handlers = {}, commands = {}, shortcuts = {}, status = {};
const api = {
  on: (name, fn) => handlers[name] = fn,
  registerCommand: (name, command) => commands[name] = command,
  registerShortcut: (name, shortcut) => shortcuts[name] = shortcut,
};
const ctx = { cwd: process.cwd(), hasUI: false, ui: { notify() {}, setStatus: (key, value) => status[key] = value } };
try {
  extension(api, { enabled: true, log: false, decider: [] });
  await handlers.session_start({}, ctx);
  assert.equal(status["pi-mode"], "AUTO");
  const call = () => handlers.tool_call({ toolName: "bash", input: { command: "rm -rf /" } }, ctx);
  assert.equal((await call()).block, true);
  await commands.mode.handler("yolo", ctx);
  assert.equal(status["pi-mode"], "YOLO");
  assert.equal(await call(), undefined);
  await commands.mode.handler("auto", ctx);
  assert.equal((await call()).block, true);
  await shortcuts["alt+m"].handler(ctx);
  assert.equal(status["pi-mode"], "YOLO");
  await handlers.session_start({}, ctx);
  assert.equal(status["pi-mode"], "AUTO");
  await commands["automode-classifier"].handler("off", ctx);
  assert.equal(status["pi-mode"], "YOLO");
  await commands["automode-classifier"].handler("on", ctx);
  assert.equal(status["pi-mode"], "AUTO");
  assert.equal((await call()).block, true);
  const fresh = {};
  extension({ on: (name, fn) => fresh[name] = fn, registerCommand() {} }, { enabled: true, log: false, decider: [] });
  assert.equal((await fresh.tool_call({ toolName: "bash", input: { command: "rm -rf /" } }, ctx)).block, true);
  console.log("Auto/YOLO switching, legacy controls, shortcut, and session reset passed (11 assertions).");
} finally {
  fs.rmSync(agentDir, { recursive: true, force: true });
}
