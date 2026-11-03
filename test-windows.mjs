// Commands are inert strings. These tests never execute destructive operations.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { bashVerdict, fileVerdict, makeScope, readVerdict } from "./rules.ts";
// Keep the run out of the user's real decisions log; the guard reads this when it loads.
process.env.XDG_STATE_HOME = fs.mkdtempSync(path.join(os.tmpdir(), "pi-automode-classifier-state-"));
// Outside Pi there is no agent directory; any scratch one exercises the same paths.
process.env.PI_CODING_AGENT_DIR ??= fs.mkdtempSync(path.join(os.tmpdir(), "pi-automode-classifier-agent-"));
const { default: extension, loadConfig } = await import("./index.ts");

assert.equal(process.platform, "win32", "Run this regression suite on Windows");
const project = path.join(os.homedir(), "Documents", "pi-windows-test-project");
const scope = () => makeScope(project, [import.meta.dirname]);
let checks = 0;
const check = (actual, expected, label) => { assert.equal(actual, expected, label); checks++; };
for (const target of ["C:/", "/c", "/c/", "/mnt/c", process.env.SystemRoot.replace(/\\/g, "/"), process.env.ProgramFiles.replace(/\\/g, "/")]) {
  check(bashVerdict(`rm -rf '${target}'`, scope()).action, "deny", `protect system path ${target}`);
}
for (const tail of [".aws/credentials", ".ssh/id_ed25519", ".codex/auth.json", ".pi/agent/auth.json"]) {
  const native = path.join(os.homedir(), tail);
  check(readVerdict("read", native, scope())?.action, "ask", `native credential path ${tail}`);
  check(readVerdict("read", native.toUpperCase(), scope())?.action, "ask", `case-insensitive credential path ${tail}`);
  const bashPath = native.replace(/\\/g, "/").replace(/^([a-z]):/i, (_m, d) => `/${d.toLowerCase()}`);
  check(bashVerdict(`cat '${bashPath}'`, scope()).action, "ask", `Git Bash credential path ${tail}`);
}
for (const target of [".pi/settings.json", ".PI/extensions/test.ts", "agents.md", "CLAUDE.MD"]) {
  check(fileVerdict("write", path.join(project, target), scope()).action, "ask", `protect Pi instructions ${target}`);
}
check(bashVerdict("rm -rf .git", scope()).action, "ask", "protect repository metadata");
check(bashVerdict("git status --short", scope()).action, "allow", "routine Git command");
check(fileVerdict("write", path.join(project, "src", "app.ts"), scope()).action, "allow", "routine file edit");
for (const command of ["pwsh -Command 'Remove-Item x'", "powershell.exe -EncodedCommand Zg==", "cmd.exe /c del x"]) {
  check(bashVerdict(command, scope()).critical, true, "review a nested Windows shell");
}
const handlers = {};
extension({ on: (event, fn) => handlers[event] = fn, registerCommand: () => {} }, { log: false, decider: [], withoutUi: { onAsk: "allow", rules: { allow: [], deny: [] } } });
const ctx = { cwd: project, hasUI: false, ui: { notify() {} } };
check((await handlers.tool_call({ toolName: "powershell", input: { command: "Remove-Item x" } }, ctx))?.block, true, "headless PowerShell cannot bypass critical review");
check((await handlers.tool_call({ toolName: "read", input: { path: path.join(process.env.PI_CODING_AGENT_DIR, "auth.json") } }, ctx))?.block, true, "protect a custom Pi auth directory");
let statusCommand;
let status;
extension({ on() {}, registerCommand(_name, command) { statusCommand = command; } }, { log: false, decider: ["context"] });
await statusCommand.handler("status", { ...ctx, ui: { notify(message) { status = message; } } });
const loaded = loadConfig().config;
check(status.includes(`context decider ${loaded.context.provider}/${loaded.context.model}`) && !status.includes("model server"), true, "status describes the context provider accurately");
console.log(`${checks} Windows regression checks passed`);
