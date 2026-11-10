// Starts one interactive agent TUI for an A/B run, inside an Orca terminal, so the user can watch.
//
//   node eval/ab/launch.mjs <run dir>
//
// <run dir>/launch.json says which agent and arguments. The environment gets the lab containment
// (labEnv: the ssh stand-in wins even in a login shell) and, for Pi, its provider keys, read from
// Pi's auth.json here and never written anywhere.
import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { labEnv } from "./scenarios.mjs";

const dir = path.resolve(process.argv[2]);
const spec = JSON.parse(fs.readFileSync(path.join(dir, "launch.json"), "utf8"));
const env = labEnv({ bin: path.join(dir, "bin") }, { ...process.env, ...spec.env });
if (spec.agent === "pi") {
  const auth = JSON.parse(fs.readFileSync(path.join(spec.realAgentDir, "auth.json"), "utf8").replace(/^﻿/, ""));
  env.OPENCODE_API_KEY = auth["opencode-go"]?.key;
  env.OPENROUTER_API_KEY = auth.openrouter?.key;
}
delete env.PI_AUTOMODE_MODE;
process.stdout.write(`\x1b]0;${spec.title}\x07`);
const child = spawn(spec.cmd, spec.args, { cwd: path.join(dir, "repo"), env, stdio: "inherit" });
fs.writeFileSync(path.join(dir, "agent.pid"), String(child.pid));
// When the agent exits, this process stays and swallows input, so the terminal never drops back to
// a shell where a late prompt could run as a command. The orchestrator sees `exited` and stops.
child.on("exit", (code) => {
  fs.writeFileSync(path.join(dir, "exited"), String(code));
  process.stdout.write(`\r\n[lab] agent exited (${code}). This terminal ignores input; close it when done.\r\n`);
  process.stdin.on("data", () => {});
  setInterval(() => {}, 1 << 30);
});
