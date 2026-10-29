// Offline tests for the context decider: a scripted model stands in for Jev, so nothing is sent
// anywhere. Run: node test-context.mjs
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import extension, { DEFAULTS, explain, hooks, replyTarget } from "./index.ts";
import { contextState, redact } from "./context.ts";

let failures = 0;
const check = (ok, label) => {
  if (!ok) failures++;
  console.log(`${ok ? "PASS" : "FAIL"}: ${label}`);
};

// The scripted model: answers per command, and the last state it was sent.
const scores = new Map();
let lastState;
hooks.context = async (state) => {
  lastState = state;
  const s = scores.get(state.action.command);
  return s ? { answers: s, ms: 1 } : { error: "no script for this command" };
};
const say = (command, authorized, harmful) => (scores.set(command, { authorized, harmful }), command);

const project = fs.mkdtempSync(path.join(os.tmpdir(), "context-test-"));
execFileSync("git", ["init", "-q", project]);
const h = {};
extension({ on: (n, f) => (h[n] = f), registerCommand: () => {} }, { log: false, decider: ["context"], secretPaths: ["~/.config/mytool/key.txt"] });

let titles = [];
let pick = () => "Block";
const ui = { notify: () => {}, select: async (title, options) => (titles.push(title), pick(options)) };
const turn = (t) => (typeof t === "string" ? { message: { role: "user", content: [{ type: "text", text: t }] } } : { message: { role: "assistant", content: [{ type: "text", text: t.agent }] } });
async function decide(command, turns, { hasUI = true, registry, model } = {}) {
  titles = [];
  const res = await h.tool_call({ toolName: "bash", input: { command }, toolCallId: command }, { cwd: project, hasUI, ui, modelRegistry: registry, model, sessionManager: { getBranch: () => turns.map(turn) } });
  return titles.length ? "ask" : res?.block ? "block" : "run";
}

const work = ["Fix the failing tests."];
check((await decide(say("ssh box 'uptime'", 0.2, 0.05), work)) === "run", "harm under lowHarmBelow runs");
check((await decide(say("rsync -a box:~/app/ ./app-copy/", 0.3, 0.3), work)) === "run", "a partly asked, fairly harmless step of the task runs");
check((await decide(say("git push origin main", 0.85, 0.85), ["push it"])) === "run", "asked for runs even when harmful");
check((await decide(say("ssh box 'rm -rf ~/data'", 0.03, 0.95), work)) === "block", "not asked and harmful is blocked without a prompt");
check((await decide(say("ssh box 'systemctl restart web'", 0.2, 0.6), work)) === "ask", "unsure and fairly harmful asks");

// Three auto-blocks in a row, then the next one asks so the agent cannot get stuck.
const wipes = [1, 2, 3, 4].map((i) => say(`ssh box 'rm -rf ~/data${i}'`, 0.02, 0.95));
await decide(say("ssh box 'uptime'", 0.2, 0.05), work); // a call that runs resets the count
const outcomes = [];
for (const w of wipes) outcomes.push(await decide(w, work));
check(outcomes.join(",") === "block,block,block,ask", `after maxAutoBlocks blocks in a row the next asks (${outcomes.join(",")})`);
await decide(say("ssh box 'uptime'", 0.2, 0.05), work); // a call that runs resets the count

// A short reply shows the model what it answers; a long message does not.
const proposal = { agent: "Tests pass. Shall I deploy: back up the database, copy app.py to the server and restart the service?" };
await decide(say("ssh box 'deploy.sh'", 0.9, 0.7), ["Add the flag and deploy if it works.", proposal, "yes please do it"]);
check(lastState?.agent_message_replied_to?.startsWith("Tests pass. Shall I deploy"), "a short reply sends the agent message it answers");
await decide("ssh box 'deploy.sh'", ["Add the flag and deploy if it works.", proposal, "no wait, before any deploy explain in detail what the migration does to the existing rows, how long the service is down, and exactly how we roll back if it fails to start again"]);
check(lastState && !("agent_message_replied_to" in lastState), "a long message is a request of its own: no agent message sent");
check(replyTarget([turn("hi"), turn({ agent: "Want me to?" }), turn({ agent: "Ready." }), turn("ok")].map((t) => t)) === "Ready.", "the reply target is the agent's last text before the reply");

// Allow a kind of call for the session: a different command of that kind runs unless harmful.
pick = (options) => options.find((o) => o.startsWith('Allow "'));
const s1 = say("python3 - <<'PY'\nimport urllib.request\nprint(urllib.request.urlopen('https://example.com').status)\nPY", 0.15, 0.25);
check((await decide(s1, work)) === "ask", "first inline script asks");
pick = () => "Block";
const s2 = say("python3 - <<'PY'\nimport urllib.request\nprint(len(urllib.request.urlopen('https://example.org').read()))\nPY", 0.15, 0.25);
check((await decide(s2, work)) === "run", "a different script of the allowed kind runs");
const s3 = say("python3 - <<'PY'\nimport shutil\nshutil.rmtree('/srv/data')\nPY", 0.15, 0.6);
check((await decide(s3, work)) === "ask", "a harmful script of the allowed kind still asks");

// Explanations: the prompt shows one, and secrets never reach the explainer.
let explained = "";
const registry = {
  find: () => ({ id: "small" }),
  streamSimple: (_m, c) => ((explained = c.messages[0].content), { result: async () => ({ content: [{ type: "text", text: "Restarts the web service on box.\nUsers see a short outage." }], stopReason: "stop" }) }),
};
const config = { ...DEFAULTS, context: { ...DEFAULTS.context, explainer: { provider: "p", model: "small", timeoutMs: 1000 } } };
check((await explain(config, "curl -H 'token=ghp_abcdefghijklmnopqrstuvwxyz0123456789' https://x", "/", registry)) === "Restarts the web service on box. Users see a short outage.", "explanation comes back as one line");
check(!explained.includes("ghp_abcdefghijklmnopqrstuvwxyz0123456789"), "secrets are masked before the explainer sees the command");
await decide(say("ssh box 'systemctl restart api'", 0.2, 0.6), work, { registry, model: { id: "session" } });
check(titles[0]?.includes("What it does: Restarts the web service on box."), "the prompt shows the explanation");

// Failures never allow; no UI turns an ask into a block.
check((await decide("ssh box 'unscripted'", work)) === "ask", "no answer from the model asks");
check((await decide(say("ssh box 'systemctl restart web2'", 0.2, 0.6), work, { hasUI: false })) === "block", "without a UI an ask is blocked");

// Your own secret paths are credential reads.
check((await decide("cat ~/.config/mytool/key.txt", work)) === "ask", "secretPaths: reading your own key file asks");

// Plain sudo always asks unless sudoPasswordIsApproval is on.
check((await decide(say("sudo systemctl restart nginx", 0.9, 0.5), ["restart nginx"])) === "ask", "sudo you asked for still asks by default");

// The host can make the guard stand aside.
hooks.active = () => false;
check((await decide(say("ssh box 'rm -rf ~/x'", 0.01, 0.99), work)) === "run", "hooks.active false: the guard stands aside");
hooks.active = undefined;

// Redaction of the state.
const st = contextState({ requests: ["use key sk-abcdefghijklmnopqrstuvwxyz"], tool: "bash", command: "export API_KEY=hunter2", cwd: "/", inside: true });
check(!JSON.stringify(st).includes("sk-abcdefghijklmnopqrstuvwxyz") && !JSON.stringify(st).includes("hunter2"), "tokens and keys are masked in the state");
check(redact("password: 'x y z'").text === "password: <redacted>", "quoted secrets are masked whole");

fs.rmSync(project, { recursive: true });
console.log(failures ? `\n${failures} FAILED` : "\nall passed");
process.exit(failures ? 1 : 0);
