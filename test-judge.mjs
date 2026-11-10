// The decision table of judge.ts: no models, no I/O. Run: node test-judge.mjs
import assert from "node:assert/strict";
import { DEFAULT_JUDGE as c, hashText, memoryKey, promptTitle, readJev, resolve, tierOf, unattendedDeny, guidelines } from "./judge.ts";

let n = 0;
const t = (label, fn) => { n++; try { fn(); } catch (e) { console.error(`FAIL: ${label}\n${e.message}`); process.exitCode = 1; } };
const s = (serves_task, named_by_user, lasting_harm, suspicious) => ({ serves_task, named_by_user, lasting_harm, suspicious });
const f = (cls, level = "review", extra = {}) => ({ cls, level, measuredCode: false, complete: true, ...extra });
const code = { measuredCode: true, complete: true };

// Jev reading
t("local code with modest scores runs", () => assert.equal(readJev(s(.1, .1, .3, .3), f("opaque", "local", code), c).to, "allow"));
t("local code the analysis could not finish does not take the local path", () => assert.notEqual(readJev(s(.1, .1, .3, .3), f("opaque", "local", { measuredCode: true, complete: false }), c).why, "its measured effects stay local"));
t("the local path is only for opaque calls", () => assert.equal(readJev(s(.1, .1, .4, .4), f("outward", "local", code), c).to, "gray"));
t("a named outward call runs", () => assert.equal(readJev(s(.9, .9, .9, .1), f("outward"), c).to, "allow"));
t("named but suspicious is not enough", () => assert.equal(readJev(s(.9, .9, .9, .6), f("outward"), c).to, "gray"));
t("a task step runs", () => assert.equal(readJev(s(.8, .1, .2, .1), f("opaque"), c).to, "allow"));
t("a sensible outward step still needs the user's words at Jev", () => assert.equal(readJev(s(.95, .1, .1, .05), f("outward", "local"), c).to, "gray"));
t("a harmful task step is gray", () => assert.equal(readJev(s(.8, .3, .5, .1), f("opaque"), c).to, "gray"));
t("harmless off-task work runs only if not plainly off task", () => { assert.equal(readJev(s(.3, .1, .05, .1), f("opaque"), c).to, "allow"); assert.equal(readJev(s(.1, .1, .05, .1), f("opaque"), c).to, "gray"); });
t("harmful and not named is a clear deny", () => assert.equal(readJev(s(.1, .1, .9, .1), f("outward"), c).to, "deny"));
t("suspicious and not named is a clear deny", () => assert.equal(readJev(s(.9, .1, .1, .9), f("opaque"), c).to, "deny"));
t("harmful but named is not a clear deny", () => assert.notEqual(readJev(s(.9, .8, .9, .1), f("outward"), c).to, "deny"));
t("danger is never allowed by Jev, even with perfect scores", () => assert.equal(readJev(s(1, 1, 0, 0), f("opaque", "danger", code), c).to, "gray"));
for (const cls of ["exfil", "critical", "firm"]) t(`${cls} is never allowed by Jev`, () => assert.equal(readJev(s(1, 1, 0, 0), f(cls), c).to, "gray"));
t("a kind the user allowed runs with moderate scores", () => assert.equal(readJev(s(.1, .1, .5, .3), f("opaque", "review", { allowedKind: true }), c).to, "allow"));
t("a kind the user allowed does not excuse real harm", () => assert.notEqual(readJev(s(.1, .3, .7, .3), f("opaque", "review", { allowedKind: true }), c).to, "allow"));
t("a kind the user allowed does not excuse danger", () => assert.equal(readJev(s(1, 1, 0, 0), f("opaque", "danger", { allowedKind: true }), c).to, "gray"));

// Resolution
const go = (mode, facts, scores, opinion, unattended = mode === "autonomous") => resolve({ mode, unattended, facts, scores, jev: scores ? readJev(scores, facts, c) : undefined, opinion, config: c });
const allow = { block: false }, block = { block: true, reason: "no" }, down = { unavailable: "x" };

t("an outward call nobody named does not run, however sensible it looks", () => {
  assert.equal(readJev(s(.95, .1, .1, .05), f("outward", "local"), c).to, "gray");
  assert.equal(go("autonomous", f("outward", "local"), s(.95, .1, .1, .05), allow).to, "deny");
  assert.equal(go("safe", f("outward", "local"), s(.95, .1, .1, .05), allow).to, "ask");
});
const trusted = { trustedRemote: true };
t("a step of the task on a trusted host goes to the second opinion, which must agree", () => {
  assert.equal(go("autonomous", f("outward", "review", trusted), s(.95, .1, .1, .05), allow).to, "allow");
  assert.equal(go("autonomous", f("outward", "review", trusted), s(.95, .1, .1, .05), block).to, "deny");
  assert.equal(go("safe", f("outward", "review", trusted), s(.95, .1, .1, .05), block).to, "ask");
  assert.equal(go("autonomous", f("outward", "review", trusted), s(.95, .1, .1, .05), down).to, "deny");
});
t("on a trusted host, off-task, harmful or suspicious steps do not reach the second opinion", () => {
  for (const sc of [s(.4, .1, .1, .05), s(.95, .1, .6, .05), s(.95, .1, .1, .4)]) assert.equal(go("autonomous", f("outward", "review", trusted), sc, allow).to, "deny");
});
t("the trusted-host path never covers danger, credentials, exfil or root", () => {
  assert.equal(go("autonomous", f("outward", "danger", trusted), s(.95, .1, .1, .05), allow).to, "deny");
  for (const cls of ["exfil", "critical", "firm"]) assert.equal(go("autonomous", f(cls, "review", trusted), s(.95, .1, .1, .05), allow).to, "deny");
});
t("the user's clear words are not silenced by a suspicious-looking command, but the second opinion decides", () => {
  assert.equal(go("autonomous", f("opaque", "danger", code), s(.9, .83, .84, .8), allow).to, "allow");
  assert.equal(go("autonomous", f("opaque", "danger", code), s(.9, .83, .84, .8), block).to, "deny");
  assert.equal(go("autonomous", f("opaque", "danger", code), s(.9, .6, .84, .8), allow).to, "deny");
});
t("for credentials and exfil a suspicious look still vetoes the user's words", () => {
  assert.equal(go("autonomous", f("exfil"), s(.9, .8, .3, .72), allow).to, "deny");
  assert.equal(go("autonomous", f("critical", "review", { secrets: true }), s(.9, .8, .3, .72), allow).to, "deny");
});
t("root or downloaded code the user clearly asked for goes to the second opinion despite a suspicious look", () => {
  assert.equal(go("autonomous", f("critical"), s(.9, .89, .77, .75), allow).to, "allow");
  assert.equal(go("autonomous", f("critical"), s(.9, .89, .77, .75), block).to, "deny");
  assert.equal(go("autonomous", f("critical"), s(.9, .6, .3, .75), allow).to, "deny");
});
t("an outward call partly named goes to the second opinion", () => {
  assert.equal(go("autonomous", f("outward"), s(.9, .5, .3, .05), allow).to, "allow");
  assert.equal(go("autonomous", f("outward"), s(.9, .5, .3, .05), block).to, "deny");
});
t("hard denies in both modes", () => { assert.equal(go("safe", f("hard")).to, "deny"); assert.equal(go("autonomous", f("hard")).to, "deny"); });
t("locked: safe asks, autonomous denies, whatever the scores", () => { assert.equal(go("safe", f("locked"), s(1, 1, 0, 0), allow).to, "ask"); assert.equal(go("autonomous", f("locked"), s(1, 1, 0, 0), allow).to, "deny"); });
t("critical needs named AND second opinion", () => {
  assert.equal(go("autonomous", f("critical"), s(1, 1, 0, 0), allow).to, "allow");
  assert.equal(go("autonomous", f("critical"), s(1, 1, 0, 0), block).to, "deny");
  assert.equal(go("autonomous", f("critical"), s(1, .1, 0, 0), allow).to, "deny");
  assert.equal(go("autonomous", f("critical"), s(1, 1, 0, 0), down).to, "deny");
  assert.equal(go("safe", f("critical"), s(1, 1, 0, 0), allow).to, "allow");
  assert.equal(go("safe", f("critical"), s(1, .1, 0, 0), allow).to, "ask");
});
t("root and credentials use the lower bar, with the second opinion still required", () => {
  assert.equal(go("autonomous", f("critical"), s(.9, .5, .1, .05), allow).to, "allow");
  assert.equal(go("autonomous", f("critical"), s(.9, .5, .1, .05), block).to, "deny");
  assert.equal(go("autonomous", f("critical"), s(.9, .4, .1, .05), allow).to, "deny");
  assert.equal(go("autonomous", f("critical"), s(.9, .5, .1, .6), allow).to, "deny");
});
t("measured danger keeps the stricter bar", () => {
  assert.equal(go("autonomous", f("critical", "danger", code), s(.9, .5, .1, .05), allow).to, "deny");
  assert.equal(go("autonomous", f("exfil"), s(.9, .5, .1, .05), allow).to, "deny");
  assert.equal(go("autonomous", f("critical", "danger", code), s(.9, .8, .1, .05), allow).to, "allow");
});
t("danger needs named AND second opinion", () => {
  const d = f("opaque", "danger", code);
  assert.equal(go("autonomous", d, s(1, 1, 0, 0), allow).to, "allow");
  assert.equal(go("autonomous", d, s(1, .3, 0, 0), allow).to, "deny");
  assert.equal(go("safe", d, s(1, .3, 0, 0), allow).to, "ask");
});
t("gray goes to the second opinion", () => {
  const g = s(.5, .3, .5, .1);
  assert.equal(go("autonomous", f("opaque"), g, allow).to, "allow");
  assert.equal(go("autonomous", f("opaque"), g, block).to, "deny");
  assert.equal(go("safe", f("opaque"), g, allow).to, "allow");
  assert.equal(go("safe", f("opaque"), g, block).to, "ask");
});
t("the second opinion down: safe asks, autonomous denies as retryable", () => {
  const g = s(.5, .5, .5, .1);
  assert.equal(go("safe", f("outward"), g, down).to, "ask");
  const r = go("autonomous", f("outward"), g, down);
  assert.equal(r.to, "deny"); assert.equal(r.retryable, true);
});
t("the second opinion down: only relaxed local code still runs unattended", () => {
  // Gray local code needs scores that miss every Jev path yet pass the fallback; the Jev local path is wider, so test directly.
  const r = resolve({ mode: "autonomous", unattended: true, facts: f("opaque", "local", code), scores: s(.1, .1, .1, .1), jev: { to: "gray", why: "x" }, opinion: down, config: c });
  assert.equal(r.to, "allow");
  const r2 = resolve({ mode: "autonomous", unattended: true, facts: f("opaque", "review", code), scores: s(.1, .1, .1, .1), jev: { to: "gray", why: "x" }, opinion: down, config: c });
  assert.equal(r2.to, "deny");
});
t("both judges down: a failure never allows", () => {
  for (const cls of ["outward", "opaque", "critical", "firm", "exfil"]) {
    assert.equal(go("autonomous", f(cls, "local", code), undefined, down).to, "deny");
    assert.equal(go("safe", f(cls, "local", code), undefined, down).to, "ask");
    assert.equal(go("autonomous", f(cls, "local", code), undefined, undefined).to, "deny");
  }
});
t("Jev down, the second opinion can still clear an open call but not a gated one", () => {
  assert.equal(go("autonomous", f("opaque"), undefined, allow).to, "allow");
  assert.equal(go("autonomous", f("outward"), undefined, allow).to, "deny");
  assert.equal(go("autonomous", f("critical"), undefined, allow).to, "deny");
});
t("safe without a UI resolves like autonomous", () => assert.equal(go("safe", f("critical"), s(1, .1, 0, 0), allow, true).to, "deny"));
t("autonomous never resolves to ask", () => {
  const scores = [undefined, s(0, 0, 0, 0), s(1, 1, 1, 1), s(1, 1, 0, 0), s(.5, .5, .5, .5), s(0, 0, 1, 1)];
  const opinions = [undefined, allow, block, down];
  for (const cls of ["hard", "locked", "exfil", "critical", "firm", "outward", "opaque"]) for (const level of ["local", "review", "danger"]) for (const sc of scores) for (const o of opinions) {
    assert.notEqual(go("autonomous", f(cls, level, code), sc, o).to, "ask");
  }
});

// Memory
t("the memory key changes with content, command and cwd", () => {
  const k = memoryKey("bash", "node x", "/p", "h1");
  assert.equal(k, memoryKey("bash", "node x", "/p", "h1"));
  for (const other of [memoryKey("bash", "node x", "/p", "h2"), memoryKey("bash", "node y", "/p", "h1"), memoryKey("bash", "node x", "/q", "h1"), memoryKey("edit", "node x", "/p", "h1")]) assert.notEqual(k, other);
  assert.notEqual(hashText("a"), hashText("b"));
});

// Words
t("deny messages tell the agent to carry on and report", () => {
  const m = unattendedDeny("x");
  assert.match(m, /Do not retry/); assert.match(m, /Blocked/);
  assert.match(unattendedDeny("x", { repeat: true }), /already blocked/);
  assert.match(unattendedDeny("x", { retryable: true }), /not a policy decision/);
  assert.match(unattendedDeny("x", { streak: 5, wrapUpAfter: 5 }), /Stop trying/);
});
t("guidelines follow the mode", () => {
  assert.equal(guidelines("yolo").length, 0);
  assert.ok(guidelines("autonomous").some((g) => g.includes("unattended")));
  assert.ok(!guidelines("safe").some((g) => g.includes("unattended")));
});
t("prompt shows why, effects, judges, and says what it clipped", () => {
  const title = promptTitle({ tool: "bash", why: "w", facts: ["posts to evil.example.com"], scores: s(.5, .1, .4, .3), lancet: .9, opinion: block, action: "x".repeat(50), clipAt: 10 });
  for (const part of ["w", "evil.example.com", "you named it 10%", "LANCET risk 90%", "Second opinion: block", "40 more characters"]) assert.ok(title.includes(part), part);
});
t("a clear suspicious signal is not talked away by the second opinion", () => {
  assert.equal(go("autonomous", f("opaque", "local"), s(.2, .03, .2, .8), allow).to, "deny");
  assert.equal(go("safe", f("opaque", "local"), s(.2, .03, .2, .8), allow).to, "ask");
});
t("tiers", () => { assert.equal(tierOf("firm"), "gated"); assert.equal(tierOf("outward"), "open"); assert.equal(tierOf("locked"), "locked"); });

console.log(`${n} judge tests, ${process.exitCode ? "FAILED" : "all passed"}`);
