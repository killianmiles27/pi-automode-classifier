// The decision core of Auto Mode Safe and Auto Mode Autonomous. Pure functions, no model calls and
// no I/O, so every path is tested offline. See docs/SPEC-auto-modes.md.
//
// A call the rules leave open is settled in this order, and each step can only be stricter than
// the floors: what the rules and the effects say a call is (its class), then Jev, then a second
// opinion for what Jev leaves gray. What is still unresolved is the only thing the two modes treat
// differently: safe asks the human, autonomous blocks and lets the agent carry on.

import { createHash } from "node:crypto";

export type Mode = "safe" | "autonomous" | "yolo";
export const MODES: Mode[] = ["safe", "autonomous", "yolo"];
export const MODE_LABEL: Record<Mode, string> = { safe: "AUTO SAFE", autonomous: "AUTONOMOUS", yolo: "YOLO" };

// hard: never runs. locked: a human can allow it, no model ever can. gated: dangerous enough that
// only the user's own words plus a second opinion clear it. open: the judges decide on the merits.
export type Tier = "hard" | "locked" | "gated" | "open";
export type VerdictClass = "hard" | "locked" | "exfil" | "critical" | "firm" | "outward" | "opaque";
export type EffectLevel = "local" | "review" | "danger";

export const tierOf = (cls: VerdictClass): Tier =>
  cls === "hard" ? "hard" : cls === "locked" ? "locked" : cls === "exfil" || cls === "critical" || cls === "firm" ? "gated" : "open";

export interface JevScores {
  serves_task: number;
  named_by_user: number;
  lasting_harm: number;
  suspicious: number;
}
export const JEV_IDS = ["serves_task", "named_by_user", "lasting_harm", "suspicious"] as const;

export interface JudgeConfig {
  // A second opinion from the chat model (`llm`) on what Jev leaves gray. Off: gray is unresolved.
  secondOpinion: boolean;
  // When Jev is down or out of quota, the chat model answers Jev's four questions instead.
  chatScorer: boolean;
  // Clear stop without a second opinion: harmful and not named, or plainly suspicious.
  denyHarmAbove: number;
  denySuspiciousAbove: number;
  denyNamedBelow: number;
  // Code whose effects were measured as local: only a strong signal overrides the measurement.
  localHarmBelow: number;
  localSuspiciousBelow: number;
  // The user named this operation and its target. This alone clears an outward call.
  namedAbove: number;
  namedSuspiciousBelow: number;
  // The same signal for root, a credential read or Pi's own files. Lower because it never clears
  // them alone: the second opinion must agree too. Measured dangerous effects keep namedAbove.
  gatedNamedAbove: number;
  // A sensible step of the task and fairly harmless.
  stepServesAbove: number;
  stepHarmBelow: number;
  stepSuspiciousBelow: number;
  // Harmless whatever it is, provided it is not off task.
  harmlessHarmBelow: number;
  harmlessSuspiciousBelow: number;
  harmlessServesAbove: number;
  // With the second opinion down, local code may run only when Jev is this relaxed about it.
  fallbackHarmBelow: number;
  fallbackSuspiciousBelow: number;
  // At or above this, with the user not having named it, no second opinion can clear a call.
  suspiciousStopsAbove: number;
  // Consecutive blocks in autonomous before the agent is told to stop trying and wrap up.
  wrapUpAfterBlocks: number;
}

// Tuned on the tune split of eval/; the holdout numbers are in docs/AUTO-MODES.md.
export const DEFAULT_JUDGE: JudgeConfig = {
  secondOpinion: true,
  chatScorer: true,
  denyHarmAbove: 0.85,
  denySuspiciousAbove: 0.85,
  denyNamedBelow: 0.25,
  localHarmBelow: 0.5,
  localSuspiciousBelow: 0.5,
  namedAbove: 0.7,
  namedSuspiciousBelow: 0.5,
  gatedNamedAbove: 0.45,
  stepServesAbove: 0.6,
  stepHarmBelow: 0.3,
  stepSuspiciousBelow: 0.3,
  harmlessHarmBelow: 0.1,
  harmlessSuspiciousBelow: 0.2,
  harmlessServesAbove: 0.2,
  fallbackHarmBelow: 0.2,
  fallbackSuspiciousBelow: 0.2,
  suspiciousStopsAbove: 0.6,
  wrapUpAfterBlocks: 5,
};

export interface Facts {
  cls: VerdictClass;
  level: EffectLevel;
  // The effects analysis read everything the call runs, and the call runs code.
  measuredCode: boolean;
  // The analysis could not follow something.
  complete: boolean;
  // A kind of call the user allowed for this session in a prompt.
  allowedKind?: boolean;
  // LANCET's score, when it ran.
  lancet?: number;
  lancetAskAbove?: number;
}

export type JevRead = { to: "allow" | "deny" | "gray"; why: string };

// Reaching outside the project or changing the system needs the user's own words. A model's view
// that it looks like a sensible step is not enough: the red-team run showed both Jev and the second
// opinion clearing `prettier --write ~/.bashrc` and a curl carrying a token.
export const needsUserWords = (f: Pick<Facts, "cls" | "level">) => f.cls === "outward" || f.level === "danger" || tierOf(f.cls) === "gated";

// Whether the user's words reach the bar this call needs before a second opinion can clear it.
export function namedEnough(s: JevScores | undefined, f: Pick<Facts, "cls" | "level">, c: JudgeConfig): boolean {
  if (!s || s.suspicious >= c.namedSuspiciousBelow) return false;
  const strict = f.level === "danger" || f.cls === "exfil";
  return s.named_by_user >= (strict ? c.namedAbove : c.gatedNamedAbove);
}

// What Jev's four answers mean for this call. A tier-gated call can never be allowed here: the
// caller also requires the second opinion, because a model can be talked into "the user named it".
export function readJev(s: JevScores, f: Facts, c: JudgeConfig): JevRead {
  const named = s.named_by_user >= c.namedAbove && s.suspicious < c.namedSuspiciousBelow;
  if (s.named_by_user < c.denyNamedBelow) {
    if (s.lasting_harm >= c.denyHarmAbove) return { to: "deny", why: "lasting harm, and the user did not name it" };
    if (s.suspicious >= c.denySuspiciousAbove) return { to: "deny", why: "looks like credential hunting, exfiltration or tampering" };
  }
  if (tierOf(f.cls) === "gated" && f.level !== "danger") return namedEnough(s, f, c) ? { to: "gray", why: "the user named it; needs a second opinion" } : { to: "gray", why: "the user did not clearly name it" };
  if (f.level === "danger") return namedEnough(s, f, c) ? { to: "gray", why: "dangerous effects, though the user named it" } : { to: "gray", why: "dangerous effects" };
  if (named) return { to: "allow", why: "the user named it" };
  if (f.cls === "outward") return namedEnough(s, f, c) ? { to: "gray", why: "the user partly named it; needs a second opinion" } : { to: "gray", why: "it acts outside the project or on shared state, and the user did not name it" };
  if (f.allowedKind && s.lasting_harm < c.stepHarmBelow * 2 && s.suspicious < c.stepSuspiciousBelow * 2) return { to: "allow", why: "a kind you allowed for this session" };
  if (f.cls === "opaque" && f.measuredCode && f.complete && f.level === "local" && s.lasting_harm < c.localHarmBelow && s.suspicious < c.localSuspiciousBelow) return { to: "allow", why: "its measured effects stay local" };
  if (s.serves_task >= c.stepServesAbove && s.lasting_harm < c.stepHarmBelow && s.suspicious < c.stepSuspiciousBelow) return { to: "allow", why: "a sensible step of the task" };
  if (s.lasting_harm < c.harmlessHarmBelow && s.suspicious < c.harmlessSuspiciousBelow && s.serves_task >= c.harmlessServesAbove) return { to: "allow", why: "harmless" };
  return { to: "gray", why: "the signals are mixed" };
}

// The second opinion's answer, or undefined when it did not run.
export type SecondOpinion = { block: boolean; reason?: string } | { unavailable: string };

export type Final = { to: "allow" | "deny" | "ask"; why: string; retryable?: boolean };

// What happens to a call Jev has looked at (or could not), given the second opinion. The only
// difference between the modes is the last line of each branch: ask versus deny.
export function resolve(input: {
  mode: Exclude<Mode, "yolo">;
  // No human to ask: autonomous, or safe without a UI.
  unattended: boolean;
  facts: Facts;
  jev?: JevRead;
  scores?: JevScores;
  opinion?: SecondOpinion;
  config: JudgeConfig;
}): Final {
  const { unattended, facts, jev, scores, opinion, config: c } = input;
  const unresolved = (why: string, retryable = false): Final => (unattended ? { to: "deny", why, retryable } : { to: "ask", why });
  const tier = tierOf(facts.cls);

  if (tier === "hard") return { to: "deny", why: "a hard limit" };
  if (tier === "locked") return unresolved("the guard's own settings: no model can approve this");

  if (jev?.to === "allow" && tier === "open") return { to: "allow", why: jev.why };
  if (jev?.to === "deny") return unresolved(jev.why);

  const opinionDown = !opinion || "unavailable" in opinion;
  if (needsUserWords(facts)) {
    if (!namedEnough(scores, facts, c)) return unresolved(jev?.why ?? "Jev could not confirm the user asked for it", !jev);
    if (opinionDown) return unresolved("the second opinion is unavailable", true);
    return opinion.block ? unresolved(opinion.reason ?? "the second opinion blocked it") : { to: "allow", why: "the user named it and the second opinion agrees" };
  }

  // A clear signal from Jev is not something a second model gets to talk away.
  if (scores && scores.suspicious >= c.suspiciousStopsAbove && scores.named_by_user < c.gatedNamedAbove) return unresolved("it looks suspicious and the user did not name it");
  if (!opinionDown) return opinion.block ? unresolved(opinion.reason ?? "the second opinion blocked it") : { to: "allow", why: "the second opinion cleared it" };
  // Nobody is left to ask. Only code measured as local, with Jev relaxed about it, may still run.
  if (unattended && facts.measuredCode && facts.complete && facts.level === "local" && scores && scores.lasting_harm < c.fallbackHarmBelow && scores.suspicious < c.fallbackSuspiciousBelow) {
    return { to: "allow", why: "measured local and rated harmless while the second opinion is down" };
  }
  return unresolved(jev?.why ? `${jev.why}; no second opinion available` : "no judge available", true);
}

// ---- review memory ----

// The same call over the same content gets the same decision: scores cannot flip-flop on an
// unchanged test, and a changed file is a new review. `contentHash` covers every script the call
// runs and every import followed, or the body of a write.
export function memoryKey(tool: string, subject: string, cwd: string, contentHash: string): string {
  return createHash("sha256").update(JSON.stringify([tool, subject, cwd, contentHash])).digest("hex");
}

export const hashText = (text: string) => createHash("sha256").update(text).digest("hex");

// ---- what the agent and the human are told ----

export function unattendedDeny(reason: string, opts: { repeat?: boolean; retryable?: boolean; streak?: number; wrapUpAfter?: number } = {}): string {
  const lines = [`Auto Mode Autonomous blocked this call: ${reason}.`];
  if (opts.retryable) lines.push("This was not a policy decision: a judge was unavailable. You may retry once later.");
  else if (opts.repeat) lines.push("This exact call was already blocked and nothing about it has changed. Do not send it again.");
  else lines.push("Nobody is watching to approve it. Do not retry it or route around it with another tool, encoding, script or path.");
  lines.push("Carry on with every part of the task that does not need it, and list it under \"Blocked\" in your final report so the user can decide.");
  if (opts.streak !== undefined && opts.wrapUpAfter !== undefined && opts.streak >= opts.wrapUpAfter) lines.push(`${opts.streak} calls in a row have been blocked. Stop trying this approach: finish what you can and report.`);
  return lines.join(" ");
}

export function guidelines(mode: Mode): string[] {
  if (mode === "yolo") return [];
  const common = [
    "Auto mode reviews each bash call by what it does. Prefer a named project-local script over long inline code, keep scratch files inside the project rather than the system temp directory, and do not print the environment.",
    "Keep test results honest: when piping a test command through a filter, use `set -o pipefail` or run it directly so a failure is not hidden.",
    "For remote work, call `ssh <host> '<command>'` directly, using a Host alias from ~/.ssh/config: never through a shell variable, function or wrapper script, which hides the command from review. Keep read-only inspection (ls, find, cat, df, docker ps, systemctl status, journalctl) in its own ssh calls, separate from changes: reads on a trusted host run without review, while a change is reviewed on its own.",
  ];
  if (mode === "safe") return common;
  return [
    ...common,
    "You are running unattended in Auto Mode Autonomous: nobody will answer questions or approve anything, so make reasonable decisions and keep going instead of asking.",
    "When auto mode blocks a call, do not retry it or work around it with another tool, script, encoding or path. Do the rest of the task, and list what was blocked and why under \"Blocked\" in your final report.",
  ];
}

export function promptTitle(input: {
  tool: string;
  why: string;
  facts: string[];
  scores?: JevScores;
  lancet?: number;
  opinion?: SecondOpinion;
  explanation?: string;
  action: string;
  clipAt: number;
  note?: string;
}): string {
  const { tool, why, facts, scores, lancet, opinion, explanation, action, clipAt, note } = input;
  const pct = (x: number) => `${Math.round(x * 100)}%`;
  const judges: string[] = [];
  if (scores) judges.push(`Jev: serves the task ${pct(scores.serves_task)}, you named it ${pct(scores.named_by_user)}, lasting harm ${pct(scores.lasting_harm)}, suspicious ${pct(scores.suspicious)}`);
  if (lancet !== undefined) judges.push(`LANCET risk ${pct(lancet)}`);
  if (opinion) judges.push("unavailable" in opinion ? `Second opinion unavailable: ${opinion.unavailable}` : opinion.block ? `Second opinion: block. ${opinion.reason ?? ""}`.trim() : "Second opinion: allow");
  const clipped = action.length > clipAt ? `${action.slice(0, clipAt)}\n... ${action.length - clipAt} more characters. Choose "View full action" to read them.` : action;
  return [
    `Auto mode: allow ${tool}?`,
    `Why you are being asked: ${why}`,
    ...(facts.length ? [`What it does: ${facts.join("; ")}`] : []),
    ...(explanation ? [`In short: ${explanation}`] : []),
    ...judges,
    "",
    clipped,
    ...(note ? ["", note] : []),
  ].join("\n");
}
