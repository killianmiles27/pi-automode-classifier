// Pass 1 of the benchmark: the raw signals for every row, cached in results/raw.jsonl.
//   rules     the fork's rule verdict (allow / deny / ask / classify, plus firm and critical)
//   lancet    LANCET Nano v0.4.3 score, through the same JSON-lines process the extension runs
//   jevCmd    Jev 1.14, command only (the upstream classifier question)
//   jevCtx    Jev 1.14 with the user's request: authorized and harmful
// Nothing is executed: commands are inert text. Usage: tsx collect.ts [--limit n]
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { bashVerdict, makeScope, within } from "../../rules.ts";
import { jev, MODEL } from "./jev.ts";
import { CMD_QUESTIONS, contextState, CTX_QUESTIONS } from "../../context.ts";

const HERE = import.meta.dirname;
const HOME = os.homedir();
const OUT = path.join(HERE, "results");
fs.mkdirSync(OUT, { recursive: true });
const limit = process.argv.includes("--limit") ? Number(process.argv[process.argv.indexOf("--limit") + 1]) : Infinity;

const project = path.join(HOME, ".cache/pi-automode-classifier/bench/project");
if (!fs.existsSync(path.join(project, ".git"))) {
	fs.mkdirSync(project, { recursive: true });
	execFileSync("git", ["init", "-q", project]);
}
const fill = (s: string) => s.replaceAll("{home}", HOME).replaceAll("{project}", project).replaceAll("{guard}", path.join(HERE, "..", ".."));
const GENERIC = "Keep working on the task in this repository.";

// Suites. lancet-bench-1 is left out: LANCET trained on it after it was retired.
const SUITES: Record<string, string> = {
	"bench-cases": "../suites/bench-cases.jsonl",
	permission: "../suites/permission.jsonl",
	rogue: "../suites/rogue.jsonl",
	"shellrisk-sample": "../suites/shellrisk-sample.jsonl",
	"desktop-dev": "data/desktop-dev.jsonl",
	"bench-llm-cases": "../suites/bench-llm-cases.jsonl",
	"user-requests": "../suites/user-requests.jsonl",
	"context-pairs": "data/context-pairs.jsonl",
};
export const CONTEXT_SUITES = new Set(["bench-llm-cases", "user-requests", "context-pairs"]);

interface Row { id: string; suite: string; command?: string; path?: string; tool?: string; label: number; user?: string; cwd?: string }
const rows: Row[] = [];
for (const [suite, file] of Object.entries(SUITES)) {
	const lines = fs.readFileSync(path.join(HERE, file), "utf8").trim().split("\n").map((l) => JSON.parse(l));
	for (const r of lines.slice(0, limit)) if (typeof r.command === "string") rows.push({ ...r, suite });
}
// Tuning or evaluation, fixed by the row's id: 40% tune, 60% held out.
export const split = (id: string) => (createHash("sha1").update(id).digest()[0]! < 102 ? "tune" : "eval");

const rawFile = path.join(OUT, "raw.jsonl");
const done = new Map<string, any>(fs.existsSync(rawFile) ? fs.readFileSync(rawFile, "utf8").trim().split("\n").filter(Boolean).map((l) => [JSON.parse(l).key, JSON.parse(l)]) : []);

// ---- LANCET: one long-lived process, as in the extension ----
const LANCET = path.join(HOME, ".local/share/lancet");
const BUNDLE = path.join(LANCET, "lancet-v0.4.3-nano-cpu-int8");
const coldStart = performance.now();
const proc = spawn(path.join(LANCET, "venv/bin/python"), ["-I", path.join(BUNDLE, "classify.py"), "--model", path.join(BUNDLE, "model")], {
	stdio: ["pipe", "pipe", "inherit"],
	env: { ...process.env, OPENBLAS_NUM_THREADS: "1" },
});
let buffer = "";
let waiting: ((line: string) => void) | undefined;
proc.stdout.setEncoding("utf8").on("data", (c: string) => {
	buffer += c;
	let i;
	while ((i = buffer.indexOf("\n")) >= 0 && waiting) {
		const line = buffer.slice(0, i);
		buffer = buffer.slice(i + 1);
		const w = waiting;
		waiting = undefined;
		w(line);
	}
});
const lancet = (command: string) =>
	new Promise<{ score: number | null; ms: number }>((resolve) => {
		const t = performance.now();
		waiting = (line) => resolve({ score: JSON.parse(line).score, ms: performance.now() - t });
		proc.stdin.write(JSON.stringify({ command, shell: "bash" }) + "\n");
	});
const first = await lancet("true");
const lancetCold = performance.now() - coldStart;
const rss = () => {
	try {
		return Number(/VmHWM:\s+(\d+)/.exec(fs.readFileSync(`/proc/${proc.pid}/status`, "utf8"))![1]) / 1024;
	} catch {
		return undefined;
	}
};

// ---- rows ----
const out = fs.createWriteStream(rawFile, { flags: "a" });
const todo = rows.filter((r) => !done.has(`${r.suite}/${r.id}`));
console.log(`${rows.length} rows, ${todo.length} to collect; LANCET cold start ${Math.round(lancetCold)} ms (first answer ${first.score?.toFixed(3)})`);
let spent = 0;
let n = 0;
const pool = 6;
// LANCET is sequential (one process); Jev calls run `pool` at a time.
for (let i = 0; i < todo.length; i += pool) {
	const batch = todo.slice(i, i + pool);
	const prepared = [];
	for (const r of batch) {
		const command = fill(r.command!);
		const cwd = fill(r.cwd ?? "{project}");
		const scope = makeScope(cwd, [path.join(HOME, ".pi/agent/extensions/pi-automode-classifier")], {
			piDirs: [path.join(HOME, ".pi/agent")],
			allowedPaths: [project],
			project: (p) => within(p, project),
			chatDecider: true,
		});
		const v = bashVerdict(command, scope);
		const lan = await lancet(command);
		prepared.push({ r, command, cwd, v, lan });
	}
	const results = await Promise.all(
		prepared.map(async ({ r, command, cwd, v }) => {
			const inside = within(cwd, project);
			const [cmd, ctx] = await Promise.all([
				jev({ tool: r.tool ?? "bash", cwd, command }, CMD_QUESTIONS),
				jev(contextState({ requests: [r.user ?? GENERIC], tool: r.tool ?? "bash", command, cwd, inside, note: v.reason }), CTX_QUESTIONS),
			]);
			return { cmd, ctx };
		}),
	);
	prepared.forEach(({ r, v, lan }, k) => {
		const { cmd, ctx } = results[k]!;
		spent += (cmd.cost ?? 0) + (ctx.cost ?? 0);
		const row = {
			key: `${r.suite}/${r.id}`,
			suite: r.suite,
			id: r.id,
			label: r.label,
			split: split(r.id),
			context: CONTEXT_SUITES.has(r.suite),
			rule: v.action,
			firm: !!v.firm,
			critical: !!v.critical,
			ruleAsk: !!v.ruleAsk,
			reason: v.reason,
			lancet: lan.score,
			lancetMs: Math.round(lan.ms * 10) / 10,
			jevCmd: cmd.answers?.risky ?? null,
			jevCmdMs: cmd.ms,
			jevCmdErr: cmd.error,
			jevCtx: ctx.answers ?? null,
			jevCtxMs: ctx.ms,
			jevCtxErr: ctx.error,
			tokens: (cmd.inputTokens ?? 0) + (ctx.inputTokens ?? 0),
			cost: (cmd.cost ?? 0) + (ctx.cost ?? 0),
		};
		out.write(JSON.stringify(row) + "\n");
	});
	n += batch.length;
	if (n % 60 < pool) console.log(`${n}/${todo.length}  spent $${spent.toFixed(4)}`);
	if (spent > 0.9) {
		console.log("Stopping: near the $1 Jev budget");
		break;
	}
}
out.end();
fs.writeFileSync(path.join(OUT, "lancet-process.json"), JSON.stringify({ coldStartMs: Math.round(lancetCold), peakRssMb: rss(), model: "LANCET Nano v0.4.3 CPU INT8", jev: MODEL }, null, 2));
proc.kill();
console.log(`done; Jev spend this run $${spent.toFixed(4)}`);
