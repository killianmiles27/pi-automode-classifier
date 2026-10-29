// Recomputes the rule verdicts in results/raw.jsonl with the current rules and your config's
// rules, keeping the cached LANCET and Jev answers. Run after changing rules, then analyze.ts.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { bashVerdict, compileRules, makeScope, within } from "../../rules.ts";
import { loadConfig } from "../../index.ts";

const HERE = import.meta.dirname;
const HOME = os.homedir();
const project = path.join(HOME, ".cache/pi-automode-classifier/bench/project");
const fill = (s: string) => s.replaceAll("{home}", HOME).replaceAll("{project}", project).replaceAll("{guard}", path.join(HERE, "..", ".."));
const { config } = loadConfig();
const rules = compileRules(config.rules);
const source: Record<string, string> = {
	"desktop-dev": "data/desktop-dev.jsonl",
	"context-pairs": "data/context-pairs.jsonl",
};
const rows = new Map<string, any>();
for (const suite of ["bench-cases", "permission", "rogue", "shellrisk-sample", "bench-llm-cases", "user-requests", "desktop-dev", "context-pairs"]) {
	const file = path.join(HERE, source[suite] ?? `../suites/${suite}.jsonl`);
	for (const line of fs.readFileSync(file, "utf8").trim().split("\n")) {
		const r = JSON.parse(line);
		rows.set(`${suite}/${r.id}`, r);
	}
}
const raw = path.join(HERE, "results/raw.jsonl");
let changed = 0;
const out = fs.readFileSync(raw, "utf8").trim().split("\n").map((l) => {
	const row = JSON.parse(l);
	const r = rows.get(row.key);
	const scope = makeScope(fill(r.cwd ?? "{project}"), [path.join(HOME, ".pi/agent/extensions/pi-automode-classifier")], {
		piDirs: [path.join(HOME, ".pi/agent")],
		allowedPaths: [project],
		project: (p) => within(p, project),
		chatDecider: true,
		rules,
	});
	const v = bashVerdict(fill(r.command), scope);
	const next = { ...row, rule: v.action, firm: !!v.firm, critical: !!v.critical, ruleAsk: !!v.ruleAsk, reason: v.reason };
	if (next.rule !== row.rule || next.critical !== row.critical) changed++;
	return JSON.stringify(next);
});
fs.writeFileSync(raw, out.join("\n") + "\n");
console.log(`${changed} rows changed verdict`);
