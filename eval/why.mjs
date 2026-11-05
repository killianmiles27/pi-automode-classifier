// Shows why cases missed their expected result. node eval/why.mjs <trace.jsonl> [--mode m] [--suite s] [--class c] [--max n]
import fs from "node:fs";

const [file, ...rest] = process.argv.slice(2);
const opt = (name) => { const i = rest.indexOf(`--${name}`); return i >= 0 ? rest[i + 1] : undefined; };
const rows = fs.readFileSync(file, "utf8").trim().split("\n").map((l) => JSON.parse(l));
const pct = (x) => (typeof x === "number" ? String(Math.round(x * 100)).padStart(3) : "  ?");
let shown = 0;
const max = Number(opt("max") ?? 200);
for (const r of rows) {
  if (r.expected === r.got) continue;
  // Stopped either way: a block instead of a prompt only asks less of the user.
  if (r.expected === "ask" && r.got === "block") continue;
  if (opt("mode") && r.mode !== opt("mode")) continue;
  if (opt("suite") && r.suite !== opt("suite")) continue;
  if (opt("class") && r.class !== opt("class")) continue;
  if (shown++ >= max) break;
  const s = r.scores ?? {};
  const jev = `S${pct(s.serves_task)} N${pct(s.named_by_user)} H${pct(s.lasting_harm)} U${pct(s.suspicious)}`;
  console.log(`${String(r.id).padEnd(14)} ${String(r.mode).slice(0, 4)} ${String(r.class).padEnd(10)} want ${String(r.expected).padEnd(5)} got ${String(r.got).padEnd(5)} by ${String(r.outcomeBy ?? r.by).padEnd(13)} ${jev} L=${r.level ?? "?"}`);
  console.log(`   ${String(r.subject ?? r.command ?? "").replace(/\s+/g, " ").slice(0, 130)}`);
  console.log(`   rule: ${String(r.ruleReason ?? "").slice(0, 90)} | final: ${String(r.final?.why ?? "").slice(0, 80)}${r.llmError ? ` | llmError: ${String(r.llmError).slice(0, 110)}` : ""}${r.llmReason ? ` | judge: ${String(r.llmReason).slice(0, 110)}` : ""}`);
  if (r.effects?.facts?.length) console.log(`   facts: ${r.effects.facts.join("; ").slice(0, 200)}`);
}
console.log(`${shown} shown`);
