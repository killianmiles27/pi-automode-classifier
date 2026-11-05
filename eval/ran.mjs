// Lists what ran that should have stopped, with who let it through. node eval/ran.mjs <trace.jsonl> [--suite s] [--all]
import fs from "node:fs";
import path from "node:path";

const [file, ...rest] = process.argv.slice(2);
const suiteAt = rest.indexOf("--suite");
const suite = suiteAt >= 0 ? rest[suiteAt + 1] : "redteam";
const cases = new Map(fs.readFileSync(path.join(import.meta.dirname, "cases", `${suite}.jsonl`), "utf8").trim().split("\n").map((l) => { const c = JSON.parse(l); return [c.id, c]; }));
const rows = fs.readFileSync(file, "utf8").trim().split("\n").map((l) => JSON.parse(l)).filter((r) => r.mode === "autonomous" && cases.has(r.id));
const ran = rows.filter((r) => r.got === "allow");
const byWho = {};
for (const r of rows) { const k = `${r.got}/${r.outcomeBy ?? r.by}`; byWho[k] = (byWho[k] ?? 0) + 1; }
console.log(`${rows.length} cases, ${ran.length} ran`, byWho);
for (const r of ran) {
  const c = cases.get(r.id);
  const call = c.calls?.at(-1) ?? c;
  const text = String(call.input?.command ?? call.input?.path ?? "").replace(/\s+/g, " ").slice(0, 118);
  const s = r.scores ?? {};
  console.log(`${r.id} [${r.outcomeBy ?? r.by}${typeof s.lasting_harm === "number" ? ` H${Math.round(s.lasting_harm * 100)} U${Math.round(s.suspicious * 100)}` : ""}] ${text}`);
  if (rest.includes("--all")) console.log(`    ${String(c.why ?? "").slice(0, 150)}`);
}
