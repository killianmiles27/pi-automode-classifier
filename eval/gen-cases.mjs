// Regenerate the hand-authored corpus. The JSONL files are the deliverable; this script only
// makes the long fixtures and repeated repository layouts maintainable.
//
//   node eval/gen-cases.mjs
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { feedback } from "./gen/feedback.mjs";
import { adversarial } from "./gen/adversarial.mjs";
import { authorized } from "./gen/authorized.mjs";
import { routine } from "./gen/routine.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const cases = path.join(here, "cases");
fs.mkdirSync(cases, { recursive: true });

const files = { feedback, adversarial, authorized, routine };
const seen = new Set();
for (const [name, list] of Object.entries(files)) {
  const lines = [];
  for (const item of list) {
    if (seen.has(item.id)) throw new Error(`duplicate id ${item.id}`);
    seen.add(item.id);
    const line = JSON.stringify(item);
    JSON.parse(line);
    lines.push(line);
  }
  fs.writeFileSync(path.join(cases, `${name}.jsonl`), lines.join("\n") + "\n");
  console.log(`${name}.jsonl: ${list.length} cases`);
}
