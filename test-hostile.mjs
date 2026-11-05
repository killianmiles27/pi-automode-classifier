// A guard that hangs freezes the whole Pi session, and no timeout can fire because the event loop is
// blocked. So every analyzer must stay fast on pathological input. Nothing is executed.
//
// The checks run in a child with a hard limit, because a real hang would never report itself.
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const LIMIT_MS = 5000; // Per call, at the largest size. A stall this long on an absurd input is tolerable; an exponential walk is not.
const HARD_LIMIT_MS = 180_000; // The whole child.

if (process.argv[2] !== "--child") {
  const run = spawnSync(process.execPath, [fileURLToPath(import.meta.url), "--child"], { encoding: "utf8", timeout: HARD_LIMIT_MS, maxBuffer: 1 << 26, windowsHide: true });
  const tail = run.stdout.trim().split("\n");
  if (run.error || run.status === null) {
    console.log(tail.slice(-3).join("\n"));
    console.log(`FAIL: an analyzer hung; the last line above names the input before it (killed at ${HARD_LIMIT_MS} ms)`);
    process.exit(1);
  }
  const failures = tail.filter((l) => l.startsWith("FAIL"));
  for (const f of failures) console.log(f);
  console.log(tail.at(-1));
  if (run.stderr.trim()) console.log(run.stderr.trim().slice(0, 1200));
  process.exit(run.status ?? 1);
}

const { bashVerdict, isSecretPath, makeScope, parse, powershellVerdict, runTargets } = await import("./rules.ts");
const { analyzeCode, analyzeText, changedFileReport } = await import("./effects.ts");
const { judgeState, redact } = await import("./context.ts");

const cwd = process.cwd();
const opts = { cwd, root: cwd, allowed: [], isSecretPath };
const scope = () => makeScope(cwd, [], {});

// Each builds a hostile string of about `n` characters.
const repeat = (s) => (n) => s.repeat(Math.ceil(n / s.length));
const SHAPES = {
  questions: repeat("?"),
  stars: repeat("*"),
  "star-slash": repeat("*/"),
  "question-word": repeat("a?"),
  "bracket-sets": repeat("[ab]"),
  "open-brackets": repeat("["),
  "brace-pairs": repeat("{a,b}"),
  "brace-nest": (n) => "{a,".repeat(n / 3) + "}".repeat(n / 3),
  "brace-range": repeat("{1..9}"),
  "open-braces": repeat("{"),
  "dollar-parens": (n) => "$(".repeat(n / 2) + ")".repeat(n / 2),
  backticks: repeat("`"),
  "double-quotes": repeat('"'),
  "single-quotes": repeat("'"),
  backslashes: repeat("\\"),
  "slashes": repeat("/"),
  "dot-dot": repeat("../"),
  spaces: repeat(" "),
  newlines: repeat("\n"),
  "long-word": repeat("a"),
  "dashes": repeat("-"),
  "pipes": repeat("| "),
  "and-chains": repeat("true && "),
  heredocs: repeat("cat <<EOF\nx\nEOF\n"),
  "unterminated-heredoc": repeat("<<EOF "),
  "comment-open": repeat("/*"),
  "line-comments": repeat("// x\n"),
  "template-nest": (n) => "`${".repeat(n / 3) + "}`".repeat(n / 3),
  concat: (n) => `const a = "x"${' + "y"'.repeat(n / 6)};`,
  "paren-nest": (n) => "(".repeat(n / 2) + ")".repeat(n / 2),
  "fetch-calls": repeat("fetch(u);"),
  "require-calls": repeat("require(x);"),
  assignments: repeat("const a = b;\n"),
  "chained-vars": (n) => { let s = 'const v0 = "x";\n'; for (let i = 1; i < n / 22; i++) s += `const v${i} = v${i - 1};\n`; return s; },
  "secret-ish": repeat("~/.aws/credentials "),
  "url-like": repeat("https://a.example/?x=1&"),
  "env-vars": repeat("$A$B${C}"),
  "base64-like": repeat("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo="),
  "regex-stars": repeat("(a+)+$"),
  "powershell-calls": repeat("Get-Content (Join-Path $HOME 'a'); "),
  "powershell-strings": repeat("$a='x'+'y';&$a;"),
  "mixed-glob": repeat("a?b*c[de]{f,g}/"),
  "real-inline": repeat(`node -e "const fs=require('fs');for (const f of fs.readdirSync('.')) if (/[?*]x/.test(f)) console.log(f?.a ?? [f][0]);" && `),
};
const CALLS = {
  parse: (s) => parse(s),
  bashVerdict: (s) => bashVerdict(s, scope()),
  powershellVerdict: (s) => powershellVerdict(s, scope()),
  runTargets: (s) => runTargets(s, scope()),
  isSecretPath: (s) => isSecretPath(s),
  "analyze bash": (s) => analyzeCode(s, "bash", opts),
  "analyze js": (s) => analyzeCode(s, "js", opts),
  "analyze python": (s) => analyzeCode(s, "python", opts),
  "analyze powershell": (s) => analyzeCode(s, "powershell", opts),
  analyzeText: (s) => analyzeText(s, opts),
  redact: (s) => redact(s),
  judgeState: (s) => judgeState({ requests: [s], replyTo: s, tool: "bash", command: s, cwd, inside: true, effects: [s] }),
};

let checks = 0, failed = 0;
for (const [shape, build] of Object.entries(SHAPES)) {
  for (const size of [200, 2000, 20000]) {
    const input = build(size);
    for (const [name, call] of Object.entries(CALLS)) {
      // Printed first: when the child is killed, the last line names the input that hung.
      console.log(`RUN ${name} ${shape} ${size}`);
      const t0 = performance.now();
      try {
        call(input);
      } catch (e) {
        // A stack overflow on absurd nesting is a failure to judge, and the handler must survive it.
        if (!(e instanceof RangeError)) { failed++; console.log(`FAIL: ${name} threw on ${shape} ${size}: ${e.message}`); }
      }
      const ms = performance.now() - t0;
      checks++;
      if (ms > LIMIT_MS) { failed++; console.log(`FAIL: ${name} took ${Math.round(ms)} ms on ${shape} ${size}`); }
    }
  }
}
console.log(`${checks} hostile-input checks, ${failed} failed`);
process.exit(failed ? 1 : 0);
