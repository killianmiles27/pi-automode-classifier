// Static effects analysis for code an action runs.
//
// Pure, synchronous, never executes, imports or evaluates the analysed code. Plain regexes and
// small hand-written scanners only, so it runs under Node's type stripping with no build step.
//
// The contract is docs/SPEC-auto-modes.md section 4. isSecretPath comes in through options so
// rules.ts stays the single source of truth.

import fs from "node:fs";
import os from "node:os";
import crypto from "node:crypto";

export type Lang =
  | "js"
  | "mjs"
  | "cjs"
  | "ts"
  | "python"
  | "bash"
  | "sh"
  | "powershell"
  | "unknown";

export interface EffectReport {
  complete: boolean;
  hash: string;
  scripts: { path: string; lang: Lang; bytes: number }[];
  network: { external: string[]; loopback: boolean; dynamic: boolean };
  credentials: string[];
  env: { whole: boolean; names: string[] };
  writes: { outside: string[]; dynamic: boolean };
  deletes: { outside: string[]; dynamic: boolean };
  reads: { outside: string[] };
  exec: { commands: string[]; dynamic: boolean };
  obfuscated: string[];
  // Facts that are not danger signals on their own, such as a credential copied into the project.
  // buildFacts puts them in `facts`.
  notes: string[];
  facts: string[];
  level: "local" | "review" | "danger";
}

export interface AnalyzeOptions {
  cwd: string;
  root?: string;
  allowed?: string[];
  isSecretPath: (p: string) => boolean;
  maxFiles?: number;
  maxDepth?: number;
  maxBytes?: number;
}

const DEFAULTS = { maxFiles: 40, maxDepth: 3, maxBytes: 2 * 1024 * 1024 };
const HOME_RAW = os.homedir();
const HOME = normAbs(slash(HOME_RAW));
const TMPDIR = normAbs(slash(os.tmpdir()));
// Scratch space: the system temp directory is not "outside the project". Writes there are
// disposable, so listing them as outside-project work is noise. A credential read there is still
// a credential; this list only decides the outside-project check.
const SCRATCH = [TMPDIR, "/tmp", "/var/tmp", "/dev/shm", "/private/var/tmp", "/private/var/folders", "C:/Windows/Temp"]
  .map((p) => slash(p))
  .filter((p, i, all) => !!p && all.indexOf(p) === i);

// ---------------------------------------------------------------------------
// Paths

function slash(p: string): string {
  return p.replace(/\\/g, "/");
}

function ciKey(p: string): string {
  return /^[A-Za-z]:\//.test(p) || process.platform === "win32" ? p.toLowerCase() : p;
}

function isAbs(p: string): boolean {
  return /^[A-Za-z]:\//.test(p) || p.startsWith("/");
}

function normAbs(input: string): string {
  let s = slash(input.trim());
  // Git Bash /c/Users/x -> C:/Users/x
  if (/^\/[A-Za-z](\/|$)/.test(s)) s = s[1].toUpperCase() + ":" + s.slice(2);
  let drive = "";
  if (/^[A-Za-z]:\//.test(s)) {
    drive = s[0].toUpperCase() + ":";
    s = s.slice(2);
  }
  const absolute = s.startsWith("/");
  const out: string[] = [];
  for (const part of s.split("/")) {
    if (!part || part === ".") continue;
    if (part === "..") {
      if (out.length && out[out.length - 1] !== "..") out.pop();
      else if (!absolute) out.push("..");
    } else out.push(part);
  }
  let res = (absolute ? "/" : "") + out.join("/");
  if (drive) res = drive + (res.startsWith("/") ? res : "/" + res);
  if (!res) res = drive ? drive + "/" : "/";
  return res;
}

function joinAbs(base: string, rel: string): string {
  if (isAbs(rel)) return normAbs(rel);
  const b = base.replace(/\/+$/, "");
  return normAbs((b || "/") + "/" + rel);
}

function dirName(p: string): string {
  const s = p.replace(/\/+$/, "");
  const i = s.lastIndexOf("/");
  if (i < 0) return ".";
  if (i === 0) return "/";
  if (i === 2 && /^[A-Za-z]:\//.test(s)) return s.slice(0, 3);
  return s.slice(0, i);
}

function baseName(p: string): string {
  const s = p.replace(/\/+$/, "");
  const i = s.lastIndexOf("/");
  return i < 0 ? s : s.slice(i + 1);
}

function underCI(p: string, root: string): boolean {
  const a = ciKey(p);
  const b = ciKey(root).replace(/\/+$/, "");
  return a === b || a.startsWith(b + "/");
}

function expandHomeRefs(input: string, home: string): string {
  let s = input;
  const envValue = (name: string, original: string): string =>
    /^(USERPROFILE|HOME)$/i.test(name) ? home : /^(TEMP|TMP|TMPDIR)$/i.test(name) ? TMPDIR : original;
  s = s.replace(/%([A-Za-z_][A-Za-z0-9_]*)%/g, (m, n) => envValue(n, m));
  s = s.replace(/\$\{env:([A-Za-z_][A-Za-z0-9_]*)\}/gi, (m, n) => envValue(n, m));
  s = s.replace(/\$env:([A-Za-z_][A-Za-z0-9_]*)/gi, (m, n) => envValue(n, m));
  s = s.replace(/\$\{(HOME|USERPROFILE)\}/gi, home);
  s = s.replace(/\$(HOME|USERPROFILE)\b/gi, home);
  s = s.replace(/\$\{?(TMPDIR|TEMP|TMP)\b\}?/gi, TMPDIR);
  s = s.replace(/^~(?=$|[\\/])/, home);
  return s;
}

function unquote(s: string): string {
  let t = s.trim();
  if (t.length >= 2 && ((t[0] === '"' && t[t.length - 1] === '"') || (t[0] === "'" && t[t.length - 1] === "'"))) {
    t = t.slice(1, -1);
  }
  return t;
}

function cleanWord(s: string): string {
  let t = s.trim();
  t = t.replace(/^@/, "");
  t = unquote(t);
  t = t.replace(/;+$/, "");
  return t;
}

function isDevNull(p: string): boolean {
  return /^\/(dev\/(null|stdout|stderr|tty|fd\/\d+)|proc\/self\/fd\/\d+)$/.test(slash(p).toLowerCase());
}

function looksPathLike(s: string): boolean {
  if (!s || s.startsWith("-")) return false;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) return false;
  return /[\\/]/.test(s) || s.startsWith("~") || /^[A-Za-z]:/.test(s) || s.startsWith(".");
}

function pathCandidates(word: string): string[] {
  const out: string[] = [];
  const clean = cleanWord(word);
  if (clean) out.push(clean);
  const eq = clean.indexOf("=");
  if (eq >= 0) out.push(clean.slice(eq + 1));
  return out.filter(Boolean);
}

// ---------------------------------------------------------------------------
// Comments: stripped so a comment can neither trigger nor suppress a match.

function stripJsComments(code: string): string {
  let out = "";
  let i = 0;
  while (i < code.length) {
    const c = code[i];
    const d = code[i + 1];
    if (c === '"' || c === "'" || c === "`") {
      const q = c;
      out += c;
      i++;
      while (i < code.length) {
        const ch = code[i];
        out += ch;
        if (ch === "\\") {
          if (i + 1 < code.length) out += code[i + 1];
          i += 2;
          continue;
        }
        i++;
        if (ch === q) break;
      }
      continue;
    }
    if (c === "/" && d === "/") {
      while (i < code.length && code[i] !== "\n") {
        out += " ";
        i++;
      }
      continue;
    }
    if (c === "/" && d === "*") {
      out += "  ";
      i += 2;
      while (i < code.length && !(code[i] === "*" && code[i + 1] === "/")) {
        out += code[i] === "\n" ? "\n" : " ";
        i++;
      }
      if (i < code.length) {
        out += "  ";
        i += 2;
      }
      continue;
    }
    out += c;
    i++;
  }
  return out;
}

function stripPyComments(code: string): string {
  let out = "";
  let i = 0;
  while (i < code.length) {
    const c = code[i];
    if (c === "#") {
      while (i < code.length && code[i] !== "\n") {
        out += " ";
        i++;
      }
      continue;
    }
    if (c === '"' || c === "'") {
      const triple = code.slice(i, i + 3) === c + c + c;
      if (triple) {
        out += c + c + c;
        i += 3;
        while (i < code.length) {
          if (code[i] === "\\") {
            out += code.slice(i, i + 2);
            i += 2;
            continue;
          }
          if (code.slice(i, i + 3) === c + c + c) {
            out += c + c + c;
            i += 3;
            break;
          }
          out += code[i];
          i++;
        }
      } else {
        out += c;
        i++;
        while (i < code.length) {
          const ch = code[i];
          out += ch;
          if (ch === "\\") {
            if (i + 1 < code.length) out += code[i + 1];
            i += 2;
            continue;
          }
          i++;
          if (ch === c) break;
        }
      }
      continue;
    }
    out += c;
    i++;
  }
  return out;
}

function stripBashComments(code: string): string {
  let out = "";
  let i = 0;
  while (i < code.length) {
    const c = code[i];
    if (c === "'" || c === '"' || c === "`") {
      const q = c;
      out += c;
      i++;
      while (i < code.length) {
        const ch = code[i];
        out += ch;
        if (ch === "\\" && q !== "'") {
          if (i + 1 < code.length) out += code[i + 1];
          i += 2;
          continue;
        }
        i++;
        if (ch === q) break;
      }
      continue;
    }
    if (c === "#") {
      const prev = i === 0 ? "" : code[i - 1];
      if (!prev || /[\s;|&(]/.test(prev)) {
        while (i < code.length && code[i] !== "\n") {
          out += " ";
          i++;
        }
        continue;
      }
    }
    out += c;
    i++;
  }
  return out;
}

function stripPsComments(code: string): string {
  let out = "";
  let i = 0;
  while (i < code.length) {
    const c = code[i];
    if (c === "'" || c === '"') {
      const q = c;
      out += c;
      i++;
      while (i < code.length) {
        const ch = code[i];
        out += ch;
        if (ch === "`") {
          if (i + 1 < code.length) out += code[i + 1];
          i += 2;
          continue;
        }
        i++;
        if (ch === q) break;
      }
      continue;
    }
    if (c === "<" && code[i + 1] === "#") {
      out += "  ";
      i += 2;
      while (i < code.length && !(code[i] === "#" && code[i + 1] === ">")) {
        out += code[i] === "\n" ? "\n" : " ";
        i++;
      }
      if (i < code.length) {
        out += "  ";
        i += 2;
      }
      continue;
    }
    if (c === "#") {
      while (i < code.length && code[i] !== "\n") {
        out += " ";
        i++;
      }
      continue;
    }
    out += c;
    i++;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Small expression helpers

function splitTopLevel(s: string, sep: string): string[] {
  const parts: string[] = [];
  let cur = "";
  let depth = 0;
  let quote = "";
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (quote) {
      cur += c;
      if (c === "\\") {
        if (i + 1 < s.length) cur += s[++i];
        continue;
      }
      if (c === quote) quote = "";
      continue;
    }
    if (c === "'" || c === '"' || c === "`") {
      quote = c;
      cur += c;
      continue;
    }
    if (c === "(" || c === "[" || c === "{") depth++;
    if (c === ")" || c === "]" || c === "}") depth = Math.max(0, depth - 1);
    if (c === sep && depth === 0) {
      if (sep === "+" && (s[i + 1] === "+" || s[i - 1] === "+")) {
        cur += c;
        continue;
      }
      if (sep === "/" && (s[i + 1] === "/" || s[i + 1] === "*")) {
        cur += c;
        continue;
      }
      parts.push(cur);
      cur = "";
      continue;
    }
    cur += c;
  }
  parts.push(cur);
  return parts;
}

// Split on a multi-character operator, ignoring quotes and nesting.
function splitTopLevelOp(s: string, op: string): string[] {
  const parts: string[] = [];
  let cur = "";
  let depth = 0;
  let quote = "";
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (quote) {
      cur += c;
      if (c === "\\") {
        if (i + 1 < s.length) cur += s[++i];
        continue;
      }
      if (c === quote) quote = "";
      continue;
    }
    if (c === "'" || c === '"' || c === "`") {
      quote = c;
      cur += c;
      continue;
    }
    if (c === "(" || c === "[" || c === "{") depth++;
    if (c === ")" || c === "]" || c === "}") depth = Math.max(0, depth - 1);
    if (depth === 0 && s.startsWith(op, i)) {
      parts.push(cur);
      cur = "";
      i += op.length - 1;
      continue;
    }
    cur += c;
  }
  parts.push(cur);
  return parts;
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// The bracket pair a computed name sits in: globalThis[<here>].
function matchingBracket(s: string, open: number): number {
  const pairs: Record<string, string> = { "[": "]", "(": ")" };
  const openCh = s[open];
  const closeCh = pairs[openCh];
  if (!closeCh) return -1;
  let depth = 0;
  let quote = "";
  for (let i = open; i < s.length; i++) {
    const c = s[i];
    if (quote) {
      if (c === "\\") {
        i++;
        continue;
      }
      if (c === quote) quote = "";
      continue;
    }
    if (c === "'" || c === '"' || c === "`") {
      quote = c;
      continue;
    }
    if (c === openCh) depth++;
    else if (c === closeCh) {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

function matchingClose(s: string, open: number): number {
  let depth = 0;
  let quote = "";
  for (let i = open; i < s.length; i++) {
    const c = s[i];
    if (quote) {
      if (c === "\\") {
        i++;
        continue;
      }
      if (c === quote) quote = "";
      continue;
    }
    if (c === "'" || c === '"' || c === "`") {
      quote = c;
      continue;
    }
    if (c === "(") depth++;
    else if (c === ")") {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

function parseArgs(code: string, open: number): { args: string[]; end: number } {
  const args: string[] = [];
  let cur = "";
  let depth = 1;
  let quote = "";
  let i = open + 1;
  for (; i < code.length; i++) {
    const c = code[i];
    if (quote) {
      cur += c;
      if (c === "\\") {
        if (i + 1 < code.length) cur += code[++i];
        continue;
      }
      if (c === quote) quote = "";
      continue;
    }
    if (c === "'" || c === '"' || c === "`") {
      quote = c;
      cur += c;
      continue;
    }
    if (c === "(" || c === "[" || c === "{") {
      depth++;
      cur += c;
      continue;
    }
    if (c === ")" || c === "]" || c === "}") {
      depth--;
      if (depth === 0) {
        if (cur.trim()) args.push(cur.trim());
        return { args, end: i };
      }
      cur += c;
      continue;
    }
    if (c === "," && depth === 1) {
      args.push(cur.trim());
      cur = "";
      continue;
    }
    cur += c;
  }
  if (cur.trim()) args.push(cur.trim());
  return { args, end: code.length - 1 };
}

function parseWholeCall(s: string): { callee: string; args: string[] } | null {
  const m = s.match(/^(?:new\s+)?([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*\(/);
  if (!m) return null;
  const open = s.indexOf("(", m[0].length - 1);
  if (open < 0 || matchingClose(s, open) !== s.length - 1) return null;
  const args = parseArgs(s, open).args;
  return { callee: m[1].replace(/\s+/g, ""), args };
}

function unescapeText(body: string): string {
  return body.replace(/\\(u\{[0-9a-fA-F]+\}|u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|[0-7]{1,3}|[\s\S])/g, (m, e) => {
    if (e[0] === "n") return "\n";
    if (e[0] === "t") return "\t";
    if (e[0] === "r") return "\r";
    if (e[0] === "b") return "\b";
    if (e[0] === "f") return "\f";
    if (e[0] === "v") return "\v";
    if (e[0] === "0") return "\0";
    if (e[0] === "x") return String.fromCharCode(parseInt(e.slice(1), 16));
    if (e[0] === "u") {
      const hex = e[1] === "{" ? e.slice(2, -1) : e.slice(1);
      return String.fromCodePoint(parseInt(hex, 16));
    }
    if (/^[0-7]+$/.test(e)) return String.fromCharCode(parseInt(e, 8));
    if (e === "\\" || e === "'" || e === '"' || e === "`") return e;
    // A Windows separator such as \U or \. is not a JS escape we need to interpret.
    return "\\" + e;
  });
}

function findStringEnd(s: string, quote: string, from: number): number {
  for (let i = from; i < s.length; i++) {
    if (s[i] === "\\") {
      i++;
      continue;
    }
    if (s[i] === quote) return i;
  }
  return -1;
}

function parseStringLiteral(s: string): string | null {
  const f = s.match(/^([rRbBuUfF]{0,2})(["'])/);
  if (!f) return null;
  const prefix = f[1] || "";
  if (/[fF]/.test(prefix)) return null; // templates are handled separately
  const quote = f[2];
  const start = prefix.length + 1;
  const triple = s.slice(start, start + 2) === quote + quote;
  if (triple) {
    const close = s.indexOf(quote + quote + quote, start + 3);
    if (close < 0 || close + 3 !== s.length) return null;
    const body = s.slice(start + 3, close);
    if (/[rR]/.test(prefix)) return body;
    return unescapeText(body);
  }
  const close = findStringEnd(s, quote, start);
  if (close < 0 || close !== s.length - 1) return null;
  const body = s.slice(start, close);
  if (/[rR]/.test(prefix)) return body;
  return unescapeText(body);
}

function parseTemplate(s: string): { body: string; marker: string; py: boolean } | null {
  if (s.startsWith("`")) {
    const close = findStringEnd(s, "`", 1);
    if (close === s.length - 1) return { body: s.slice(1, -1), marker: "${", py: false };
    return null;
  }
  const f = s.match(/^[fF](["'])/);
  if (!f) return null;
  const close = findStringEnd(s, f[1], 2);
  if (close !== s.length - 1) return null;
  return { body: s.slice(2, -1), marker: "{", py: true };
}

function foldTemplate(state: State, tpl: { body: string; marker: string; py: boolean }, depth: number): string | null {
  const body = tpl.py ? "" : tpl.body;
  if (!tpl.py && !tpl.body.includes("${")) return unescapeText(tpl.body);
  if (tpl.py && !tpl.body.includes("{")) return unescapeText(tpl.body);
  let out = "";
  let i = 0;
  const src = tpl.py ? tpl.body : body;
  while (i < src.length) {
    if (tpl.py ? src[i] === "{" : src[i] === "$" && src[i + 1] === "{") {
      const start = i + (tpl.py ? 1 : 2);
      let depthN = 1;
      let j = start;
      let quote = "";
      for (; j < src.length; j++) {
        const c = src[j];
        if (quote) {
          if (c === "\\") j++;
          else if (c === quote) quote = "";
          continue;
        }
        if (c === "'" || c === '"') quote = c;
        else if (c === "{") depthN++;
        else if (c === "}") {
          depthN--;
          if (depthN === 0) break;
        }
      }
      if (j >= src.length) return null;
      const inner = foldExpr(state, src.slice(start, j), depth + 1);
      if (inner === null) return null;
      out += inner;
      i = j + 1;
      continue;
    }
    if (src[i] === "\\") {
      out += unescapeText(src.slice(i, i + 2));
      i += 2;
      continue;
    }
    out += src[i];
    i++;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Analysis state

interface State {
  opts: AnalyzeOptions;
  cwd: string;
  root: string;
  home: string;
  allowed: string[];
  lang: Lang;
  family: "js" | "python" | "shell" | "powershell" | "unknown";
  path: string;
  dir: string;
  code: string;
  complete: boolean;
  external: Set<string>;
  loopback: boolean;
  dynamicNetwork: boolean;
  credentials: Set<string>;
  envWhole: boolean;
  envNames: Set<string>;
  writesOutside: Set<string>;
  writesDynamic: boolean;
  deletesOutside: Set<string>;
  deletesDynamic: boolean;
  readsOutside: Set<string>;
  commands: Set<string>;
  execDynamic: boolean;
  obfuscated: Set<string>;
  notes: string[];
  vars: Map<string, string | null>;
  tainted: Set<string>;
  socketVars: Set<string>;
  cpVars: Set<string>;
  cpNames: Set<string>;
  httpVars: Set<string>;
  pyModules: Map<string, string>;
  varExprs: Map<string, string>;
  serverListen: boolean;
  dangerFile: boolean;
  depth: number;
}

function newState(opts: AnalyzeOptions, lang: Lang, filePath: string, dir: string, depth: number): State {
  return {
    opts,
    cwd: normAbs(slash(opts.cwd || process.cwd())),
    root: normAbs(slash(opts.root || opts.cwd || process.cwd())),
    home: HOME,
    allowed: (opts.allowed || []).map((p) => normAbs(expandHomeRefs(slash(p), HOME))),
    lang,
    family: languageFamily(lang),
    path: filePath,
    dir: normAbs(slash(dir || opts.cwd || process.cwd())),
    code: "",
    complete: true,
    external: new Set(),
    loopback: false,
    dynamicNetwork: false,
    credentials: new Set(),
    envWhole: false,
    envNames: new Set(),
    writesOutside: new Set(),
    writesDynamic: false,
    deletesOutside: new Set(),
    deletesDynamic: false,
    readsOutside: new Set(),
    commands: new Set(),
    execDynamic: false,
    obfuscated: new Set(),
    notes: [],
    vars: new Map(),
    tainted: new Set(),
    socketVars: new Set(),
    cpVars: new Set(),
    cpNames: new Set(),
    httpVars: new Set(),
    pyModules: new Map(),
    varExprs: new Map(),
    serverListen: false,
    dangerFile: false,
    depth,
  };
}

function languageFamily(lang: Lang): State["family"] {
  if (lang === "js" || lang === "mjs" || lang === "cjs" || lang === "ts") return "js";
  if (lang === "python") return "python";
  if (lang === "bash" || lang === "sh") return "shell";
  if (lang === "powershell") return "powershell";
  return "unknown";
}

function markIncomplete(state: State): void {
  state.complete = false;
}

function underScratch(p: string): boolean {
  return SCRATCH.some((s) => underCI(p, s));
}

function insideProject(state: State, abs: string): boolean {
  if (underCI(abs, state.root)) return true;
  if (underScratch(abs)) return true;
  return state.allowed.some((a) => underCI(abs, a));
}

function isHomeWide(state: State, abs: string): boolean {
  const a = ciKey(abs);
  const h = ciKey(state.home);
  if (a === h || a === h + "/*") return true;
  if (a === "/" || /^[a-z]:\/$/.test(a)) return true;
  // A parent of the home directory: deleting it destroys home.
  return h.startsWith(a.endsWith("/") ? a : a + "/");
}

function displayPath(state: State, abs: string): string {
  if (underCI(abs, state.home)) {
    const rest = abs.slice(state.home.length);
    return rest ? "~" + rest : "~";
  }
  if (underCI(abs, state.root) && abs.length > state.root.length) {
    return abs.slice(state.root.length + 1);
  }
  return abs;
}

function secretAbs(state: State, value: string): string {
  const expanded = expandHomeRefs(value, state.home);
  const s = slash(expanded);
  return isAbs(s) ? normAbs(s) : joinAbs(state.cwd, s);
}

function checkSecret(state: State, candidates: string[]): string | null {
  for (const raw of candidates) {
    if (!raw) continue;
    const expanded = expandHomeRefs(raw, state.home);
    const forms = new Set<string>([raw, expanded, slash(raw), slash(expanded)]);
    for (const f of forms) {
      if (!f) continue;
      try {
        if (state.opts.isSecretPath && state.opts.isSecretPath(f)) return secretAbs(state, f);
      } catch {
        /* an option callback must never break the analyzer */
      }
    }
  }
  return null;
}

function addCredential(state: State, value: string): void {
  if (value) state.credentials.add(value);
}

function isSecretEnvName(name: string): boolean {
  if (/(?:TOKEN|SECRET|PASSWORD|PASSWD|PASSPHRASE|CREDENTIAL)/i.test(name)) return true;
  return /(?:^|_)(?:KEY|KEYS|AUTH|AUTHORIZATION)(?:$|_)/i.test(name);
}

function addEnvName(state: State, name: string): void {
  if (!name || name === "dynamic") return;
  state.envNames.add(name);
  if (isSecretEnvName(name)) addCredential(state, name);
}

function addExternal(state: State, host: string): void {
  const h = host.trim().replace(/^\[|\]$/g, "").toLowerCase();
  if (!h) return;
  if (isLoopbackHost(h)) {
    state.loopback = true;
    return;
  }
  state.external.add(host.trim());
}

function isLoopbackHost(host: string): boolean {
  const h = host.trim().replace(/^\[|\]$/g, "").toLowerCase();
  if (!h) return false;
  if (h === "localhost" || h.endsWith(".localhost")) return true;
  if (h === "::1" || h === "0:0:0:0:0:0:0:1" || h === "0.0.0.0") return true;
  if (/^127(?:\.\d{1,3}){3}$/.test(h) || h === "127.0.0.1") return true;
  return false;
}

function markDynamicNetwork(state: State): void {
  state.dynamicNetwork = true;
}

function classifyHost(state: State, raw: string): void {
  let h = unquote(raw.trim());
  if (!h) return;
  h = h.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "");
  h = h.replace(/^[^@/]*@/, "");
  h = h.split(/[/?#]/)[0];
  h = h.replace(/:\d+$/, "");
  if (!h) return;
  if (/[$`]|\$\{/.test(h)) {
    markDynamicNetwork(state);
    return;
  }
  addExternal(state, h);
}

function classifyURL(state: State, raw: string): void {
  let u = unquote(raw.trim());
  if (!u) return;
  const m = u.match(/^(?:([a-z][a-z0-9+.-]*):)?\/\/([^/?#]+)/i);
  if (m) {
    const scheme = (m[1] || "http").toLowerCase();
    if (scheme === "file") return;
    const authority = m[2];
    const hostPort = authority.replace(/^[^@]*@/, "");
    let host: string;
    if (hostPort.startsWith("[")) host = hostPort.slice(1, hostPort.indexOf("]") < 0 ? undefined : hostPort.indexOf("]"));
    else if (hostPort.startsWith("${")) host = hostPort;
    else host = hostPort.split(":")[0];
    if (!host) return;
    if (/[$`{}%]/.test(host)) {
      markDynamicNetwork(state);
      return;
    }
    addExternal(state, host);
    return;
  }
  // Bare destination (curl example.com/path, ssh box).
  const bare = u.replace(/^[^/]*@/, "").split(/[/?#]/)[0].replace(/:\d+$/, "");
  if (!bare) return;
  if (/[$`{}]/.test(bare)) {
    markDynamicNetwork(state);
    return;
  }
  if (/^[A-Za-z0-9_.-]+$/.test(bare) && (bare.includes(".") || bare === "localhost")) {
    addExternal(state, bare);
  }
}

function exprHint(state: State, raw: string, depth = 0): string {
  if (depth > 4) return raw;
  const parts = [raw];
  const seen = new Set<string>();
  const visit = (text: string, d: number) => {
    if (d > 4) return;
    for (const m of text.matchAll(/\b([A-Za-z_$][\w$]*)\b/g)) {
      const name = m[1];
      if (seen.has(name)) continue;
      seen.add(name);
      const expr = state.varExprs.get(name);
      if (expr && expr !== text) {
        parts.push(expr);
        visit(expr, d + 1);
      }
    }
  };
  visit(raw, 0);
  return parts.join(" ");
}

function loopbackHint(state: State, hint: string): boolean {
  if (/\blocalhost\b|127(?:\.\d{1,3}){3}|\b::1\b|\[::1\]|\b0\.0\.0\.0\b/i.test(hint)) return true;
  return state.serverListen && /(?:address\s*\(|server_address|getsockname\s*\()/i.test(hint);
}

function classifyNetworkArg(state: State, expr: string): void {
  const raw = expr.trim();
  if (!raw) {
    markDynamicNetwork(state);
    return;
  }
  if (state.family === "js" && raw.startsWith("{")) {
    if (/\bsocketPath\s*:/.test(raw)) {
      state.loopback = true;
      return;
    }
    const props = raw.match(/\b(?:host|hostname|href|url)\s*:\s*([^,}]+)/g) || [];
    let found = false;
    for (const p of props) {
      const value = p.replace(/^[^:]+:\s*/, "");
      const folded = foldExpr(state, value, 0);
      if (folded && /^[a-z][a-z0-9+.-]*:\/\//i.test(folded)) {
        classifyURL(state, folded);
        found = true;
      } else if (folded) {
        classifyHost(state, folded);
        found = true;
      }
    }
    if (!found) {
      if (!props.length && /\b(?:port|path|socketPath)\s*:/.test(raw)) state.loopback = true;
      else markDynamicNetwork(state);
    }
    return;
  }
  const folded = foldExpr(state, raw, 0);
  if (folded !== null) {
    const clean = expandHomeRefs(folded.trim(), state.home);
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(clean)) classifyURL(state, clean);
    else if (state.family === "js" && /^\/\//.test(clean)) classifyURL(state, clean);
    else if (state.family === "js") {
      if (/^[A-Za-z0-9_.-]+(?::\d+)?$/.test(clean)) classifyHost(state, clean);
      else if (state.serverListen) state.loopback = true;
      else markDynamicNetwork(state);
    } else classifyURL(state, clean);
    return;
  }
  // Unfoldable: a literal URL or a loopback host inside the expression still tells us the target.
  const hint = exprHint(state, raw);
  const urls = raw.match(/\b[a-z][a-z0-9+.-]*:\/\/[^\s"'`<>)]+/gi) || [];
  if (urls.length) {
    for (const u of urls) {
      const authority = u.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "").split(/[/?#]/)[0];
      const hostPart = authority.replace(/^[^@]*@/, "").split(":")[0];
      if (/[$`{}%]/.test(hostPart) && loopbackHint(state, hint)) {
        state.loopback = true;
        continue;
      }
      classifyURL(state, expandVarsForUrl(state, u));
    }
    return;
  }
  const hintUrls = hint.match(/\b[a-z][a-z0-9+.-]*:\/\/[^\s"'`<>)]+/gi) || [];
  if (hintUrls.length) {
    for (const u of hintUrls) {
      const authority = u.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "").split(/[/?#]/)[0];
      const hostPart = authority.replace(/^[^@]*@/, "").split(":")[0];
      if (/[$`{}%]/.test(hostPart) && loopbackHint(state, hint)) {
        state.loopback = true;
        continue;
      }
      classifyURL(state, expandVarsForUrl(state, u));
    }
    return;
  }
  if (loopbackHint(state, hint)) {
    state.loopback = true;
    return;
  }
  markDynamicNetwork(state);
}

function expandVarsForUrl(state: State, s: string): string {
  let out = s.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g, (m, n) => state.vars.get(n) ?? m);
  out = out.replace(/\$([A-Za-z_][A-Za-z0-9_]*)/g, (m, n) => state.vars.get(n) ?? m);
  out = out.replace(/\$env:([A-Za-z_][A-Za-z0-9_]*)/gi, (m, n) => {
    if (/^(USERPROFILE|HOME)$/i.test(n)) return state.home;
    return state.vars.get(n) ?? m;
  });
  return expandHomeRefs(out, state.home);
}

function substituteVars(state: State, s: string): string | null {
  let unknown = false;
  let out = s.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g, (m, n) => {
    if (/^(HOME|USERPROFILE)$/i.test(n)) return state.home;
    if (/^(TMPDIR|TEMP|TMP)$/i.test(n)) return TMPDIR;
    const v = state.vars.get(n);
    if (v === undefined || v === null) {
      unknown = true;
      return m;
    }
    return v;
  });
  out = out.replace(/\$env:([A-Za-z_][A-Za-z0-9_]*)/gi, (m, n) => {
    if (/^(USERPROFILE|HOME)$/i.test(n)) return state.home;
    if (/^(TMPDIR|TEMP|TMP)$/i.test(n)) return TMPDIR;
    if (/^PSScriptRoot$/i.test(n)) return state.dir;
    if (/^PWD$/i.test(n)) return state.cwd;
    const v = state.vars.get(n);
    if (v === undefined || v === null) {
      unknown = true;
      return m;
    }
    return v;
  });
  out = out.replace(/\$([A-Za-z_][A-Za-z0-9_]*)/g, (m, n) => {
    if (/^(HOME|USERPROFILE)$/i.test(n)) return state.home;
    if (/^(TMPDIR|TEMP|TMP)$/i.test(n)) return TMPDIR;
    if (/^PSScriptRoot$/i.test(n)) return state.dir;
    if (/^PWD$/i.test(n)) return state.cwd;
    const v = state.vars.get(n);
    if (v === undefined || v === null) {
      unknown = true;
      return m;
    }
    return v;
  });
  out = expandHomeRefs(out, state.home);
  if (unknown || /\$[A-Za-z_{(]|%[A-Za-z_]+%/.test(out)) return null;
  return out;
}

function resolvePath(state: State, raw: string, base?: string): string | null {
  let s = raw.trim();
  if (!s) return null;
  s = cleanWord(s);
  if (!s) return null;
  s = s.replace(/^file:\/\//i, "");
  const substituted = substituteVars(state, s);
  if (substituted === null) return null;
  s = substituted;
  if (/[()]$/.test(s) && /[($]/.test(s)) {
    // Command substitution or a call expression is dynamic.
    if (/\$\(|`/.test(s)) return null;
  }
  if (s === "-" || s.startsWith("&") || s === "NUL" || s === "nul") return null;
  if (isDevNull(s)) return null;
  if (isAbs(s)) return normAbs(s);
  return joinAbs(base || state.cwd, s);
}

function isSecretTarget(state: State, raw: string, abs: string | null): string | null {
  const candidates = [raw, expandHomeRefs(raw, state.home)];
  if (abs) {
    candidates.push(abs, displayPath(state, abs));
    if (underCI(abs, state.home)) candidates.push("~" + abs.slice(state.home.length));
  }
  return checkSecret(state, candidates);
}

function recordPath(state: State, kind: "read" | "write" | "delete", raw: string, base?: string): void {
  if (!raw) return;
  const candidates = pathCandidates(raw);
  if (!candidates.length) return;
  let word = candidates[candidates.length - 1];
  if (!word || word === "-" || word.startsWith("&") || word.startsWith("<")) return;
  if (isDevNull(word)) return;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(word)) return;
  const foldedRaw = foldExpr(state, raw, 0);
  const folded = foldedRaw !== null ? foldedRaw : foldExpr(state, word, 0);
  let dynamic = false;
  if (folded !== null) word = folded;
  else if ((state.family === "js" || state.family === "python") && /^[A-Za-z_$][\w$]*$/.test(word)) dynamic = true;
  else if (/[`(]/.test(word) || word.includes("${") || /\s\+\s/.test(word)) dynamic = true;
  if (dynamic) {
    if (kind === "write") state.writesDynamic = true;
    else if (kind === "delete") state.deletesDynamic = true;
    return;
  }
  const abs = resolvePath(state, word, base);
  const secret = isSecretTarget(state, word, abs);
  if (secret) addCredential(state, secret);
  if (kind === "read") {
    if (abs && !insideProject(state, abs)) state.readsOutside.add(abs);
    return;
  }
  if (!abs) {
    if (kind === "write") state.writesDynamic = true;
    else state.deletesDynamic = true;
    return;
  }
  const sensitive = !!secret || isHomeWide(state, abs);
  if (sensitive) state.dangerFile = true;
  if (insideProject(state, abs)) return;
  if (kind === "write") state.writesOutside.add(abs);
  else state.deletesOutside.add(abs);
}

function addCommand(state: State, words: string[]): void {
  const line = words.join(" ").trim();
  if (!line) return;
  if (state.commands.size < 100) state.commands.add(line.slice(0, 300));
}

// ---------------------------------------------------------------------------
// Folding: string literals, constant concatenation, simple single-file variables.

function foldExpr(state: State, expr: string, depth = 0): string | null {
  if (depth > 8) return null;
  let s = expr.trim();
  if (!s) return null;
  s = s.replace(/^await\s+/, "").trim();
  s = s.replace(/\s+as\s+(?:const|string|any|unknown|number|boolean)\s*$/, "").trim();
  for (;;) {
    s = s.trim();
    if (s.startsWith("(") && matchingClose(s, 0) === s.length - 1) s = s.slice(1, -1).trim();
    else break;
  }
  if (!s) return null;

  const literally = parseStringLiteral(s);
  if (literally !== null) return literally;

  const tpl = parseTemplate(s);
  if (tpl) return foldTemplate(state, tpl, depth);

  // `["a", "ws"].join("")` builds a string from literal parts, the way a script evades a text match.
  const arrayJoin = s.match(/^\[([\s\S]*)\]\s*\.\s*(join|concat)\s*\(\s*([\s\S]*?)\s*\)$/);
  if (arrayJoin) {
    const parts = splitTopLevel(arrayJoin[1], ",").map((p) => p.trim()).filter(Boolean);
    const separator = arrayJoin[2] === "join" ? foldExpr(state, arrayJoin[3] || "\"\"", depth + 1) : "";
    if (separator === null) return null;
    const values: string[] = [];
    for (const part of parts) {
      const v = foldExpr(state, part, depth + 1);
      if (v === null) return null;
      values.push(v);
    }
    return values.join(separator);
  }

  // Wrappers that decode or reshape a value.
  const suffix = s.match(/^([\s\S]+)\.(?:toString|trim|strip|decodeURIComponent)\s*\(\s*\)$/);
  if (suffix) return foldExpr(state, suffix[1], depth + 1);
  const pathSuffix = s.match(/^([\s\S]+)\.\s*(resolve|absolute|expanduser)\s*\(\s*\)$/);
  if (pathSuffix) {
    const base = foldExpr(state, pathSuffix[1], depth + 1);
    if (base === null) return null;
    if (pathSuffix[2].toLowerCase() === "expanduser") return base.replace(/^~(?=$|[\\/])/, state.home);
    return isAbs(slash(base)) ? normAbs(base) : joinAbs(state.cwd, base);
  }
  const decodeUtf = s.match(/^([\s\S]+)\.decode\s*\(\s*["'](?:utf-?8|ascii)["']\s*\)$/i);
  if (decodeUtf) return foldExpr(state, decodeUtf[1], depth + 1);

  const decoded = foldDecode(state, s, depth);
  if (decoded !== null) return decoded;

  if (state.family === "powershell") {
    const joinPath = s.match(/^Join-Path\s+([\s\S]+)$/i);
    if (joinPath) {
      const parts = psWords(joinPath[1]).filter((p) => !p.startsWith("-"));
      if (!parts.length) return null;
      let out = "";
      for (const part of parts) {
        let v = foldExpr(state, part, depth + 1);
        if (v === null && !/[$`(){}]/.test(part)) v = part;
        if (v === null) return null;
        out = out ? out.replace(/[\\/]+$/, "") + "/" + v.replace(/^[\\/]+/, "") : v;
      }
      return out;
    }
  }

  const call = parseWholeCall(s);
  if (call) {
    const folded = foldCall(state, call.callee, call.args, depth);
    if (folded !== undefined) return folded;
  }

  // `a || b`: the first foldable branch is a value the reader can see. A default such as
  // `Deno.env.get("HOME") || Deno.env.get("USERPROFILE")` folds to the home directory.
  const orParts = splitTopLevelOp(s, "||");
  if (orParts.length > 1) {
    for (const p of orParts) {
      const v = foldExpr(state, p, depth + 1);
      if (v !== null) return v;
    }
  }

  const parts = splitTopLevel(s, "+");
  if (parts.length > 1) {
    let out = "";
    for (const p of parts) {
      const v = foldExpr(state, p, depth + 1);
      if (v === null) return null;
      out += v;
    }
    return out;
  }

  if (state.family === "python") {
    const joinPath = s.match(/^([\s\S]+)\.\s*joinpath\s*\(([\s\S]*)\)$/);
    if (joinPath) {
      const base = foldExpr(state, joinPath[1], depth + 1);
      if (base === null) return null;
      let out = base.replace(/\/+$/, "");
      for (const part of splitTopLevel(joinPath[2], ",")) {
        if (!part.trim()) continue;
        const v = foldExpr(state, part, depth + 1);
        if (v === null) return null;
        out += "/" + v.replace(/^\/+/, "");
      }
      return out;
    }
    const div = splitTopLevel(s, "/");
    if (div.length > 1) {
      let out = "";
      for (const p of div) {
        const v = foldExpr(state, p, depth + 1);
        if (v === null) return null;
        out += (out && !out.endsWith("/") ? "/" : "") + v;
      }
      return out;
    }
  }

  let name = s.trim();
  if (/^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$/.test(name)) name = name.slice(2, -1);
  else if (/^\$([A-Za-z_][A-Za-z0-9_]*)$/.test(name)) name = name.slice(1);
  if (/^[A-Za-z_$][\w$]*$/.test(name)) {
    const v = state.vars.get(name);
    if (v !== undefined) return v;
  }

  if (/^(?:process\.env\s*\.\s*(?:HOME|USERPROFILE)|process\.env\s*\[\s*["'](?:HOME|USERPROFILE)["']\s*\]|os\.environ\s*\[\s*["'](?:HOME|USERPROFILE)["']\s*\]|os\.environ\.get\s*\(\s*["'](?:HOME|USERPROFILE)["']\s*\)|os\.getenv\s*\(\s*["'](?:HOME|USERPROFILE)["']\s*\))$/i.test(s)) {
    return state.home;
  }
  // Deno and Bun name the same variables with their own APIs.
  if (/^(?:Deno\.env\.get\s*\(\s*["'](?:HOME|USERPROFILE)["']\s*\)|Deno\.env\s*\.\s*(?:HOME|USERPROFILE)|Deno\.env\s*\[\s*["'](?:HOME|USERPROFILE)["']\s*\]|Bun\.env\s*\.\s*(?:HOME|USERPROFILE)|Bun\.env\s*\[\s*["'](?:HOME|USERPROFILE)["']\s*\]|Bun\.env\.get\s*\(\s*["'](?:HOME|USERPROFILE)["']\s*\))$/i.test(s)) {
    return state.home;
  }
  const parent = s.match(/^([\s\S]+)\.parent$/);
  if (parent) {
    const base = foldExpr(state, parent[1], depth + 1);
    return base === null ? null : dirName(base);
  }

  if (s === "process.execPath" || s === "Deno.execPath()" || s === "sys.executable") return "node";
  if (s === "import.meta.dirname" || s === "__dirname" || s === "$PSScriptRoot" || s === "${PSScriptRoot}") return state.dir;
  if (s === "import.meta.filename" || s === "__filename") return state.path;
  if (s === "process.cwd()" || s === "os.getcwd()" || s === "Path.cwd()") return state.cwd;
  if (/^(?:process\.env\s*\.\s*PWD|process\.env\s*\[\s*["']PWD["']\s*\]|os\.environ\s*\[\s*["']PWD["']\s*\]|os\.environ\.get\s*\(\s*["']PWD["']\s*\)|os\.getenv\s*\(\s*["']PWD["']\s*\))$/i.test(s)) return state.cwd;
  if (/^(?:process\.env\s*\.\s*(?:TMPDIR|TEMP|TMP)|process\.env\s*\[\s*["'](?:TMPDIR|TEMP|TMP)["']\s*\]|os\.environ\s*\[\s*["'](?:TMPDIR|TEMP|TMP)["']\s*\]|os\.environ\.get\s*\(\s*["'](?:TMPDIR|TEMP|TMP)["']\s*\)|os\.getenv\s*\(\s*["'](?:TMPDIR|TEMP|TMP)["']\s*\))$/i.test(s)) return TMPDIR;
  if (s === "os.tmpdir()" || s === "tmpdir()" || s === "tempfile.gettempdir()") return TMPDIR;
  if (s === "tmp_path" || s === "tmpdir" || s === "tmp_path_factory") return TMPDIR;
  if (s === "os.homedir()" || s === "homedir()" || s === "Path.home()" || s === "pathlib.Path.home()" || s === "expanduser(\"~\")") {
    return state.home;
  }
  return null;
}

function foldDecode(state: State, s: string, depth: number): string | null {
  const call = parseWholeCall(s);
  if (!call) return null;
  const callee = call.callee;
  const base64ish =
    callee === "atob" ||
    callee === "b64decode" ||
    callee === "urlsafe_b64decode" ||
    callee === "base64.b64decode" ||
    callee === "base64.urlsafe_b64decode" ||
    callee === "Convert.FromBase64String" ||
    callee === "System.Convert.FromBase64String";
  if (callee === "Buffer.from" || callee === "buffer.from") {
    if (call.args.length < 2) return null;
    const enc = foldExpr(state, call.args[1], depth + 1);
    if (!enc || enc.toLowerCase() !== "base64") return null;
    const v = foldExpr(state, call.args[0], depth + 1);
    if (v === null) return null;
    try {
      return Buffer.from(v, "base64").toString("utf8");
    } catch {
      return null;
    }
  }
  if (base64ish) {
    const v = foldExpr(state, call.args[0], depth + 1);
    if (v === null) return null;
    try {
      return Buffer.from(v, "base64").toString("utf8");
    } catch {
      return null;
    }
  }
  if (callee === "codecs.decode" && call.args.length >= 2) {
    const enc = foldExpr(state, call.args[1], depth + 1);
    if (!enc || enc.toLowerCase() !== "base64") return null;
    const v = foldExpr(state, call.args[0], depth + 1);
    if (v === null) return null;
    try {
      return Buffer.from(v, "base64").toString("utf8");
    } catch {
      return null;
    }
  }
  return null;
}

function foldCall(state: State, callee: string, args: string[], depth: number): string | null | undefined {
  if (state.family === "python") {
    const direct = state.pyModules.get(callee);
    if (direct) {
      callee = direct;
    } else {
      const first = callee.split(".")[0];
      const mod = state.pyModules.get(first);
      if (mod) callee = mod + callee.slice(first.length);
    }
  }
  const last = callee.split(".").pop() || callee;
  if (last === "tmpdir" || last === "gettempdir") return TMPDIR;
  if (last === "mkdtemp" || last === "mkdtempSync" || last === "mkdtempDisposableSync") {
    if (!args.length) return TMPDIR;
    if (/^\s*[A-Za-z_]\w*\s*=/.test(args[0])) return TMPDIR;
    return foldExpr(state, args[0], depth + 1);
  }
  if (last === "mktemp") {
    if (!args.length) return TMPDIR;
    const name = /^\s*[A-Za-z_]\w*\s*=/.test(args[0]) ? null : foldExpr(state, args[0], depth + 1);
    return name === null ? TMPDIR : joinAbs(TMPDIR, name);
  }
  if (last === "realpath" || last === "realpathSync") {
    return args.length ? foldExpr(state, args[0], depth + 1) : null;
  }
  const joiners = new Set(["join", "joinpath", "resolve", "abspath", "realpath", "normalize", "Path", "PurePath", "path", "Join-Path", "join-path"]);
  if (joiners.has(last) || callee === "os.path.join" || callee === "path.posix.join") {
    if (!args.length) {
      if (last === "resolve" || last === "abspath") return state.cwd;
      return null;
    }
    const vals: string[] = [];
    for (const a of args) {
      const v = foldExpr(state, a, depth + 1);
      if (v === null) return null;
      vals.push(v);
    }
    if (last === "resolve" || last === "abspath" || last === "realpath") {
      let joined = vals[0] || "";
      if (!isAbs(joined) && !/^[A-Za-z]:/.test(joined)) joined = joinAbs(state.cwd, joined);
      for (let i = 1; i < vals.length; i++) joined = joinAbs(joined, vals[i]);
      return normAbs(joined);
    }
    if (last === "normalize") return normAbs(vals[0] || "");
    if (last === "dirname") return dirName(vals[0]);
    if (last === "basename") return baseName(vals[0]);
    let out = vals[0] || "";
    for (let i = 1; i < vals.length; i++) {
      if (!vals[i]) continue;
      out = out.replace(/\/+$/, "") + "/" + vals[i].replace(/^\/+/, "");
    }
    return out;
  }
  if (last === "homedir" || callee === "Path.home" || callee === "pathlib.Path.home" || callee === "home") {
    return state.home;
  }
  if (last === "getcwd" || last === "cwd") return state.cwd;
  if (last === "expanduser") {
    const v = foldExpr(state, args[0] || "", depth + 1);
    if (v === null) return null;
    return v.replace(/^~(?=$|\/)/, state.home);
  }
  if (last === "str" || last === "String" || last === "strval") {
    return args.length ? foldExpr(state, args[0], depth + 1) : null;
  }
  if (last === "dirname" || callee === "os.path.dirname") {
    const v = foldExpr(state, args[0] || "", depth + 1);
    return v === null ? null : dirName(v);
  }
  if (last === "basename" || callee === "os.path.basename") {
    const v = foldExpr(state, args[0] || "", depth + 1);
    return v === null ? null : baseName(v);
  }
  if (last === "fileURLToPath") {
    const v = foldExpr(state, args[0] || "", depth + 1);
    if (v === null) return null;
    return v.replace(/^file:\/\//i, "");
  }
  if (last === "unquote" || last === "decodeURIComponent" || last === "urldecode") {
    const v = foldExpr(state, args[0] || "", depth + 1);
    if (v === null) return null;
    try {
      return decodeURIComponent(v);
    } catch {
      return v;
    }
  }
  if (last === "URL" || callee === "new URL") {
    return args.length ? foldExpr(state, args[0], depth + 1) : null;
  }
  if (last === "joinpath" && callee.includes(".")) {
    return undefined;
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// Assignments: single assignment in this file with a foldable value.

function collectAssignments(state: State): void {
  const code = state.code;
  const exprs = new Map<string, string[]>();
  const add = (name: string, expr: string) => {
    if (!name || !expr) return;
    const list = exprs.get(name) || [];
    list.push(expr.trim());
    exprs.set(name, list);
  };
  if (state.family === "js") {
    for (const m of code.matchAll(/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*[^=;\n]+)?=\s*/g)) {
      const start = (m.index || 0) + m[0].length;
      add(m[1], readAssignmentExpr(code, start));
    }
    for (const m of code.matchAll(/(?<![\w$.[\]])([A-Za-z_$][\w$]*)\s*=(?![=>])\s*/g)) {
      const before = code.slice(Math.max(0, (m.index || 0) - 12), m.index || 0);
      if (/\b(?:const|let|var)\s*$/.test(before)) continue;
      const start = (m.index || 0) + m[0].length;
      add(m[1], readAssignmentExpr(code, start));
    }
  } else if (state.family === "python") {
    for (const m of code.matchAll(/^[ \t]*([A-Za-z_]\w*)\s*(?::\s*[^=\n]+)?\s*=(?!=)\s*([^\n#]+)$/gm)) {
      if (m[2].startsWith("=")) continue;
      add(m[1], m[2]);
    }
  } else if (state.family === "shell") {
    for (const m of code.matchAll(/(?<![\w$])(?:(?:export|local|readonly)\s+|(?:declare|typeset)\s+(?:-[A-Za-z]+\s+)?)?([A-Za-z_]\w*)=("[^"\n]*"|'[^'\n]*'|[^\s;|&]+)/g)) {
      add(m[1], m[2]);
    }
  } else if (state.family === "powershell") {
    for (const m of code.matchAll(/(?:\[[^\]]+\]\s*)?\$([A-Za-z_]\w*)\s*=\s*([^;\n]+)/g)) {
      add(m[1], m[2]);
    }
  }
  // Keep names assigned exactly once with a value that folds; iterate so dependencies resolve.
  for (let pass = 0; pass < 4; pass++) {
    let changed = false;
    for (const [name, list] of exprs) {
      if (list.length !== 1) continue;
      if (state.vars.has(name)) continue;
      const v = foldExpr(state, list[0], 0);
      if (v !== null) {
        state.vars.set(name, v);
        changed = true;
      }
    }
    if (!changed) break;
  }
  for (const [name, list] of exprs) {
    if (list.length !== 1) continue;
    if (!state.vars.has(name)) state.vars.set(name, null);
    if (list[0] && hasDecodeExpr(list[0])) state.tainted.add(name);
    if (state.family === "python" && /\bsocket\s*\.\s*socket\s*\(/.test(list[0])) state.socketVars.add(name);
  }
  if (state.family === "js") {
    for (const [name, list] of exprs) {
      const expr = list[0] || "";
      if (!/child_process/.test(expr)) continue;
      if (/\.\s*(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)\b/.test(expr)) state.cpNames.add(name);
      else state.cpVars.add(name);
    }
    for (const [name, list] of exprs) {
      const bit = (list[0] || "").trim().match(/^([A-Za-z_$][\w$]*)\s*\.\s*(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)\s*$/);
      if (bit && state.cpVars.has(bit[1])) state.cpNames.add(name);
    }
    for (const m of code.matchAll(/import\s+(?:\*\s+as\s+)?([A-Za-z_$][\w$]*)\s+from\s+["'](?:node:)?child_process["']/g)) {
      state.cpVars.add(m[1]);
    }
    for (const m of code.matchAll(/import\s+([A-Za-z_$][\w$]*)\s*,\s*\{([^}]*)\}\s*from\s+["'](?:node:)?child_process["']/g)) {
      state.cpVars.add(m[1]);
      for (const part of m[2].split(",")) {
        const bit = part.trim().match(/^([A-Za-z_$][\w$]*)(?:\s+as\s+([A-Za-z_$][\w$]*))?$/);
        if (bit) state.cpNames.add(bit[2] || bit[1]);
      }
    }
    for (const m of code.matchAll(/import\s*\{([^}]*)\}\s*from\s+["'](?:node:)?child_process["']/g)) {
      for (const part of m[1].split(",")) {
        const bit = part.trim().match(/^([A-Za-z_$][\w$]*)(?:\s+as\s+([A-Za-z_$][\w$]*))?$/);
        if (bit) state.cpNames.add(bit[2] || bit[1]);
      }
    }
    for (const m of code.matchAll(/(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\s*\(\s*["'](?:node:)?child_process["']\s*\)/g)) {
      for (const part of m[1].split(",")) {
        const bit = part.trim().match(/^([A-Za-z_$][\w$]*)(?:\s*:\s*([A-Za-z_$][\w$]*))?$/);
        if (bit) state.cpNames.add(bit[2] || bit[1]);
      }
    }
    for (const m of code.matchAll(/(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*["'](?:node:)?child_process["']\s*\)\s*\.\s*[A-Za-z_$][\w$]*/g)) {
      state.cpNames.add(m[1]);
    }
    for (const m of code.matchAll(/(?:const|let|var)\s*\{([^}]*)\}\s*=\s*([A-Za-z_$][\w$]*)\s*(?:;|\n|$)/g)) {
      if (!state.cpVars.has(m[2])) continue;
      for (const part of m[1].split(",")) {
        const bit = part.trim().match(/^([A-Za-z_$][\w$]*)(?:\s*:\s*([A-Za-z_$][\w$]*))?$/);
        if (bit) state.cpNames.add(bit[2] || bit[1]);
      }
    }
    for (const m of code.matchAll(/(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*["'](?:node-fetch|axios|undici)["']\s*\)/g)) {
      state.httpVars.add(m[1]);
    }
    for (const m of code.matchAll(/(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:axios\.create|got\.extend|ky\.create)\s*\(/g)) {
      state.httpVars.add(m[1]);
    }
    for (const m of code.matchAll(/import\s+([A-Za-z_$][\w$]*)\s*(?:,\s*\{[^}]*\})?\s*from\s+["'](?:node-fetch|axios|undici)["']/g)) {
      state.httpVars.add(m[1]);
    }
    for (const m of code.matchAll(/import\s*\{([^}]*)\}\s*from\s+["'](?:node-fetch|axios|undici)["']/g)) {
      for (const part of m[1].split(",")) {
        const bit = part.trim().match(/^([A-Za-z_$][\w$]*)(?:\s+as\s+([A-Za-z_$][\w$]*))?$/);
        if (bit) state.httpVars.add(bit[2] || bit[1]);
      }
    }
  }
  for (const [name, list] of exprs) {
    if (list.length === 1) state.varExprs.set(name, list[0]);
  }
  if (state.family === "python") {
    for (const m of code.matchAll(/^[ \t]*\(?\s*([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)+)\s*\)?\s*=\s*([^\n#]+)$/gm)) {
      for (const name of m[1].split(",")) {
        const key = name.trim();
        if (key && !state.varExprs.has(key)) state.varExprs.set(key, m[2]);
      }
    }
  }
  for (const m of code.matchAll(/(?:const|let|var)\s*\{([^}]*)\}\s*=\s*([^;\n]+)/g)) {
    for (const part of m[1].split(",")) {
      const bit = part.trim().match(/^([A-Za-z_$][\w$]*)(?:\s*:\s*([A-Za-z_$][\w$]*))?$/);
      if (bit) state.varExprs.set(bit[2] || bit[1], m[2]);
    }
  }
  for (const value of state.vars.values()) {
    if (!value) continue;
    const expanded = expandHomeRefs(value, state.home);
    if (!looksPathLike(expanded) && !/^~/.test(value)) continue;
    const abs = isAbs(expanded) ? normAbs(expanded) : joinAbs(state.cwd, expanded);
    const secret = checkSecret(state, [value, expanded, abs, displayPath(state, abs)]);
    if (secret) addCredential(state, secret);
  }
}

function readAssignmentExpr(code: string, start: number): string {
  let depth = 0;
  let quote = "";
  let end = start;
  for (let i = start; i < code.length; i++) {
    const c = code[i];
    if (quote) {
      end = i + 1;
      if (c === "\\") {
        if (i + 1 < code.length) end = ++i + 1;
        continue;
      }
      if (c === quote) quote = "";
      continue;
    }
    if (c === "'" || c === '"' || c === "`") {
      quote = c;
      end = i + 1;
      continue;
    }
    if (c === "(" || c === "[" || c === "{") depth++;
    else if (c === ")" || c === "]" || c === "}") {
      if (depth === 0) break;
      depth--;
    }
    if ((c === ";" || c === "\n") && depth === 0) break;
    end = i + 1;
  }
  return code.slice(start, end).trim();
}

function collectPythonModules(state: State): void {
  if (state.family !== "python") return;
  for (const m of state.code.matchAll(/^\s*import\s+([\w.]+)(?:\s+as\s+([A-Za-z_]\w*))?/gm)) {
    state.pyModules.set(m[2] || m[1].split(".")[0], m[1]);
  }
  for (const m of state.code.matchAll(/^\s*from\s+([\w.]+)\s+import\s+([^\n#]+)/gm)) {
    const mod = m[1];
    for (const part of m[2].split(",")) {
      const bit = part.trim();
      if (!bit || bit === "*") continue;
      const as = bit.match(/^([A-Za-z_]\w*)(?:\s+as\s+([A-Za-z_]\w*))?$/);
      if (!as) continue;
      state.pyModules.set(as[2] || as[1], mod + "." + as[1]);
    }
  }
}

// ---------------------------------------------------------------------------
// Environment

function shellBoundNames(state: State): Set<string> {
  const names = new Set<string>(state.vars.keys());
  const code = state.code;
  // Loop variables (for f in ...), read targets (while read f), POSIX assignments and
  // PowerShell-style "$p =" that appears inside a -Command string are local bindings.
  for (const m of code.matchAll(/\b(?:for|select)\s+([A-Za-z_]\w*)\s+in\b/g)) names.add(m[1]);
  for (const m of code.matchAll(/\b(?:read|readarray|mapfile)\b([^\n;|&]*)/g)) {
    for (const a of m[1].trim().split(/\s+/)) {
      if (a && !a.startsWith("-")) names.add(a.replace(/["']/g, ""));
    }
  }
  for (const m of code.matchAll(/\$\{?([A-Za-z_]\w*)\}?\s*=(?!=)/g)) names.add(m[1]);
  for (const m of code.matchAll(/(?<![\w$])([A-Za-z_]\w*)\s*=(?!=)/g)) names.add(m[1]);
  return names;
}

function scanEnv(state: State): void {
  const code = state.code;
  if (state.family === "js") {
    let work = code;
    // Destructuring reads named variables, not the whole environment.
    work = work.replace(/(?:const|let|var)\s*\{([^}]*)\}\s*=\s*process\.env\b/g, (m, inner) => {
      for (const part of inner.split(",")) {
        const name = part.split(":")[0].split("=")[0].trim();
        if (/^[A-Za-z_$][\w$]*$/.test(name)) addEnvName(state, name);
      }
      return " ".repeat(m.length);
    });
    // Passing the environment to a child is not dumping it.
    work = work.replace(/(?:["']?env["']?\s*:\s*\{)[^{}]*\.\.\.\s*process\.env[^{}]*\}/g, (m) => " ".repeat(m.length));
    work = work.replace(/(?:["']?env["']?\s*:\s*)process\.env\b/g, (m) => " ".repeat(m.length));
    const named: string[] = [];
    work = work.replace(/process\.env\s*\??\.\s*([A-Za-z_$][\w$]*)/g, (m, name) => {
      named.push(name);
      return " ".repeat(m.length);
    });
    work = work.replace(/process\.env\s*\[\s*["']([^"']+)["']\s*\]/g, (m, name) => {
      named.push(name);
      return " ".repeat(m.length);
    });
    work = work.replace(/process\.env\s*\[\s*[^\]\n]*\]/g, (m) => " ".repeat(m.length));
    // Deno and Bun read the environment through their own APIs.
    work = work.replace(/\bDeno\s*\.\s*env\s*\.\s*get\s*\(\s*["']([^"']+)["']/g, (m, name) => {
      named.push(name);
      return " ".repeat(m.length);
    });
    work = work.replace(/\bBun\s*\.\s*env\s*\.\s*([A-Za-z_$][\w$]*)/g, (m, name) => {
      named.push(name);
      return " ".repeat(m.length);
    });
    work = work.replace(/\b(?:Bun|Deno)\s*\.\s*env\s*\[\s*["']([^"']+)["']\s*\]/g, (m, name) => {
      named.push(name);
      return " ".repeat(m.length);
    });
    for (const n of named) addEnvName(state, n);
    if (/process\.env\b/.test(work)) state.envWhole = true;
    if (/\bDeno\s*\.\s*env\s*\.\s*toObject\s*\(/.test(work)) state.envWhole = true;
    if (/\b(?:Bun|Deno)\s*\.\s*env\b(?!\s*[.[])/.test(work)) state.envWhole = true;
  } else if (state.family === "python") {
    let work = code;
    const named: string[] = [];
    work = work.replace(/os\.environ\s*\[\s*["']([A-Za-z_]\w*)["']\s*\]/g, (m, n) => {
      named.push(n);
      return " ".repeat(m.length);
    });
    work = work.replace(/os\.environ\.(?:get|setdefault|pop)\s*\(\s*["']([A-Za-z_]\w*)["']/g, (m, n) => {
      named.push(n);
      return " ".repeat(m.length);
    });
    work = work.replace(/os\.getenv\s*\(\s*["']([A-Za-z_]\w*)["']/g, (m, n) => {
      named.push(n);
      return " ".repeat(m.length);
    });
    for (const n of named) addEnvName(state, n);
    if (/os\.getenv\s*\(\s*\)/.test(work)) state.envWhole = true;
    work = work.replace(/os\.environ\s*\[\s*[^\]\n]*\]/g, (m) => " ".repeat(m.length));
    work = work.replace(/os\.environ\.(?:get|setdefault|pop)\s*\([^)]*\)/g, (m) => " ".repeat(m.length));
    work = work.replace(/os\.getenv\s*\([^)]*\)/g, (m) => " ".repeat(m.length));
    if (/os\.environb?\b/.test(work)) state.envWhole = true;
  } else if (state.family === "shell") {
    const bound = shellBoundNames(state);
    for (const m of code.matchAll(/\bprintenv\b([^\n;|&]*)/g)) {
      const args = m[1].trim().split(/\s+/).filter((a) => a && !a.startsWith("-"));
      if (!args.length) state.envWhole = true;
      else for (const a of args) addEnvName(state, a.replace(/["']/g, ""));
    }
    for (const m of code.matchAll(/(?:^|[;|&\n]\s*)env\s*(?=[;|&\n]|$)/gm)) {
      state.envWhole = true;
    }
    for (const m of code.matchAll(/(?:^|[;|&\n][ \t]*)(?:set|export|declare|typeset)(?:[ \t]+-p)?[ \t]*(?=[;|&\n]|$)/gm)) {
      state.envWhole = true;
    }
    for (const m of code.matchAll(/\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?/g)) {
      const name = m[1];
      // $f and $p are loop and local variables, not environment reads. A shell name is an env
      // read when it is ALL_CAPS, or when the same code never assigns or binds it.
      if (bound.has(name) && !/^[A-Z][A-Z0-9_]*$/.test(name)) continue;
      addEnvName(state, name);
    }
    for (const m of code.matchAll(/%([A-Za-z_][A-Za-z0-9_]*)%/g)) addEnvName(state, m[1]);
  } else if (state.family === "powershell") {
    for (const m of code.matchAll(/\$env:([A-Za-z_][A-Za-z0-9_]*)/gi)) addEnvName(state, m[1]);
    for (const m of code.matchAll(/\$env\b(?!:)/gi)) state.envWhole = true;
    if (/\b(?:Get-ChildItem|gci|dir|ls|Get-Item|gi|Get-Content|gc)\s+(?:-Path\s+)?["']?env:/i.test(code)) state.envWhole = true;
    if (/\[(?:System\.)?Environment\]::GetEnvironmentVariables|System\.Environment\.GetEnvironmentVariables/i.test(code)) {
      state.envWhole = true;
    }
    for (const m of code.matchAll(/%([A-Za-z_][A-Za-z0-9_]*)%/g)) addEnvName(state, m[1]);
  }
}

// ---------------------------------------------------------------------------
// File calls

const JS_FILE_CALLS =
  /\b(writeFileSync|writeFile|appendFileSync|appendFile|createWriteStream|mkdirSync|mkdir|copyFileSync|copyFile|renameSync|rename|truncateSync|truncate|rmSync|rm|unlinkSync|unlink|rmdirSync|rmdir|rimraf|openSync|readFileSync|readFile|readdirSync|readdir|createReadStream)\s*\(/g;
const JS_FILE_MEMBERS = new Set(["writeFileSync", "writeFile", "appendFileSync", "appendFile", "createWriteStream", "mkdirSync", "mkdir", "copyFileSync", "copyFile", "renameSync", "rename", "truncateSync", "truncate", "rmSync", "rm", "unlinkSync", "unlink", "rmdirSync", "rmdir", "rimraf", "openSync", "readFileSync", "readFile", "readdirSync", "readdir", "createReadStream"]);
const JS_MEMBER_KEYS = new Set([...JS_FILE_MEMBERS, "fetch", "get", "request", "connect", "lookup", "resolve"]);

// Bracket access to a member with a literal or folded string key is the same member as the dot
// form: fs["readFileSync"], fs["read" + "FileSync"], globalThis["fetch"], process["env"].
function normalizeJsMembers(state: State): void {
  for (let pass = 0; pass < 3; pass++) {
    let changed = false;
    state.code = state.code.replace(/([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*\[\s*([^\[\]\n]+?)\s*\]/g, (match, object: string, expr: string) => {
      const key = foldExpr(state, expr, 0);
      if (!key || !/^[A-Za-z_$][\w$]*$/.test(key)) return match;
      const isProcessEnv = key === "env" && /(^|\.)process$/.test(object.trim());
      if (!JS_MEMBER_KEYS.has(key) && !isProcessEnv) return match;
      changed = true;
      return `${object}.${key}`;
    });
    // require("https")["get"] is the same member as require("https").get.
    state.code = state.code.replace(/(require\s*\(\s*["'][^"'\n]+["']\s*\))\s*\[\s*([^\[\]\n]+?)\s*\]/g, (match, object: string, expr: string) => {
      const key = foldExpr(state, expr, 0);
      if (!key || !/^[A-Za-z_$][\w$]*$/.test(key) || !JS_MEMBER_KEYS.has(key)) return match;
      changed = true;
      return `${object}.${key}`;
    });
    if (!changed) break;
  }
}

// A member reached through a local name is the same call: const r = fs.readFileSync; r(p),
// const f = globalThis.fetch; f(u), const { readFileSync: rf } = fs; rf(p). Rewriting the call
// site keeps every later scanner on the code it already knows how to read.
function rewriteJsAliases(state: State): void {
  const aliases = new Map<string, string>();
  const dotForm = (expr: string) => expr.trim().replace(/\[\s*["']([A-Za-z_$][\w$]*)["']\s*\]/g, ".$1");
  const addMember = (name: string, target: string) => {
    if (name && target && name !== target) aliases.set(name, target);
  };
  for (const [name, expr] of state.varExprs) {
    const e = dotForm(expr);
    const last = e.split(".").pop()?.trim() || "";
    if (JS_FILE_MEMBERS.has(last) && /^[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*$/.test(e)) addMember(name, last);
    else if (last === "fetch" && /^[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*$/.test(e)) addMember(name, "fetch");
    else if (/^(?:https?|http2)\.(?:get|request)$|^(?:axios|got|undici|nodeFetch)$/.test(e)) addMember(name, e);
    else {
      // A member of a module named by require: const g = require("https").get; g(url).
      const mod = e.match(/^require\s*\(\s*["'](?:node:)?(https?|http2|net|tls|dns|dns\.promises)["']\s*\)\s*\.\s*([A-Za-z_$][\w$]*)$/);
      if (mod) {
        const receiver = mod[1] === "dns.promises" ? "dns.promises" : mod[1].replace(/^node:/, "");
        addMember(name, `${receiver}.${mod[2]}`);
      }
    }
  }
  // Destructuring with a rename, from the fs module, the global object or process.
  for (const m of state.code.matchAll(/(?:const|let|var)\s*\{([^}]*)\}\s*=\s*(fs|require\s*\(\s*["'](?:node:)?fs["']\s*\)|globalThis|window|self|process)\b/g)) {
    const source = m[2].replace(/\s+/g, "");
    for (const part of m[1].split(",")) {
      const bit = part.trim().match(/^([A-Za-z_$][\w$]*)(?:\s*:\s*([A-Za-z_$][\w$]*))?$/);
      if (!bit) continue;
      const from = bit[1];
      const to = bit[2] || bit[1];
      if (source === "fs" || /require.*fs/.test(source)) {
        if (JS_FILE_MEMBERS.has(from)) addMember(to, from);
      } else if (/globalThis|window|self/.test(source)) {
        if (from === "fetch") addMember(to, "fetch");
      } else if (source === "process" && from === "env") {
        if (to !== "process.env") aliases.set(to, "process.env");
      }
    }
  }
  for (const [name, target] of aliases) {
    const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    if (target === "process.env") {
      state.code = state.code.replace(new RegExp(`(^|[^\\w$.])${escaped}\\s*\\.`, "g"), (_m, pre: string) => `${pre}process.env.`);
      state.code = state.code.replace(new RegExp(`(^|[^\\w$.])${escaped}\\s*\\[`, "g"), (_m, pre: string) => `${pre}process.env[`);
      continue;
    }
    const call = new RegExp(`(^|[^\\w$.])${escaped}\\s*\\(`, "g");
    state.code = state.code.replace(call, (_m, pre: string) => `${pre}${target}(`);
  }
}

// A credential copied into the project cannot be sent anywhere by this file alone, but a reader
// wants the fact. It is not danger on its own: the credential read already asks for review.
function noteCredentialCopy(state: State, src: string | undefined, dest: string | undefined): void {
  if (!src || !dest) return;
  const srcAbs = resolvePath(state, src);
  if (!isSecretTarget(state, src, srcAbs)) return;
  const destAbs = resolvePath(state, dest);
  if (!destAbs || isSecretTarget(state, dest, destAbs)) return;
  if (!insideProject(state, destAbs)) return;
  state.notes.push(`copies a credential into the project: ${displayPath(state, destAbs)}`);
}

function scanJsFiles(state: State): void {
  const structural = maskStrings(state.code, "js");
  for (const m of structural.matchAll(JS_FILE_CALLS)) {
    const name = m[1];
    const open = (m.index || 0) + m[0].lastIndexOf("(");
    const { args } = parseArgs(state.code, open);
    const write = /^(writeFileSync|writeFile|appendFileSync|appendFile|createWriteStream|mkdirSync|mkdir|truncateSync|truncate)$/.test(name);
    const remove = /^(rmSync|rm|unlinkSync|unlink|rmdirSync|rmdir|rimraf)$/.test(name);
    const read = /^(readFileSync|readFile|readdirSync|readdir|createReadStream)$/.test(name);
    if (write) recordPath(state, "write", args[0]);
    else if (remove) recordPath(state, "delete", args[0]);
    else if (read) recordPath(state, "read", args[0]);
    else if (name === "copyFileSync" || name === "copyFile") {
      recordPath(state, "read", args[0]);
      recordPath(state, "write", args[1]);
      noteCredentialCopy(state, args[0], args[1]);
    } else if (name === "renameSync" || name === "rename") {
      recordPath(state, "read", args[0]);
      recordPath(state, "delete", args[0]);
      recordPath(state, "write", args[1]);
    } else if (name === "openSync") {
      const flags = args[1] ? foldExpr(state, args[1], 0) : "r";
      if (flags === null) {
        recordPath(state, "read", args[0]);
        state.writesDynamic = true;
      } else if (/[wax+]/.test(flags)) recordPath(state, "write", args[0]);
      else recordPath(state, "read", args[0]);
    }
  }
  // Deno and Bun read and write files with their own APIs; neither goes through fs.
  for (const m of structural.matchAll(/\bDeno\s*\.\s*(readTextFile|readFile|readDir|writeTextFile|writeFile|appendTextFile|remove)\s*\(/g)) {
    const open = (m.index || 0) + m[0].lastIndexOf("(");
    const { args } = parseArgs(state.code, open);
    const op = m[1];
    if (/^(?:readTextFile|readFile|readDir)$/.test(op)) recordPath(state, "read", args[0]);
    else if (op === "remove") recordPath(state, "delete", args[0]);
    else recordPath(state, "write", args[0]);
  }
  for (const m of structural.matchAll(/\bBun\s*\.\s*(file|write)\s*\(/g)) {
    const open = (m.index || 0) + m[0].lastIndexOf("(");
    const { args } = parseArgs(state.code, open);
    if (m[1] === "file") recordPath(state, "read", args[0]);
    else recordPath(state, "write", args[0]);
  }
}

function pythonOpenMode(args: string[], positional: number): string | null {
  for (const a of args) {
    const kw = a.match(/^\s*mode\s*=\s*([\s\S]+)$/);
    if (kw) return kw[1].trim();
  }
  const direct = args[positional] ? args[positional].trim() : "";
  if (!direct || /^[A-Za-z_]\w*\s*=/.test(direct)) return "r";
  return direct;
}

function scanPythonFiles(state: State): void {
  const structural = maskStrings(state.code, "python");
  const calls = [
    { re: /(?<![\w.])open\s*\(/g, kind: "open", positional: 1 },
    { re: /\b(?:io|codecs|gzip|bz2|lzma)\.open\s*\(/g, kind: "open", positional: 1 },
    { re: /\bPath\s*\(([^()]*)\)\s*\.\s*open\s*\(/g, kind: "pathopen", positional: 0 },
    { re: /\b([A-Za-z_]\w*)\s*\.\s*open\s*\(/g, kind: "pathopen", positional: 0 },
    { re: /\bshutil\.(rmtree|move|copy|copy2|copyfile|copytree)\s*\(/g, kind: "shutil" },
    { re: /\bos\.(remove|unlink|rmdir|removedirs|makedirs|mkdir|rename|replace)\s*\(/g, kind: "os" },
    { re: /\bPath\s*\(([^()]*)\)\s*\.\s*(write_text|write_bytes|read_text|read_bytes|unlink|rmdir|mkdir)\s*\(/g, kind: "pathcall" },
    { re: /\b([A-Za-z_]\w*)\s*\.\s*(write_text|write_bytes|read_text|read_bytes|unlink|rmdir|mkdir)\s*\(/g, kind: "pathvar" },
  ];
  for (const spec of calls) {
    for (const m of state.code.matchAll(spec.re)) {
      // A call written inside a string literal is text, not a write call.
      if (maskedAt(structural, state.code, m.index || 0)) continue;
      const open = findOpenParen(state.code, (m.index || 0) + m[0].length - 1);
      if (open < 0) continue;
      const { args, end } = parseArgs(state.code, open);
      if (spec.kind === "open" || spec.kind === "pathopen") {
        if (spec.kind === "pathopen" && /^(?:io|codecs|gzip|bz2|lzma)$/i.test(m[1] || "")) continue;
        const modeExpr = pythonOpenMode(args, spec.positional);
        const mode = modeExpr === null ? null : foldExpr(state, modeExpr, 0);
        const receiver = spec.kind === "pathopen" ? (m[0].trim().startsWith("Path(") ? `Path(${m[1]})` : m[1]) : args[0];
        if (mode === null || (mode && /[wax+]/.test(mode))) recordPath(state, "write", receiver);
        else recordPath(state, "read", receiver);
      } else if (spec.kind === "shutil") {
        if (m[1] === "rmtree") recordPath(state, "delete", args[0]);
        else if (m[1] === "move") {
          recordPath(state, "read", args[0]);
          recordPath(state, "delete", args[0]);
          recordPath(state, "write", args[1]);
        } else {
          recordPath(state, "read", args[0]);
          recordPath(state, "write", args[1] || args[0]);
        }
      } else if (spec.kind === "os") {
        if (["remove", "unlink", "rmdir", "removedirs"].includes(m[1])) recordPath(state, "delete", args[0]);
        else if (m[1] === "rename" || m[1] === "replace") {
          recordPath(state, "read", args[0]);
          recordPath(state, "delete", args[0]);
          recordPath(state, "write", args[1]);
        } else recordPath(state, "write", args[0]);
      } else {
        const receiver = spec.kind === "pathcall" ? (m[1] ? `Path(${m[1]})` : "") : m[1];
        const op = m[2];
        if (/^read_/.test(op)) recordPath(state, "read", receiver);
        else if (op === "unlink" || op === "rmdir") recordPath(state, "delete", receiver);
        else recordPath(state, "write", receiver);
        void end;
      }
    }
  }
  // Path(...).read_text() where the constructor is a single expression.
  for (const m of state.code.matchAll(/Path\s*\(([^()]*)\)\s*\.\s*(?:read_text|read_bytes)\s*\(/g)) {
    if (maskedAt(structural, state.code, m.index || 0)) continue;
    recordPath(state, "read", `Path(${m[1]})`);
  }
  // A glob of a secret directory reads whatever the directory holds.
  for (const m of state.code.matchAll(/\bglob\s*\.\s*(?:glob|iglob)\s*\(/g)) {
    if (maskedAt(structural, state.code, m.index || 0)) continue;
    const open = (m.index || 0) + m[0].lastIndexOf("(");
    const { args } = parseArgs(state.code, open);
    if (args[0]) recordPath(state, "read", args[0]);
  }
  for (const m of state.code.matchAll(/\bPath\s*\(([^()]*)\)\s*\.\s*(?:glob|rglob)\s*\(/g)) {
    if (maskedAt(structural, state.code, m.index || 0)) continue;
    const open = (m.index || 0) + m[0].lastIndexOf("(");
    const { args } = parseArgs(state.code, open);
    const base = foldExpr(state, `Path(${m[1]})`, 0);
    const pattern = args[0] ? foldExpr(state, args[0], 0) : null;
    if (!base) continue;
    recordPath(state, "read", pattern ? base.replace(/\/+$/, "") + "/" + pattern.replace(/^\/+/, "") : base);
  }
}

function findOpenParen(code: string, near: number): number {
  for (let i = Math.max(0, near - 2); i < Math.min(code.length, near + 3); i++) {
    if (code[i] === "(") return i;
  }
  const idx = code.indexOf("(", near);
  return idx;
}

const PS_VALUE_OPTIONS = new Set([
  "path", "literalpath", "filepath", "itempath", "destination", "source", "outfile", "infile",
  "value", "itemtype", "name", "newname", "filter", "include", "exclude", "encoding", "credential",
  "method", "uri", "url", "body", "headers", "contenttype", "type", "inputobject",
  "property", "argumentlist", "workingdirectory", "redirectstandardoutput", "redirectstandarderror",
  "erroraction", "warningaction", "informationaction", "progressaction", "depth", "stream",
]);

function psParse(words: string[], start: number): { positional: string[]; paths: string[]; outFiles: string[]; inFiles: string[]; uris: string[] } {
  const positional: string[] = [];
  const paths: string[] = [];
  const outFiles: string[] = [];
  const inFiles: string[] = [];
  const uris: string[] = [];
  for (let i = start; i < words.length; i++) {
    const a = words[i];
    if (!a) continue;
    if (a.startsWith("-") && a.length > 1) {
      let opt = a.replace(/^-+/, "").toLowerCase();
      let inline: string | undefined;
      const colon = opt.indexOf(":");
      if (colon >= 0) {
        inline = opt.slice(colon + 1);
        opt = opt.slice(0, colon);
      }
      let value = inline;
      if (value === undefined && PS_VALUE_OPTIONS.has(opt)) value = words[++i];
      if (value === undefined) continue;
      if (["path", "literalpath", "filepath", "itempath", "destination", "source", "newname"].includes(opt)) paths.push(value);
      if (opt === "outfile") {
        outFiles.push(value);
        paths.push(value);
      }
      if (opt === "infile") {
        inFiles.push(value);
        paths.push(value);
      }
      if (opt === "uri" || opt === "url") uris.push(value);
      continue;
    }
    positional.push(a);
  }
  return { positional, paths, outFiles, inFiles, uris };
}

function scanPowerShellFiles(state: State): void {
  const aliases = /^(get-content|gc|cat|type|remove-item|ri|del|erase|rd|rmdir|set-content|add-content|out-file|new-item|copy-item|move-item|rename-item|clear-content|get-childitem|gci|dir|ls|test-path|resolve-path)$/i;
  for (const seg of shellSegments(stripPsComments(state.code))) {
    const words = psWords(seg);
    const cmd = commandOf(words);
    if (!cmd) continue;
    const name = baseName(cmd.replace(/\.exe$/i, "")).toLowerCase();
    if (!aliases.test(name)) continue;
    const at = words.indexOf(cmd);
    const parsed = psParse(words, at + 1);
    const readTargets = parsed.paths.length ? parsed.paths : parsed.positional.slice(0, 1);
    if (/^(get-content|gc|cat|type|get-childitem|gci|dir|ls|test-path|resolve-path)$/.test(name)) {
      for (const a of readTargets) recordPath(state, "read", a);
    } else if (/^(remove-item|ri|del|erase|rd|rmdir)$/.test(name)) {
      const targets = parsed.paths.length ? parsed.paths : parsed.positional;
      for (const a of targets) recordPath(state, "delete", a);
    } else if (/^(set-content|add-content|out-file|new-item|clear-content)$/.test(name)) {
      const target = parsed.paths[0] || parsed.positional[0];
      if (target) recordPath(state, "write", target);
    } else if (/^(copy-item|move-item|rename-item)$/.test(name)) {
      const source = parsed.paths[0] || parsed.positional[0];
      const dest = parsed.paths[1] || parsed.positional[1] || (name === "rename-item" ? parsed.positional[1] : undefined);
      if (source) recordPath(state, "read", source);
      if (name === "move-item" && source) recordPath(state, "delete", source);
      if (dest) recordPath(state, "write", dest);
    }
  }
  for (const seg of shellSegments(stripPsComments(state.code))) recordShellRedirections(state, seg, state.cwd);
}

// ---------------------------------------------------------------------------
// Network

const JS_NETWORK_CALLS: { re: RegExp; kind: "url" | "request" | "socket" | "options" | "xhr" }[] = [
  { re: /\bfetch\s*\(/g, kind: "url" },
  { re: /\b(?:https?|http2)\.(?:get|request)\s*\(/g, kind: "url" },
  { re: /\bnet\.(?:connect|createConnection)\s*\(/g, kind: "socket" },
  { re: /\btls\.connect\s*\(/g, kind: "socket" },
  { re: /\bnew\s+WebSocket\s*\(/g, kind: "url" },
  { re: /\bWebSocket\s*\(/g, kind: "url" },
  { re: /\baxios(?:\s*\.\s*[A-Za-z_$][\w$]*)?\s*\(/g, kind: "url" },
  { re: /\bundici\.(?:fetch|request)\s*\(/g, kind: "url" },
  { re: /\bnodeFetch\s*\(/g, kind: "url" },
  { re: /\bgot(?:\s*\.\s*[A-Za-z_$][\w$]*)?\s*\(/g, kind: "url" },
  { re: /\bnew\s+EventSource\s*\(/g, kind: "url" },
  { re: /\bXMLHttpRequest\s*\(/g, kind: "xhr" },
  { re: /\brequire\s*\(\s*["'](?:node:)?https?["']\s*\)\s*\.\s*(?:get|request)\s*\(/g, kind: "url" },
  { re: /\brequire\s*\(\s*["'](?:node:)?net["']\s*\)\s*\.\s*connect\s*\(/g, kind: "socket" },
  { re: /\brequire\s*\(\s*["'](?:node:)?tls["']\s*\)\s*\.\s*connect\s*\(/g, kind: "socket" },
  // Name resolution is a network call: the name it asks for is the destination.
  { re: /\bdns(?:\.promises)?\s*\.\s*(?:lookup|lookupService|resolve[A-Za-z0-9]*)\s*\(/g, kind: "url" },
  { re: /\brequire\s*\(\s*["'](?:node:)?dns(?:\.promises)?["']\s*\)\s*\.\s*(?:lookup|resolve[A-Za-z0-9]*)\s*\(/g, kind: "url" },
  { re: /\bDeno\s*\.\s*(?:connect|connectTls)\s*\(/g, kind: "socket" },
];

function scanJsNetwork(state: State): void {
  const structural = maskStrings(state.code, "js");
  const original = state.code;
  const seen = new Set<number>();
  for (const alias of state.httpVars) {
    const escaped = alias.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const direct = new RegExp(`\\b${escaped}\\s*\\(`, "g");
    for (const m of original.matchAll(direct)) {
      if (maskedAt(structural, original, m.index || 0)) continue;
      const open = (m.index || 0) + m[0].lastIndexOf("(");
      const { args } = parseArgs(original, open);
      classifyNetworkArg(state, args[0] || "");
    }
    const methods = new RegExp(`\\b${escaped}\\s*\\.\\s*(?:get|post|put|delete|patch|head|options|request)\\s*\\(`, "g");
    for (const m of original.matchAll(methods)) {
      if (maskedAt(structural, original, m.index || 0)) continue;
      const open = (m.index || 0) + m[0].lastIndexOf("(");
      const { args } = parseArgs(original, open);
      classifyNetworkArg(state, args[0] || "");
    }
  }
  for (const spec of JS_NETWORK_CALLS) {
    for (const m of original.matchAll(spec.re)) {
      if (maskedAt(structural, original, m.index || 0)) continue;
      const open = (m.index || 0) + m[0].lastIndexOf("(");
      if (seen.has(open)) continue;
      seen.add(open);
      const { args } = parseArgs(original, open);
      if (spec.kind === "socket") {
        const first = (args[0] || "").trim();
        if (first.startsWith("{")) {
          if (/\b(?:host|hostname|socketPath)\s*:/.test(first)) classifyNetworkArg(state, first);
          else state.loopback = true; // net.connect defaults to localhost
        } else {
          const hostArg =
            args[1] && !/^\d+$/.test(args[1].trim())
              ? args[1]
              : args[0] && !/^\d+$/.test(args[0].trim())
                ? args[0]
                : undefined;
          if (hostArg) classifyNetworkArg(state, hostArg);
          else state.loopback = true;
        }
        continue;
      }
      if (spec.kind === "xhr") {
        const openCall = original.slice(open).match(/\.\s*open\s*\(\s*["'][A-Za-z]+["']\s*,\s*([^)]+)\)/);
        if (openCall) classifyNetworkArg(state, openCall[1]);
        else markDynamicNetwork(state);
        continue;
      }
      classifyNetworkArg(state, args[0] || "");
    }
  }
  for (const m of original.matchAll(/\.\s*open\s*\(\s*["'](?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)["']\s*,\s*([^)]+)\)/gi)) {
    if (maskedAt(structural, original, m.index || 0)) continue;
    classifyNetworkArg(state, m[1]);
  }
}

function pythonUrlArg(args: string[], positional: number): string {
  for (const a of args) {
    const kw = a.match(/^\s*(?:url|uri)\s*=\s*([\s\S]+)$/);
    if (kw) return kw[1].trim();
  }
  return args[positional] || "";
}

function pythonTupleHost(expr: string): string {
  const tuple = expr.match(/\(\s*([^,]+),/);
  return tuple ? tuple[1].trim() : expr;
}

function scanPythonNetwork(state: State): void {
  const aliases = [...state.pyModules.entries()];
  const roots = new Set<string>(["requests", "httpx", "urllib", "urllib2", "urllib3", "aiohttp"]);
  for (const [alias, mod] of aliases) if (/^(requests|httpx|urllib|urllib2|urllib3|aiohttp)/.test(mod)) roots.add(alias);
  for (const root of roots) {
    const escaped = root.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const re = new RegExp(`\\b${escaped}\\s*\\.\\s*(?:get|post|put|delete|patch|head|options|request|urlopen|urlretrieve|Request|HTTPConnection|HTTPSConnection|SMTP|FTP|ClientSession)\\s*\\(`, "g");
    for (const m of state.code.matchAll(re)) {
      const open = (m.index || 0) + m[0].lastIndexOf("(");
      const { args } = parseArgs(state.code, open);
      const method = (m[0].match(/\.\s*(\w+)/) || [])[1] || "";
      if (/^(request)$/i.test(method) && args.length >= 2) classifyNetworkArg(state, pythonUrlArg(args, 1));
      else classifyNetworkArg(state, pythonUrlArg(args, 0));
    }
  }
  // `from requests import post as p` and friends become bare calls.
  const networkFunctions = new Set(["get", "post", "put", "delete", "patch", "head", "options", "request", "urlopen", "urlretrieve"]);
  for (const [alias, mod] of aliases) {
    if (!/^(?:requests|httpx|urllib|urllib2|urllib3|aiohttp)(?:\.|$)/.test(mod)) continue;
    const tail = mod.split(".").pop() || "";
    if (!networkFunctions.has(tail)) continue;
    const escaped = alias.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const re = new RegExp(`\\b${escaped}\\s*\\(`, "g");
    for (const m of state.code.matchAll(re)) {
      const open = (m.index || 0) + m[0].lastIndexOf("(");
      const { args } = parseArgs(state.code, open);
      classifyNetworkArg(state, pythonUrlArg(args, tail === "request" ? 1 : 0));
    }
  }
  for (const m of state.code.matchAll(/\b(?:urlopen|urlretrieve)\s*\(/g)) {
    const open = (m.index || 0) + m[0].lastIndexOf("(");
    const { args } = parseArgs(state.code, open);
    classifyNetworkArg(state, pythonUrlArg(args, 0));
  }
  for (const m of state.code.matchAll(/\burllib(?:2)?\.request\.(?:urlopen|urlretrieve)\s*\(/g)) {
    const open = (m.index || 0) + m[0].lastIndexOf("(");
    const { args } = parseArgs(state.code, open);
    classifyNetworkArg(state, pythonUrlArg(args, 0));
  }
  for (const m of state.code.matchAll(/\bsocket\.(?:create_connection|create_server)\s*\(/g)) {
    const open = (m.index || 0) + m[0].lastIndexOf("(");
    const { args } = parseArgs(state.code, open);
    if (m[0].includes("server")) state.loopback = true;
    else classifyNetworkArg(state, pythonTupleHost(args[0] || ""));
  }
  for (const m of state.code.matchAll(/\bsocket\.socket\s*\(\s*\)\s*\.\s*connect\s*\(/g)) {
    const open = (m.index || 0) + m[0].lastIndexOf("(");
    const { args } = parseArgs(state.code, open);
    classifyNetworkArg(state, pythonTupleHost(args[0] || ""));
  }
  for (const m of state.code.matchAll(/\b(?:HTTPConnection|HTTPSConnection)\s*\(/g)) {
    const open = (m.index || 0) + m[0].lastIndexOf("(");
    const { args } = parseArgs(state.code, open);
    classifyNetworkArg(state, args[0] || "");
  }
  for (const v of state.socketVars) {
    const re = new RegExp(`\\b${v.replace(/[.*+?^${}()|[\\]\\\\]/g, "\\\\$&")}\\s*\\.\\s*connect\\s*\\(`, "g");
    for (const m of state.code.matchAll(re)) {
      const open = (m.index || 0) + m[0].lastIndexOf("(");
      const { args } = parseArgs(state.code, open);
      classifyNetworkArg(state, pythonTupleHost(args[0] || ""));
    }
  }
  for (const m of state.code.matchAll(/\bsocket\s*\.\s*(?:gethostbyname(?:_ex)?|getaddrinfo|getfqdn)\s*\(/g)) {
    const open = (m.index || 0) + m[0].lastIndexOf("(");
    const { args } = parseArgs(state.code, open);
    classifyNetworkArg(state, args[0] || "");
  }
  for (const m of state.code.matchAll(/\b(?:smtplib|ftplib)\.(?:SMTP|FTP)\s*\(/g)) {
    const open = (m.index || 0) + m[0].lastIndexOf("(");
    const { args } = parseArgs(state.code, open);
    classifyNetworkArg(state, args[0] || "");
  }
  // Sessions: session.get(url) after requests.Session() / aiohttp.ClientSession().
  const sessionVars = new Set<string>();
  const sessionAssign = state.code.match(/\b([A-Za-z_]\w*)\s*=\s*(?:(?:requests|httpx)\.(?:Session|AsyncClient)|aiohttp\.ClientSession)\s*\(/);
  if (sessionAssign) sessionVars.add(sessionAssign[1]);
  for (const m of state.code.matchAll(/(?:async\s+with|with)\s+(?:(?:requests|httpx)\.(?:Session|AsyncClient)|(?:aiohttp\.)?ClientSession)\s*\([^)]*\)\s+as\s+([A-Za-z_]\w*)/g)) {
    sessionVars.add(m[1]);
  }
  for (const session of sessionVars) {
    const re = new RegExp(`\\b${session}\\s*\\.\\s*(?:get|post|put|delete|patch|head|options|request)\\s*\\(`, "g");
    for (const m of state.code.matchAll(re)) {
      const open = (m.index || 0) + m[0].lastIndexOf("(");
      const { args } = parseArgs(state.code, open);
      classifyNetworkArg(state, pythonUrlArg(args, 0));
    }
  }
  for (const m of state.code.matchAll(/(?:requests|httpx)\.(?:Session|AsyncClient)\s*\(\s*\)\s*\.\s*(?:get|post|put|delete|patch|head|options|request)\s*\(/g)) {
    const open = (m.index || 0) + m[0].lastIndexOf("(");
    const { args } = parseArgs(state.code, open);
    classifyNetworkArg(state, pythonUrlArg(args, 0));
  }
}

function scanPowerShellNetwork(state: State): void {
  const clients = /^(invoke-webrequest|iwr|invoke-restmethod|irm|curl|wget|start-bitstransfer|downloadstring|downloadfile|downloaddata|uploadstring|uploadfile|uploaddata|uploadvalues|openread|openwrite)$/i;
  for (const seg of shellSegments(stripPsComments(state.code))) {
    const words = psWords(seg);
    const cmd = commandOf(words);
    if (!cmd) continue;
    const name = baseName(cmd).toLowerCase();
    if (!clients.test(name)) continue;
    const at = words.indexOf(cmd);
    const parsed = psParse(words, at + 1);
    for (const p of parsed.paths) {
      if (/^[a-z][a-z0-9+.-]*:\/\//i.test(p)) classifyNetworkArg(state, p);
    }
    const dest = parsed.uris[0] || parsed.positional[0];
    if (dest) classifyNetworkArg(state, dest);
    else markDynamicNetwork(state);
    for (const f of parsed.inFiles) recordPath(state, "read", f);
    for (const f of parsed.outFiles) recordPath(state, "write", f);
  }
  for (const m of state.code.matchAll(/\b(?:DownloadString|DownloadFile|DownloadData|UploadString|UploadFile|UploadData|OpenRead|OpenWrite)\s*\(\s*([^)]+)\)/gi)) {
    const first = (m[1].split(",")[0] || "").trim();
    classifyNetworkArg(state, first);
  }
  for (const m of state.code.matchAll(/\bTcpClient\s*\(\s*([^)]+)\)/gi)) {
    const { args } = parseArgs(state.code, (m.index || 0) + m[0].lastIndexOf("("));
    classifyNetworkArg(state, args[0] || "");
  }
  if (/\bTcpListener\b|\bHttpListener\b/i.test(state.code)) state.loopback = true;
}

function detectServerListen(state: State): void {
  if (state.family === "js") {
    if (/\.listen\s*\(/.test(state.code)) state.loopback = true;
    if (/\.listen\s*\(\s*(?:0|\d+|[["'`](?:127\.|localhost|::1))/i.test(state.code)) state.loopback = true;
    if (/\.listen\s*\(\s*\{[^}]*port\s*:\s*0/i.test(state.code)) state.loopback = true;
  } else if (state.family === "python") {
    if (/\.listen\s*\(/.test(state.code)) state.loopback = true;
    if (/\.listen\s*\(\s*(?:\d+|\(?\s*["']127\.)/.test(state.code)) state.loopback = true;
    if (/\b(?:HTTPServer|TCPServer|ThreadingHTTPServer)\s*\(\s*\(\s*["'](?:127\.|localhost|::1|0\.0\.0\.0)/.test(state.code)) state.loopback = true;
    if (/\b(?:HTTPServer|TCPServer|ThreadingHTTPServer)\s*\(\s*\(\s*["'][^"']*["']\s*,\s*\d+/.test(state.code)) state.loopback = true;
  } else if (state.family === "shell") {
    if (/(?:^|[;&|]\s*)(?:python3?\s+-m\s+http\.server|npx\s+serve|node\s+[^\s]*server)/m.test(state.code)) state.loopback = true;
    if (/\blisten\s*\(/.test(state.code)) state.loopback = true;
  }
  // A detected listen means the script starts its own local server.
  if (state.loopback) state.serverListen = true;
}

// ---------------------------------------------------------------------------
// Shell

function shellSegments(code: string): string[] {
  const segments: string[] = [];
  let cur = "";
  let quote = "";
  let i = 0;
  const push = () => {
    const t = cur.trim();
    if (t) segments.push(t);
    cur = "";
  };
  while (i < code.length) {
    const c = code[i];
    if (quote) {
      cur += c;
      if (c === "\\" && quote !== "'") {
        if (i + 1 < code.length) cur += code[++i];
        i++;
        continue;
      }
      if (c === quote) quote = "";
      i++;
      continue;
    }
    if (c === "'" || c === '"') {
      quote = c;
      cur += c;
      i++;
      continue;
    }
    if (c === "\\" && i + 1 < code.length) {
      cur += c + code[i + 1];
      i += 2;
      continue;
    }
    if (c === "\n" || c === ";") {
      push();
      i++;
      continue;
    }
    if (c === "&") {
      if (code[i + 1] === "&") {
        push();
        i += 2;
        continue;
      }
      const prev = cur.trimEnd().slice(-1);
      if (prev === ">" || prev === "<") {
        cur += c;
        i++;
        continue;
      }
      push();
      i++;
      continue;
    }
    if (c === "|") {
      if (code[i + 1] === "|") {
        push();
        i += 2;
        continue;
      }
      push();
      i++;
      continue;
    }
    cur += c;
    i++;
  }
  push();
  return segments;
}

function shellWords(seg: string): string[] {
  const words: string[] = [];
  let cur = "";
  let quote = "";
  let started = false;
  for (let i = 0; i < seg.length; i++) {
    const c = seg[i];
    if (quote === "'") {
      if (c === quote) quote = "";
      else cur += c;
      continue;
    }
    if (quote === '"') {
      if (c === '"') {
        quote = "";
        continue;
      }
      if (c === "\\") {
        const next = seg[i + 1];
        if (next && /[$`"\\\n]/.test(next)) {
          cur += next;
          i++;
        } else {
          cur += "\\";
        }
        continue;
      }
      cur += c;
      continue;
    }
    if (c === "'" || c === '"') {
      quote = c;
      started = true;
      continue;
    }
    if (c === "\\" && i + 1 < seg.length) {
      const next = seg[i + 1];
      if (/\s/.test(next) || /[;|&()<>"'`]/.test(next)) {
        cur += next;
        i++;
        started = true;
        continue;
      }
      // Keep Windows separators and other literal backslashes.
      cur += "\\";
      started = true;
      continue;
    }
    if (/\s/.test(c)) {
      if (started) {
        words.push(cur);
        cur = "";
        started = false;
      }
      continue;
    }
    cur += c;
    started = true;
  }
  if (started) words.push(cur);
  return words.filter((w) => w !== "");
}

function psWords(seg: string): string[] {
  const words: string[] = [];
  let cur = "";
  let quote = "";
  let started = false;
  for (let i = 0; i < seg.length; i++) {
    const c = seg[i];
    if (quote) {
      if (c === "`" && quote === '"') {
        if (i + 1 < seg.length) cur += seg[++i];
        continue;
      }
      if (c === quote) {
        quote = "";
        continue;
      }
      cur += c;
      continue;
    }
    if (c === "'") {
      quote = c;
      started = true;
      continue;
    }
    if (c === '"') {
      quote = c;
      started = true;
      continue;
    }
    if (c === "`") {
      const next = seg[i + 1];
      if (next === undefined) continue;
      if (next === "\n" || next === "\r") {
        i++;
        continue;
      }
      cur += next;
      i++;
      started = true;
      continue;
    }
    if (/\s/.test(c)) {
      if (started) {
        words.push(cur);
        cur = "";
        started = false;
      }
      continue;
    }
    cur += c;
    started = true;
  }
  if (started) words.push(cur);
  return words.filter((w) => w !== "");
}

function commandOf(words: string[]): string | undefined {
  for (let i = 0; i < words.length; i++) {
    const w = words[i];
    if (!w) continue;
    if (/^[A-Za-z_]\w*=/.test(w)) continue;
    if (/^\$[A-Za-z_]\w*$/.test(w) && words[i + 1] === "=") {
      i++;
      continue;
    }
    if (w === "=") continue;
    if (/^(?:sudo|command|builtin|nohup|time|exec|then|do|else|if|while|until|!)$/.test(w)) continue;
    if (w === "env") {
      while (i + 1 < words.length && (/^[A-Za-z_]\w*=/.test(words[i + 1]) || words[i + 1].startsWith("-"))) i++;
      continue;
    }
    return w;
  }
  return undefined;
}

function optionValue(name: string, arg: string): boolean {
  const bare = arg.replace(/^-+/, "").replace(/=.*$/, "");
  const sets: Record<string, string[]> = {
    curl: "d data data-raw data-binary data-urlencode F form H header X request o output u user A user-agent e referer b cookie c cookie-jar T upload-file x proxy E cert key cacert resolve connect-to m max-time retry w write-out K config".split(" "),
    wget: "O output-document header body-data post-file method user password e execute T timeout".split(" "),
    ssh: "p i l o F J L R D W b c m e S".split(" "),
    scp: "P i o F J S c l".split(" "),
    rsync: "e rsh l bw timeout port partial-dir backup-dir log-file password-file".split(" "),
    nc: "p s w i q X x e c".split(" "),
    ncat: "p s w i q X x e c".split(" "),
    socat: "".split(" "),
  };
  return (sets[name] || []).includes(bare);
}

function isRedirectToken(word: string): boolean {
  return /^(?:\d*(?:>>?|<)|&>>?)\S*$/.test(word);
}

// A bare operator (>, >>, 2>) carries its target as the next word; a glued one (2>/dev/null)
// carries it already. Either way the operator's target is not a command argument.
function dropRedirectWords(words: string[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < words.length; i++) {
    const w = words[i];
    if (!isRedirectToken(w)) {
      out.push(w);
      continue;
    }
    if (/^(?:\d*(?:>>?|<)|&>>?)$/.test(w)) i++;
  }
  return out;
}

function stripOptions(args: string[], optsWithValue: string[] = []): string[] {
  const out: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--") {
      out.push(...args.slice(i + 1));
      break;
    }
    // Option words (including numeric options such as head -30 and values such as head -c 3000),
    // stdin/stdout and redirect operators are not paths.
    if (!a || a === "-") continue;
    if (isRedirectToken(a)) {
      if (/^(?:\d*(?:>>?|<)|&>>?)$/.test(a)) i++;
      continue;
    }
    if (/^-/.test(a)) {
      if (a.includes("=")) continue;
      if (optsWithValue.includes(a.replace(/^-+/, ""))) i++;
      continue;
    }
    out.push(a);
  }
  return out;
}

function recordShellRedirections(state: State, segment: string, base: string): void {
  let quote = "";
  for (let i = 0; i < segment.length; i++) {
    const c = segment[i];
    if (quote) {
      if (c === "\\" && quote !== "'" && i + 1 < segment.length) {
        i++;
        continue;
      }
      if (c === quote) quote = "";
      continue;
    }
    if (c === "'" || c === '"') {
      quote = c;
      continue;
    }
    if (c === "\\" && i + 1 < segment.length) {
      i++;
      continue;
    }
    if (c !== ">") continue;
    // JavaScript arrows in an inline program (=> and ->) are not shell redirections.
    if (i > 0 && (segment[i - 1] === "=" || segment[i - 1] === "-")) continue;
    let j = i + 1;
    if (segment[j] === ">") j++;
    if (segment[j] === "&") continue; // 2>&1 duplicates a stream, no file
    while (j < segment.length && /[ \t]/.test(segment[j])) j++;
    if (j >= segment.length) return;
    let target = "";
    if (segment[j] === '"' || segment[j] === "'") {
      const q = segment[j];
      j++;
      while (j < segment.length) {
        const ch = segment[j];
        if (ch === "\\" && q === '"' && j + 1 < segment.length) {
          target += segment[j + 1];
          j += 2;
          continue;
        }
        if (ch === q) {
          j++;
          break;
        }
        target += ch;
        j++;
      }
    } else {
      const start = j;
      while (j < segment.length && !/[\s;|&<>]/.test(segment[j])) j++;
      target = segment.slice(start, j);
    }
    if (target && !target.startsWith("&") && !target.startsWith("(") && !target.includes("$(")) {
      recordPath(state, "write", target, base);
    }
    i = j - 1;
  }
}

function analyzeInlineArg(state: State, inner: string, lang: "js" | "python" | "powershell" | "bash", depth: number, cwd: string): void {
  const code = unquote(inner || "");
  if (!code) return;
  if (/^\$\{?[A-Za-z_]\w*\}?$/.test(code.trim())) {
    state.execDynamic = true;
    return;
  }
  if (lang === "bash") analyzeShell(state, code, depth, cwd);
  else analyzeInline(state, code, lang, depth);
}

function analyzeShell(state: State, text: string, depth = 0, base = state.cwd): void {
  if (depth > 3) return;
  noteShellObfuscation(state, text);
  // Command substitution is still code.
  for (const m of text.matchAll(/\$\(([^()]*)\)/g)) analyzeShell(state, m[1], depth + 1, base);
  for (const m of text.matchAll(/`([^`]*)`/g)) analyzeShell(state, m[1], depth + 1, base);
  let cwd = base;
  for (const segment of shellSegments(text)) {
    recordShellRedirections(state, segment, cwd);
    const words = dropRedirectWords(shellWords(segment));
    if (!words.length) continue;
    const cmd = commandOf(words);
    if (!cmd) continue;
    const idx = words.indexOf(cmd);
    const args = words.slice(idx + 1);
    const name = baseName(cmd.replace(/\.exe$/i, "")).toLowerCase();
    addCommand(state, [cmd, ...args].slice(0, 20));
    if (name === "cd" || name === "pushd") {
      const target = args.find((a) => !a.startsWith("-"));
      if (target) {
        const abs = resolvePath(state, target, cwd);
        if (abs) cwd = abs;
      }
      continue;
    }
    if (name === "eval") {
      const raw = args.join(" ");
      if (hasDecodeExpr(raw)) state.obfuscated.add("base64-decoded data is evaluated by the shell");
      const folded = foldExpr(state, unquote(raw), 0);
      if (folded !== null) analyzeShell(state, folded, depth + 1, cwd);
      else {
        if (/\$|`/.test(raw)) state.obfuscated.add("eval of a string built at runtime");
        state.execDynamic = true;
      }
      continue;
    }
    if (["sh", "bash", "zsh", "dash", "ksh"].includes(name)) {
      const cFlag = args.findIndex((a) => /^-[a-zA-Z]*c[a-zA-Z]*$/.test(a));
      if (cFlag >= 0) {
        analyzeInlineArg(state, args[cFlag + 1] || "", "bash", depth + 1, cwd);
      }
      // The -c program is code, not a path argument.
      for (let k = 0; k < args.length; k++) {
        if (cFlag >= 0 && (k === cFlag || k === cFlag + 1)) continue;
        if (looksPathLike(args[k])) recordPath(state, "read", args[k], cwd);
      }
      continue;
    }
    if (["python", "python3", "py"].includes(name)) {
      const cFlag = args.findIndex((a) => a === "-c" || /^-[a-zA-Z]*c[a-zA-Z]*$/.test(a));
      if (cFlag >= 0) {
        analyzeInlineArg(state, args[cFlag + 1] || "", "python", depth + 1, cwd);
      }
      for (let k = 0; k < args.length; k++) {
        if (cFlag >= 0 && (k === cFlag || k === cFlag + 1)) continue;
        if (looksPathLike(args[k])) recordPath(state, "read", args[k], cwd);
      }
      continue;
    }
    if (name === "node" || name === "nodejs") {
      const eFlag = args.findIndex((a) => a === "-e" || a === "--eval" || /^-[a-zA-Z]*e[a-zA-Z]*$/.test(a));
      if (eFlag >= 0) {
        analyzeInlineArg(state, args[eFlag + 1] || "", "js", depth + 1, cwd);
      }
      for (let k = 0; k < args.length; k++) {
        if (eFlag >= 0 && (k === eFlag || k === eFlag + 1)) continue;
        if (looksPathLike(args[k])) recordPath(state, "read", args[k], cwd);
      }
      continue;
    }
    if (name === "powershell" || name === "pwsh") {
      if (args.some((a) => /^-(?:e|en|enc|encodedcommand)$/i.test(a) || /^-EncodedCommand/i.test(a))) {
        state.obfuscated.add("encoded PowerShell command");
      }
      const cFlag = args.findIndex((a) => /^-(?:c|command)$/i.test(a));
      if (cFlag >= 0) {
        analyzeInlineArg(state, args[cFlag + 1] || "", "powershell", depth + 1, cwd);
      }
      continue;
    }
    if (name === "curl" || name === "wget") {
      analyzeCurlLike(state, name, args, cwd);
      continue;
    }
    if (name === "ssh" || name === "scp" || name === "sftp" || name === "rsync" || name === "ftp" || name === "lftp") {
      analyzeRemote(state, name, args, cwd, depth);
      continue;
    }
    if (name === "nc" || name === "ncat" || name === "netcat" || name === "telnet" || name === "socat") {
      analyzeNetcat(state, name, args);
      continue;
    }
    if (name === "rm" || name === "rmdir" || name === "unlink" || name === "shred" || name === "srm") {
      for (const a of stripOptions(args)) recordPath(state, "delete", a, cwd);
      continue;
    }
    if (["mkdir", "touch", "truncate", "tee"].includes(name)) {
      for (const a of stripOptions(args, ["m", "mode"])) recordPath(state, "write", a, cwd);
      continue;
    }
    if (name === "cp" || name === "mv" || name === "install" || name === "ln") {
      const operands = stripOptions(args);
      for (let i = 0; i < operands.length; i++) {
        if (i === operands.length - 1) recordPath(state, "write", operands[i], cwd);
        else recordPath(state, "read", operands[i], cwd);
        if (name === "mv" && i < operands.length - 1) recordPath(state, "delete", operands[i], cwd);
      }
      if (operands.length >= 2) noteCredentialCopy(state, operands[0], operands[operands.length - 1]);
      continue;
    }
    if (name === "tar") {
      analyzeTar(state, args, cwd);
      continue;
    }
    if (name === "sed") {
      const inPlace = args.some((a) => /^-[a-zA-Z]*i/.test(a) || a.startsWith("--in-place"));
      if (inPlace) {
        const operands = stripOptions(args, ["e", "f", "l"]);
        for (let i = 1; i < operands.length; i++) recordPath(state, "write", operands[i], cwd);
      }
      continue;
    }
    if (name === "dd") {
      for (const a of args) {
        if (a.startsWith("of=")) recordPath(state, "write", a.slice(3), cwd);
        if (a.startsWith("if=")) recordPath(state, "read", a.slice(3), cwd);
      }
      continue;
    }
    if (name === "find") {
      const roots = args.filter((a) => !a.startsWith("-") && a !== "(" && a !== ")" && a !== "!" && !/^[{};+]$/.test(a));
      if (args.includes("-delete")) for (const r of roots) recordPath(state, "delete", r, cwd);
      const execAt = args.findIndex((a) => a === "-exec" || a === "-execdir" || a === "-ok");
      if (execAt >= 0) {
        const end = args.findIndex((a, i) => i > execAt && (a === ";" || a === "+"));
        const inner = args.slice(execAt + 1, end < 0 ? undefined : end);
        if (inner.length) analyzeCommandWords(state, inner, cwd, depth + 1);
      }
      continue;
    }
    if (name === "git") {
      for (const a of args) if (/^https?:\/\//i.test(a)) classifyURL(state, a);
      continue;
    }
    if (["cat", "tac", "head", "tail", "less", "more", "strings", "od", "xxd", "hexdump", "base64", "sha256sum", "sha1sum", "md5sum"].includes(name)) {
      // head -c 3000 / tail -n 20: the number is an option value, not a path.
      for (const a of stripOptions(args, ["c", "n", "bytes", "lines", "num", "count", "max-count", "skip", "bytes"])) recordPath(state, "read", a, cwd);
      continue;
    }
    if (name === "unzip") {
      const operands = stripOptions(args);
      for (const a of operands) recordPath(state, "read", a, cwd);
      const d = args.findIndex((a) => a === "-d");
      if (d >= 0 && args[d + 1]) recordPath(state, "write", args[d + 1], cwd);
      continue;
    }
    if (name === "source" || name === ".") continue;
  }
  // Secrets named anywhere in the script, and words that name credential files.
  for (const segment of shellSegments(text)) {
    const words = shellWords(segment);
    for (const w of words) {
      if (!w || w.startsWith("-") || /^[a-z][a-z0-9+.-]*:\/\//i.test(w)) continue;
      for (const c of pathCandidates(w)) {
        const abs = resolvePath(state, c, base);
        const secret = isSecretTarget(state, c, abs);
        if (secret) addCredential(state, secret);
        if (isHomeWide(state, abs || "")) {
          // A home-wide path in a destructive or writing command is handled by recordPath.
        }
      }
    }
  }
}

function analyzeInline(state: State, code: string, lang: "js" | "python" | "powershell", depth: number): void {
  if (depth > 3) return;
  const sub = cloneForInline(state, lang);
  sub.code = lang === "js" ? stripJsComments(code) : lang === "python" ? stripPyComments(code) : stripPsComments(code);
  if (lang === "js") rewriteCreateRequire(sub);
  collectPythonModules(sub);
  collectAssignments(sub);
  scanEnv(sub);
  if (lang === "js") {
    detectServerListen(sub);
    scanJsFiles(sub);
    scanJsNetwork(sub);
    scanJsExec(sub);
    scanJsDynamic(sub);
  } else if (lang === "python") {
    detectServerListen(sub);
    scanPythonFiles(sub);
    scanPythonNetwork(sub);
    scanPythonExec(sub);
    scanPythonDynamic(sub);
  } else {
    detectServerListen(sub);
    scanPowerShellFiles(sub);
    scanPowerShellNetwork(sub);
    scanPowerShellExec(sub);
  }
  scanObfuscation(sub);
  mergeInto(state, sub);
}

function cloneForInline(state: State, lang: "js" | "python" | "powershell"): State {
  const sub = newState(state.opts, lang, state.path, state.dir, state.depth + 1);
  sub.cwd = state.cwd;
  sub.root = state.root;
  sub.home = state.home;
  sub.allowed = state.allowed;
  sub.vars = new Map(state.vars);
  return sub;
}

function mergeInto(target: State, source: State): void {
  for (const v of source.external) target.external.add(v);
  target.loopback = target.loopback || source.loopback;
  target.dynamicNetwork = target.dynamicNetwork || source.dynamicNetwork;
  for (const v of source.credentials) target.credentials.add(v);
  target.envWhole = target.envWhole || source.envWhole;
  for (const v of source.envNames) target.envNames.add(v);
  for (const v of source.writesOutside) target.writesOutside.add(v);
  target.writesDynamic = target.writesDynamic || source.writesDynamic;
  for (const v of source.deletesOutside) target.deletesOutside.add(v);
  target.deletesDynamic = target.deletesDynamic || source.deletesDynamic;
  for (const v of source.readsOutside) target.readsOutside.add(v);
  for (const v of source.commands) target.commands.add(v);
  target.execDynamic = target.execDynamic || source.execDynamic;
  for (const v of source.obfuscated) target.obfuscated.add(v);
  for (const v of source.notes) if (!target.notes.includes(v)) target.notes.push(v);
  target.dangerFile = target.dangerFile || source.dangerFile;
  target.complete = target.complete && source.complete;
}

function analyzeCurlLike(state: State, name: string, args: string[], base: string): void {
  let destFound = false;
  const valueOpts = name === "curl"
    ? ["d", "data", "data-raw", "data-binary", "data-urlencode", "F", "form", "H", "header", "X", "request", "u", "user", "A", "user-agent", "e", "referer", "b", "cookie", "c", "cookie-jar", "E", "cert", "key", "cacert", "resolve", "connect-to", "m", "max-time", "retry", "w", "write-out", "K", "config", "x", "proxy", "T", "upload-file"]
    : ["H", "header", "e", "execute", "T", "timeout", "U", "user-agent", "--user-agent"];
  for (let i = 0; i < args.length; i++) {
    let a = args[i];
    if (/^--/.test(a)) {
      if (a.includes("=")) {
        const [k, ...rest] = a.split("=");
        const v = rest.join("=");
        handleCurlOption(state, name, k.replace(/^--/, ""), v, base, () => (destFound = true));
        continue;
      }
      const bare = a.replace(/^--/, "");
      if (bare === "url" && args[i + 1]) {
        classifyNetworkArg(state, args[++i]);
        destFound = true;
        continue;
      }
      if (bare === "output" || bare === "output-document") {
        if (args[i + 1]) recordPath(state, "write", args[++i], base);
        continue;
      }
      if (bare === "post-file" || bare === "body-file" || bare === "upload-file") {
        if (args[i + 1]) recordPath(state, "read", args[++i], base);
        continue;
      }
      if (valueOpts.includes(bare)) {
        if (args[i + 1]) {
          const v = args[++i];
          if (bare === "data" || bare === "data-binary" || bare === "data-raw") {
            for (const part of v.split(/\s+/)) if (part.startsWith("@")) recordPath(state, "read", part.slice(1), base);
          }
        }
        continue;
      }
      continue;
    }
    if (/^-[A-Za-z]/.test(a)) {
      const cluster = a.slice(1);
      for (let k = 0; k < cluster.length; k++) {
        const ch = cluster[k];
        if (ch === "o" && name === "curl") {
          let target = cluster.slice(k + 1);
          if (!target && args[i + 1]) target = args[++i];
          if (target) recordPath(state, "write", target, base);
          break;
        }
        if (ch === "O" && name === "wget") {
          let target = cluster.slice(k + 1);
          if (!target && args[i + 1]) target = args[++i];
          if (target) recordPath(state, "write", target, base);
          break;
        }
        if (ch === "d" || ch === "F" || ch === "H" || ch === "X" || ch === "u" || ch === "A" || ch === "b" || ch === "c" || ch === "T" || ch === "x" || ch === "m" || ch === "w" || ch === "K") {
          let v = cluster.slice(k + 1);
          if (!v && args[i + 1]) v = args[++i];
          if ((ch === "d" || ch === "F") && v) {
            for (const part of v.split(/\s+/)) if (part.startsWith("@")) recordPath(state, "read", part.slice(1), base);
          }
          break;
        }
      }
      continue;
    }
    if (!a || a === "-") continue;
    const firstSegment = a.split("/")[0];
    const bareHost = /^[A-Za-z0-9_.-]+$/.test(firstSegment) && firstSegment.includes(".") && !a.startsWith("/") && !a.startsWith(".");
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(a) || /^\/\//.test(a) || bareHost) {
      classifyNetworkArg(state, a);
      destFound = true;
    }
  }
  if (!destFound) markDynamicNetwork(state);
}

function handleCurlOption(
  state: State,
  name: string,
  key: string,
  value: string,
  base: string,
  markDest: () => void,
): void {
  if (key === "url") {
    classifyNetworkArg(state, value);
    markDest();
    return;
  }
  if (key === "output" || key === "output-document") {
    recordPath(state, "write", value, base);
    return;
  }
  if (key === "post-file" || key === "body-file" || key === "upload-file") {
    recordPath(state, "read", value, base);
    return;
  }
  if (key === "data" || key === "data-binary" || key === "data-raw") {
    for (const part of value.split(/\s+/)) if (part.startsWith("@")) recordPath(state, "read", part.slice(1), base);
    return;
  }
  if (/^https?:\/\//i.test(value) || /^\/\//.test(value)) {
    classifyNetworkArg(state, value);
    markDest();
  }
  void name;
}

function analyzeRemote(state: State, name: string, args: string[], base: string, depth: number): void {
  const operands: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (/^-[A-Za-z]/.test(a)) {
      if (optionValue(name, a)) i++;
      continue;
    }
    if (a.startsWith("--")) continue;
    operands.push(a);
  }
  if (name === "ssh") {
    const dest = operands[0];
    if (dest) classifyHost(state, dest);
    else markDynamicNetwork(state);
    const cmdAt = args.indexOf(dest);
    const remote = args.slice(cmdAt + 1).join(" ");
    if (remote) analyzeShell(state, remote, depth + 1, state.home);
    return;
  }
  for (const a of operands) {
    const host = a.match(/^(?:[^@/]+@)?([^:/]+):/);
    if (host && !/^[A-Za-z]:[\\/]/.test(a)) classifyHost(state, host[1]);
  }
  if (name === "rsync" || name === "scp") {
    const dest = operands[operands.length - 1];
    if (dest && !/^(?:[^@/]+@)?[^:/]+:/.test(dest)) recordPath(state, "write", dest, base);
    const src = operands[0];
    if (src && !/^(?:[^@/]+@)?[^:/]+:/.test(src)) recordPath(state, "read", src, base);
    if (operands.length === 0) markDynamicNetwork(state);
  }
}

function analyzeNetcat(state: State, name: string, args: string[]): void {
  if (args.some((a) => /^-[a-zA-Z]*l/.test(a) || a === "--listen")) {
    state.loopback = true;
    return;
  }
  const operands = stripOptions(args, ["p", "s", "w", "i", "q", "X", "x", "e", "c"]);
  const host = operands.find((a) => !/^\d+$/.test(a));
  if (name === "socat") {
    for (const a of args) {
      const m = a.match(/(?:TCP|SSL|OPENSSL|UDP):([^:]+):/i);
      if (m) classifyHost(state, m[1]);
    }
    return;
  }
  if (host) classifyHost(state, host);
  else markDynamicNetwork(state);
}

function analyzeTar(state: State, args: string[], base: string): void {
  let mode = "";
  let archive: string | undefined;
  const operands: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (!a) continue;
    if (!a.startsWith("-") && /^[a-z]+$/i.test(a) && /[cxtru]/i.test(a) && !mode) {
      mode = a;
      if (/f/i.test(a) && args[i + 1]) archive = args[++i];
      continue;
    }
    if (a.startsWith("-")) {
      const bare = a.replace(/^-+/, "");
      if (bare === "file" || bare === "f") {
        if (args[i + 1]) archive = args[++i];
        continue;
      }
      if (bare === "directory" || bare === "C") {
        if (args[i + 1]) recordPath(state, "write", args[++i], base);
        continue;
      }
      if (bare === "files-from" || bare === "T" || bare === "exclude-from" || bare === "X") {
        if (args[i + 1]) recordPath(state, "read", args[++i], base);
        continue;
      }
      if (/^[a-z]*[cxtru]/i.test(bare)) mode = bare;
      continue;
    }
    operands.push(a);
  }
  if (mode && /c/i.test(mode)) {
    if (archive && archive !== "-") recordPath(state, "write", archive, base);
    for (const o of operands) recordPath(state, "read", o, base);
  } else if (mode && /x/i.test(mode)) {
    if (archive && archive !== "-") recordPath(state, "read", archive, base);
  } else {
    if (archive && archive !== "-") recordPath(state, "read", archive, base);
    for (const o of operands) recordPath(state, "read", o, base);
  }
}

function analyzeCommandWords(state: State, words: string[], base: string, depth = 0): void {
  const name = words.length ? baseName(words[0]) : "";
  const rest = words.slice(1).filter(Boolean);
  if (name === "env") {
    const operands = rest.filter((a) => !a.startsWith("-"));
    if (!operands.length || operands.every((a) => /^[A-Za-z_]\w*=/.test(a))) state.envWhole = true;
  } else if (name === "printenv") {
    const names = rest.filter((a) => !a.startsWith("-"));
    if (!names.length) state.envWhole = true;
    else for (const n of names) addEnvName(state, n.replace(/["']/g, ""));
  } else if (name === "set" && !rest.length) {
    state.envWhole = true;
  }
  analyzeShell(state, shellQuoteWords(words), depth, base);
}

function shellQuoteWords(words: string[]): string {
  return words
    .map((w) => (/\s/.test(w) ? `'${w.replace(/'/g, "'\\''")}'` : w))
    .join(" ");
}

// ---------------------------------------------------------------------------
// Exec

function isChildProcessCall(state: State, code: string, index: number, name: string): boolean {
  if (!/^(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)$/.test(name)) return false;
  const before = code.slice(Math.max(0, index - 140), index);
  if (/require\s*\(\s*["'](?:node:)?child_process["']\s*\)\s*\.\s*$/.test(before)) return true;
  if (/import\s*\(\s*["'](?:node:)?child_process["']\s*\)\s*\.\s*$/.test(before)) return true;
  const prefix = before.match(/([A-Za-z_$][\w$]*)\s*\.\s*$/);
  if (prefix) {
    return state.cpVars.has(prefix[1]) || prefix[1] === "child_process";
  }
  if (/\.\s*$/.test(before)) return false;
  return state.cpNames.has(name);
}

function scanJsExec(state: State): void {
  const structural = maskStrings(state.code, "js");
  const re = /\b(execSync|exec|execFileSync|execFile|spawnSync|spawn|fork)\s*\(/g;
  for (const m of structural.matchAll(re)) {
    const name = m[1];
    if (!isChildProcessCall(state, state.code, m.index || 0, name)) continue;
    const open = (m.index || 0) + m[0].lastIndexOf("(");
    const { args } = parseArgs(state.code, open);
    if (args.some((a) => hasDecodeExpr(a) || mentionsTainted(state, a))) {
      state.obfuscated.add("base64-decoded data reaches a child process");
    }
    if (name === "fork") {
      const spec = args[0] ? foldExpr(state, args[0], 0) : null;
      if (spec) addCommand(state, ["node", spec]);
      continue;
    }
    const cmd = args[0] ? foldExpr(state, args[0], 0) : null;
    if (cmd === null) {
      state.execDynamic = true;
      continue;
    }
    const shellString = name === "exec" || name === "execSync";
    const rest: string[] = [];
    let sawLiteralArg = false;
    if (!shellString && args[1] && args[1].trim().startsWith("[")) {
      for (const item of splitArrayLiteral(args[1])) {
        const v = foldExpr(state, item, 0);
        if (v !== null) {
          rest.push(v);
          sawLiteralArg = true;
        } else if (/node|python|^(?:sh|bash|pwsh|powershell)$/.test(baseName(cmd))) {
          // A dynamic argument to an interpreter can be code.
          if (isInterpreterWithCodeFlag(cmd, rest) || !sawLiteralArg) state.execDynamic = true;
        }
      }
    } else if (!shellString && args[1] && !args[1].trim().startsWith("{")) {
      const v = foldExpr(state, args[1], 0);
      if (v !== null) rest.push(v);
      else state.execDynamic = true;
    }
    const words = shellString ? shellWords(cmd) : [cmd, ...rest];
    addCommand(state, words);
    analyzeCommandWords(state, words, state.cwd);
    // spawn("bash", ["-c", code]) / node -e / python -c, and exec("bash -c ...").
    const after = shellString ? words.slice(1) : rest;
    const flagAt = after.findIndex((a) => /^-[a-zA-Z]*[ce]$/.test(a) || /^--(?:eval|command)$/.test(a));
    if (flagAt >= 0 && after[flagAt + 1]) {
      const inner = after[flagAt + 1];
      const executable = shellString ? words[0] || "" : cmd;
      const lang = /node/.test(executable) ? "js" : /python|py/.test(executable) ? "python" : /pwsh|powershell/.test(executable) ? "powershell" : "bash";
      if (lang === "bash") analyzeShell(state, inner, 1, state.cwd);
      else analyzeInline(state, inner, lang, 1);
    } else if (flagAt >= 0) {
      state.execDynamic = true;
    }
  }
}

function isInterpreterWithCodeFlag(cmd: string, rest: string[]): boolean {
  return /(?:^|\/)(?:sh|bash|zsh|node|python3?|pwsh|powershell)$/.test(cmd) && rest.some((a) => /^-[a-zA-Z]*[ce]$/.test(a));
}

function splitArrayLiteral(expr: string): string[] {
  const inner = expr.trim().replace(/^\[/, "").replace(/\]$/, "");
  const parts = splitTopLevel(inner, ",");
  return parts.map((p) => p.trim()).filter(Boolean);
}

function scanPythonExec(state: State): void {
  const calls = [
    /\b(?:subprocess\.(?:run|Popen|call|check_call|check_output)|os\.system|os\.popen)\s*\(/g,
  ];
  for (const re of calls) {
    for (const m of state.code.matchAll(re)) {
      const open = (m.index || 0) + m[0].lastIndexOf("(");
      const { args } = parseArgs(state.code, open);
      if (args.some((a) => hasDecodeExpr(a) || mentionsTainted(state, a))) {
        state.obfuscated.add("base64-decoded data reaches a child process");
      }
      const first = args[0] || "";
      let words: string[] = [];
      if (first.trim().startsWith("[")) {
        for (const item of splitArrayLiteral(first)) {
          const v = foldExpr(state, item, 0);
          if (v === null) {
            state.execDynamic = true;
            break;
          }
          words.push(v);
        }
      } else {
        const v = foldExpr(state, first, 0);
        if (v === null) state.execDynamic = true;
        else words = shellWords(v);
      }
      if (words.length) {
        addCommand(state, words);
        analyzeCommandWords(state, words, state.cwd);
        const flagAt = words.findIndex((a) => /^-[a-zA-Z]*c$/.test(a));
        if (flagAt >= 0 && words[flagAt + 1]) {
          const cmd = words[0] || "";
          const lang = /python|py/.test(cmd) ? "python" : /pwsh|powershell/.test(cmd) ? "powershell" : /node/.test(cmd) ? "js" : "bash";
          if (lang === "bash") analyzeShell(state, words[flagAt + 1], 1, state.cwd);
          else analyzeInline(state, words[flagAt + 1], lang, 1);
        }
      }
    }
  }
}

function scanPowerShellExec(state: State): void {
  for (const seg of shellSegments(stripPsComments(state.code))) {
    const words = psWords(seg);
    const cmd = commandOf(words);
    if (!cmd) continue;
    const name = baseName(cmd).toLowerCase();
    if (name === "iex" || name === "invoke-expression") {
      const raw = words.slice(words.indexOf(cmd) + 1).join(" ");
      if (hasDecodeExpr(raw) || mentionsTainted(state, raw)) {
        state.obfuscated.add("PowerShell evaluates base64-decoded data");
      } else if (/Download(?:String|File|Data)|Invoke-WebRequest|Invoke-RestMethod|\biwr\b|\birm\b|\bcurl\b|\bwget\b/i.test(raw)) {
        state.obfuscated.add("downloaded code is evaluated by PowerShell");
      } else {
        const folded = foldExpr(state, unquote(raw), 0);
        if (folded !== null) analyzeInline(state, folded, "powershell", 1);
        else state.obfuscated.add("PowerShell evaluates a string built at runtime");
      }
      continue;
    }
    if (name === "start-process") {
      const args = words.slice(words.indexOf(cmd) + 1).filter((a) => !a.startsWith("-"));
      addCommand(state, ["start-process", ...args]);
      if (!args.length) state.execDynamic = true;
      continue;
    }
  }
  if (/-(?:EncodedCommand|enc|e)\s+[A-Za-z0-9+/=]{8,}/i.test(state.code)) {
    state.obfuscated.add("encoded PowerShell command");
  }
}

// ---------------------------------------------------------------------------
// Dynamic execution: a sink whose program or module name is not written out.

function noteDynamicExec(state: State, text: string): void {
  state.obfuscated.add(text);
  state.execDynamic = true;
}

// A code sink with a plain literal program has that program read as code. Anything else (a
// concatenation, a variable, a decoded string) is a program the reader cannot see, so the report
// is never `local`: an obfuscated entry is danger, and every one of these sets exec.dynamic too.
function codeSink(state: State, rawArg: string | undefined, what: string, lang: "js" | "python"): void {
  const raw = (rawArg || "").trim();
  if (!raw) return;
  const plain = isPlainLiteral(raw);
  const folded = foldExpr(state, raw, 0);
  if (folded !== null) {
    if (folded.trim()) {
      if (lang === "js") analyzeInline(state, folded, "js", state.depth + 1);
      else analyzeInline(state, folded, "python", state.depth + 1);
    }
    if (!plain) noteDynamicExec(state, `${what} of a program assembled at runtime`);
    return;
  }
  noteDynamicExec(state, `${what} of a program named at runtime`);
}

// require(<built>) / import(<built>): the module is picked by a name the reader cannot see.
function moduleSink(state: State, rawArg: string | undefined): void {
  const raw = (rawArg || "").trim();
  if (!raw || isPlainLiteral(raw)) return;
  const folded = foldExpr(state, raw, 0);
  noteDynamicExec(
    state,
    folded === null ? "loads a module named at runtime" : "loads a module named by a string built at runtime",
  );
}

// const req = createRequire(import.meta.url); req("node:fs") is require("node:fs").
function rewriteCreateRequire(state: State): void {
  if (!/\bcreateRequire\b/.test(state.code)) return;
  const names = new Set<string>();
  for (const m of state.code.matchAll(/(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:[A-Za-z_$][\w$]*\s*\.\s*)?createRequire\s*\(/g)) {
    names.add(m[1]);
  }
  for (const name of names) {
    if (name === "require") continue;
    state.code = state.code.replace(new RegExp(`(?<![\\w$.])${escapeRe(name)}\\s*\\(`, "g"), "require(");
  }
}

function scanJsDynamic(state: State): void {
  const code = state.code;
  const structural = maskStrings(code, "js");
  const handled = new Set<number>();
  const argsAt = (open: number): string[] => (open < 0 ? [] : parseArgs(code, open).args);
  const last = (args: string[]): string | undefined => args[args.length - 1];
  const each = (re: RegExp, fn: (open: number) => void) => {
    for (const m of structural.matchAll(re)) {
      const open = (m.index || 0) + m[0].lastIndexOf("(");
      if (open < 0 || handled.has(open)) continue;
      handled.add(open);
      fn(open);
    }
  };
  each(/\bnew\s+Function\s*\(/g, (open) => codeSink(state, last(argsAt(open)), "new Function", "js"));
  each(/(?<![\w$.])Function\s*\(/g, (open) => codeSink(state, last(argsAt(open)), "Function", "js"));
  each(/\b(?:globalThis|window|self|global)\s*\.\s*Function\s*\(/g, (open) => codeSink(state, last(argsAt(open)), "Function", "js"));
  each(/(?<![\w$.])eval\s*\(/g, (open) => codeSink(state, argsAt(open)[0], "eval", "js"));
  each(/\b(?:globalThis|window|self|global)\s*\.\s*eval\s*\(/g, (open) => codeSink(state, argsAt(open)[0], "eval", "js"));
  each(/\(\s*0\s*,\s*eval\s*\)\s*\(/g, (open) => codeSink(state, argsAt(open)[0], "indirect eval", "js"));
  each(/\.\s*(?:runInThisContext|runInNewContext|runInContext)\s*\(/g, (open) => codeSink(state, argsAt(open)[0], "vm code compilation", "js"));
  each(/\bvm\s*\.\s*compileFunction\s*\(/g, (open) => codeSink(state, argsAt(open)[0], "vm code compilation", "js"));
  each(/\bvm\s*\.\s*Script\s*\(/g, (open) => codeSink(state, argsAt(open)[0], "a vm.Script program", "js"));
  each(/(?<![\w$.])require\s*\(/g, (open) => moduleSink(state, argsAt(open)[0]));
  each(/(?<![\w$.])import\s*\(/g, (open) => moduleSink(state, argsAt(open)[0]));
  // Node internals, reached without the public API.
  if (/\bprocess\s*\.\s*(?:binding|_linkedBinding|dlopen)\s*\(/.test(structural)) {
    noteDynamicExec(state, "reaches Node internals without the public API");
  }
  if (/(?<![\w$.])internalBinding\s*\(/.test(structural)) {
    noteDynamicExec(state, "reaches Node internals without the public API");
  }
  // globalThis[<computed>]: the reader cannot tell which global runs.
  for (const m of structural.matchAll(/\b(?:globalThis|window|self|global)\s*\[/g)) {
    const open = (m.index || 0) + m[0].length - 1;
    const close = matchingBracket(code, open);
    if (close < 0) continue;
    const key = code.slice(open + 1, close).trim();
    if (!key || isPlainLiteral(key)) continue;
    noteDynamicExec(state, "a global is selected by a computed name");
  }
}

function scanPythonDynamic(state: State): void {
  const code = state.code;
  const structural = maskStrings(code, "python");
  const argsAt = (open: number): string[] => (open < 0 ? [] : parseArgs(code, open).args);
  const each = (re: RegExp, fn: (open: number) => void) => {
    for (const m of structural.matchAll(re)) {
      const open = (m.index || 0) + m[0].lastIndexOf("(");
      if (open < 0) continue;
      fn(open);
    }
  };
  // exec / eval of a program: read the literal, never call an assembled one harmless.
  each(/(?<![\w$.])(exec|eval)\s*\(/g, (open) => {
    const raw = (argsAt(open)[0] || "").trim();
    if (/^compile\s*\(/.test(raw)) return; // the compile sink below reads the source and the mode
    codeSink(state, raw, "exec", "python");
  });
  // compile(source, filename, mode) compiles the same program exec would run.
  each(/(?<![\w$.])compile\s*\(/g, (open) => {
    const args = argsAt(open);
    const source = (args[0] || "").trim();
    if (!source) return;
    const mode = args[2] ? foldExpr(state, args[2], 0) : null;
    if (!mode || !/^(?:exec|eval|single)$/i.test(mode)) {
      noteDynamicExec(state, "executes compiled code whose mode is chosen at runtime");
      return;
    }
    codeSink(state, source, "compile", "python");
  });
  // __import__ / importlib.import_module with a computed module name.
  each(/(?:\b__import__|(?<![\w$.])importlib\s*\.\s*import_module)\s*\(/g, (open) => moduleSink(state, argsAt(open)[0]));
  // getattr(os, <computed>): the module attribute is chosen at runtime.
  each(/(?<![\w$.])getattr\s*\(\s*(?:os|sys|subprocess|builtins|importlib|shutil|pathlib|socket|ctypes|glob)\s*,/g, (open) => {
    const raw = (argsAt(open)[1] || "").trim();
    if (!raw || isPlainLiteral(raw)) return;
    noteDynamicExec(state, "reads a module attribute named at runtime");
  });
  // A shell command assembled at runtime is the one shell=True form that is not readable.
  each(/\bsubprocess\s*\.\s*(?:run|Popen|call|check_call|check_output)\s*\(/g, (open) => {
    const args = argsAt(open);
    if (!args.some((a) => /^\s*shell\s*=\s*True\b/i.test(a))) return;
    const first = (args[0] || "").trim();
    if (!first || isPlainLiteral(first)) return;
    if (!/\+|\bf["']|\.\s*format\s*\(|%\s*[(%]|\.\s*join\s*\(/.test(first)) return;
    noteDynamicExec(state, "runs a shell command assembled at runtime");
  });
}

// ---------------------------------------------------------------------------
// Obfuscation

function hasDecodeExpr(s: string): boolean {
  return (
    /\batob\s*\(/i.test(s) ||
    /Buffer\.from\s*\([^)]*,\s*["']base64["']\s*\)/i.test(s) ||
    /\bb64decode\s*\(/i.test(s) ||
    /\b(?:urlsafe_b64decode|base64\.b64decode)\s*\(/i.test(s) ||
    /\bFromBase64String\s*\(/i.test(s) ||
    /\.decode\s*\(\s*["']base64["']\s*\)/i.test(s) ||
    /codecs\.decode\s*\([^)]*["']base64["']/i.test(s) ||
    /base64\s+(?:-d|--decode)\b[^|\n]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|dash|ksh|python3?|node|perl)\b/i.test(s)
  );
}

function isPlainLiteral(s: string): boolean {
  if (parseStringLiteral(s) !== null) return true;
  const tpl = parseTemplate(s);
  if (!tpl) return false;
  return tpl.py ? !tpl.body.includes("{") : !tpl.body.includes("${");
}

function mentionsTainted(state: State, s: string): boolean {
  for (const name of state.tainted) {
    const re = new RegExp(`\\b${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`);
    if (re.test(s)) return true;
  }
  return false;
}

function maskedAt(structural: string, original: string, index: number): boolean {
  return structural[index] === " " && !/\s/.test(original[index] || "");
}

function maskStrings(code: string, family: State["family"]): string {
  if (family === "unknown") return code;
  let out = "";
  let i = 0;
  const blank = (ch: string): string => (ch === "\n" ? "\n" : " ");
  while (i < code.length) {
    const c = code[i];
    if (family === "js" && c === "/" && code[i + 1] !== "/" && code[i + 1] !== "*" && regexLikelyStart(code, i)) {
      out += " ";
      i++;
      let inClass = false;
      while (i < code.length) {
        const ch = code[i];
        if (ch === "\\" && i + 1 < code.length) {
          out += blank(code[i + 1]) + blank(code[i + 1]);
          i += 2;
          continue;
        }
        if (ch === "[") inClass = true;
        else if (ch === "]") inClass = false;
        else if (ch === "/" && !inClass) {
          out += " ";
          i++;
          while (i < code.length && /[a-z]/i.test(code[i])) {
            out += " ";
            i++;
          }
          break;
        }
        out += blank(ch);
        i++;
      }
      continue;
    }
    if (family === "js" && (c === '"' || c === "'" || c === "`")) {
      const q = c;
      out += " ";
      i++;
      while (i < code.length) {
        const ch = code[i];
        if (ch === "\\" && i + 1 < code.length) {
          out += blank(code[i + 1]) + blank(code[i + 1]);
          i += 2;
          continue;
        }
        out += blank(ch);
        i++;
        if (ch === q) break;
      }
      continue;
    }
    if (family === "python" && (c === "'" || c === '"')) {
      const triple = code.slice(i, i + 3) === c + c + c;
      const delim = triple ? c + c + c : c;
      out += " ".repeat(delim.length);
      i += delim.length;
      while (i < code.length) {
        if (code[i] === "\\" && i + 1 < code.length) {
          out += blank(code[i + 1]) + blank(code[i + 1]);
          i += 2;
          continue;
        }
        if (code.startsWith(delim, i)) {
          out += " ".repeat(delim.length);
          i += delim.length;
          break;
        }
        out += blank(code[i]);
        i++;
      }
      continue;
    }
    if (family === "powershell" && (c === "'" || c === '"')) {
      const q = c;
      out += " ";
      i++;
      while (i < code.length) {
        const ch = code[i];
        if (ch === "`" && q === '"' && i + 1 < code.length) {
          out += "  ";
          i += 2;
          continue;
        }
        out += blank(ch);
        i++;
        if (ch === q) break;
      }
      continue;
    }
    if (family === "shell" && (c === "'" || c === '"' || c === "`")) {
      const q = c;
      out += " ";
      i++;
      while (i < code.length) {
        const ch = code[i];
        if (ch === "\\" && q !== "'" && i + 1 < code.length) {
          out += blank(code[i + 1]) + blank(code[i + 1]);
          i += 2;
          continue;
        }
        out += blank(ch);
        i++;
        if (ch === q) break;
      }
      continue;
    }
    out += c;
    i++;
  }
  return out;
}

function regexLikelyStart(code: string, i: number): boolean {
  let j = i - 1;
  while (j >= 0 && /\s/.test(code[j])) j--;
  if (j < 0) return true;
  if (/[=(:,[!&|?{;>]/.test(code[j])) return true;
  const before = code.slice(Math.max(0, i - 16), i);
  return /\b(?:return|case|typeof|delete|void|in|of|yield|await|new)\s*$/.test(before);
}

// Download-and-run only when the interpreter reads its PROGRAM from stdin. `curl x | python -c
// '...'` gives the downloaded bytes to a program that was already supplied; they are input.
function positionalArgs(args: string[]): string[] {
  return args.filter((a) => a === "-" || !a.startsWith("-"));
}

function interpreterReadsProgramFromStdin(cmd: string, args: string[]): boolean {
  const name = baseName(cmd.replace(/\.exe$/i, "")).toLowerCase();
  const pos = positionalArgs(args);
  if (["sh", "bash", "zsh", "dash", "ksh", "ash", "mksh"].includes(name)) {
    if (args.some((a) => /^-[a-zA-Z]*c[a-zA-Z]*$/.test(a) || a === "--command")) return false;
    if (args.some((a) => /^-[a-zA-Z]*s[a-zA-Z]*$/.test(a))) return true;
    return pos.length === 0 || (pos.length === 1 && pos[0] === "-");
  }
  if (["python", "python2", "python3", "py"].includes(name)) {
    if (args.some((a) => /^-[a-zA-Z]*[cm][a-zA-Z]*$/.test(a) || /^--(?:command|module)$/.test(a))) return false;
    return pos.length === 0 || pos[0] === "-";
  }
  if (name === "node" || name === "nodejs") {
    if (args.some((a) => /^-[a-zA-Z]*[ep][a-zA-Z]*$/.test(a) || a === "--eval" || a === "--print")) return false;
    return pos.length === 0 || pos[0] === "-";
  }
  if (name === "perl" || name === "ruby") {
    if (args.some((a) => /^-[a-zA-Z]*[er][a-zA-Z]*$/.test(a))) return false;
    return pos.length === 0 || pos[0] === "-";
  }
  if (name === "php") return !args.some((a) => a === "-r" || a === "--run");
  if (name === "lua") return pos.length === 0 || pos[0] === "-";
  return false;
}

function pipelineStageBefore(text: string, at: number): string {
  for (let i = at - 1; i >= 0; i--) {
    const c = text[i];
    if (c === "\n" || c === ";" || c === "&") return text.slice(i + 1, at);
  }
  return text.slice(0, at);
}

function pipesCodeIntoStdinInterpreter(text: string, source: (stage: string) => boolean): boolean {
  for (let i = 0; i < text.length; i++) {
    if (text[i] !== "|") continue;
    if (text[i + 1] === "|") {
      i++;
      continue;
    }
    // Only this stage of the pipeline: reading to the end for every pipe is quadratic. The first
    // words decide whether a program reads its code from stdin, so a cut quote cannot change that.
    const rest = text.slice(i + 1, i + 4001).split(/\n|;|\||&&/)[0] || "";
    const words = dropRedirectWords(shellWords(rest));
    const cmd = words.length ? commandOf(words) : undefined;
    if (!cmd) continue;
    const args = words.slice(words.indexOf(cmd) + 1);
    if (!interpreterReadsProgramFromStdin(cmd, args)) continue;
    if (source(pipelineStageBefore(text, i))) return true;
    i += rest.length;
  }
  return false;
}

function downloadStage(stage: string): boolean {
  return /\b(?:curl|wget)\b/.test(stage);
}

function decodeStage(stage: string): boolean {
  return /\b(?:base64|openssl\s+base64)\b/.test(stage) && /(?:-d|--decode|-D)\b/.test(stage);
}

function scanObfuscation(state: State): void {
  const code = state.code;
  const structural = maskStrings(code, state.family);
  // Character-code assembly builds a string instead of writing it.
  if (state.family === "js") {
    for (const m of structural.matchAll(/String\s*\.\s*(?:fromCharCode|fromCodePoint)\s*\(([^)]*)\)/g)) {
      const args = splitTopLevel(m[1], ",").map((a) => a.trim()).filter(Boolean);
      const numeric = args.filter((a) => /^(?:0x[0-9a-f]+|\d+)$/i.test(a)).length;
      if (args.length >= 2 && numeric === args.length) state.obfuscated.add("character codes assembled into a string");
      else if (args.length === 1 && args[0].startsWith("...")) state.obfuscated.add("character codes assembled into a string");
    }
  }
  if (state.family === "python" && (/["']{2}\s*\.\s*join\s*\(\s*(?:map\s*\(\s*chr|\[?chr\s*\()/.test(structural) || /["'][^"']*["']\s*\.\s*join\s*\(\s*chr\s*\(/.test(structural))) {
    state.obfuscated.add("character codes assembled into a string");
  }
  if (state.family === "powershell" && (/\[\s*char\s*\[\s*\]\s*\]|-join\s*\(\s*\[char\[\]\]/i.test(structural) || (structural.match(/\[char\]\s*(?:0x[0-9a-f]+|\d+)/gi) || []).length >= 2)) {
    state.obfuscated.add("character codes assembled into a string");
  }
  if (state.family === "python" && (structural.match(/\bchr\s*\(\s*(?:0x[0-9a-f]+|\d+)\s*\)/gi) || []).length >= 2) {
    state.obfuscated.add("character codes assembled into a string");
  }
  if (state.family === "shell" && /\bprintf\b[^\n]*\\x[0-9a-fA-F]{2}[^\n]*\\x[0-9a-fA-F]{2}/.test(structural)) {
    state.obfuscated.add("character codes assembled into a string");
  }
  if (state.family === "powershell" && /\b(?:iex|Invoke-Expression)\b[^\n;]*(?:DownloadString|DownloadData|Invoke-WebRequest|Invoke-RestMethod|\biwr\b|\birm\b)/i.test(structural)) {
    state.obfuscated.add("downloaded code is evaluated by PowerShell");
  }
  if (state.family === "powershell" && (/\b(?:iex|Invoke-Expression)\b[^\n;]*(?:FromBase64String|[A-Za-z0-9+/=]{40,})/i.test(structural) || /FromBase64String[^\n;]*(?:iex|Invoke-Expression)\b/i.test(structural))) {
    state.obfuscated.add("PowerShell evaluates base64-decoded data");
  }
  if ((state.family === "powershell" || state.family === "shell") && /\b(?:-EncodedCommand|-enc(?:odedcommand)?)\b/i.test(structural)) {
    state.obfuscated.add("encoded PowerShell command");
  }
  // base64 -d piped to a shell, and downloads piped to a shell.
  if (pipesCodeIntoStdinInterpreter(structural, decodeStage)) {
    state.obfuscated.add("base64-decoded data is piped to a shell");
  }
  if (pipesCodeIntoStdinInterpreter(structural, downloadStage)) {
    state.obfuscated.add("downloaded code is piped to a shell");
  }
  if (state.family === "shell" && /eval\s*["']?\$\(\s*(?:echo|printf)[^)]*base64/i.test(structural)) {
    state.obfuscated.add("base64-decoded data is evaluated by the shell");
  }
  // Direct dataflow into sinks.
  const sinks = /\b(eval|Function|exec|execSync|execFile|execFileSync|spawn|spawnSync|fork|Invoke-Expression|iex)\s*\(/gi;
  for (const m of structural.matchAll(sinks)) {
    const sinkName = m[1];
    if (/^(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)$/i.test(sinkName) && !isChildProcessCall(state, code, m.index || 0, sinkName)) continue;
    const open = (m.index || 0) + m[0].lastIndexOf("(");
    const { args } = parseArgs(code, open);
    const raw = args.join(", ");
    if (hasDecodeExpr(raw) || mentionsTainted(state, raw)) {
      state.obfuscated.add("base64-decoded data reaches an execution sink");
    }
  }
}
// ---------------------------------------------------------------------------
// Level and facts

const HOME_CREDENTIAL = /(^|[\\/])(\.(ssh|aws|gnupg|kube|azure|docker|password-store)([\\/]|$)|\.(npmrc|netrc|pypirc|git-credentials|pgpass)$|auth\.json$|id_(rsa|dsa|ecdsa|ed25519)\b)/i;
function computeLevel(r: EffectReport): "local" | "review" | "danger" {
  const netOut = r.network.external.length > 0 || r.network.dynamic;
  const creds = r.credentials.length > 0;
  if (r.obfuscated.length > 0) return "danger";
  if (creds && netOut) return "danger";
  if (r.env.whole && netOut) return "danger";
  // A home credential sent even to loopback counts: a local server can pass it on, and no test has
  // a reason to read a real login. A project's own .env with a local test server stays review.
  if (r.network.loopback && r.credentials.some((c) => HOME_CREDENTIAL.test(c))) return "danger";
  if (r.network.external.length > 0 || r.network.dynamic) return "review";
  if (creds || r.env.whole) return "review";
  if (r.writes.outside.length > 0 || r.deletes.outside.length > 0) return "review";
  if (r.writes.dynamic || r.deletes.dynamic) return "review";
  if (r.exec.dynamic) return "review";
  if (!r.complete) return "review";
  return "local";
}

function shorten(s: string, n: number): string {
  const one = s.replace(/\s+/g, " ").trim();
  return one.length <= n ? one : one.slice(0, n - 3) + "...";
}

function looksSecretValue(value: string): boolean {
  if (!value) return false;
  if (/^(?:gh[pousr]_|glpat-|npm_|sk-|xox[abprs]-|AKIA[0-9A-Z]{16})/.test(value)) return true;
  if (/^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(value)) return true;
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) return true;
  if (!/^[A-Za-z0-9_+=-]{24,}$/.test(value)) return false;
  if (/^[0-9a-f]{24,}$/i.test(value) && /[0-9]/.test(value)) return true;
  // A long mixed-case alphanumeric token. Ordinary words, paths and file names stay readable.
  return /[A-Z]/.test(value) && /[a-z]/.test(value) && /[0-9]/.test(value);
}

function redactFactText(s: string): string {
  return s
    .replace(/\b(bearer|basic)\s+([^\s"',;]+)/gi, "$1 <redacted>")
    .replace(/((?:bearer|basic|token|api[-_]?key|secret|password|passwd|authorization|credential|private[-_]?key|access[-_]?key)\s*[:=]\s*)([^\s"',;]+)/gi, "$1<redacted>")
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g, "<redacted>")
    // Mask only values that really look like a secret: a long token. Paths (with separators) and
    // ordinary words are facts, not secrets, so they stay readable.
    .replace(/(?<![A-Za-z0-9_+=-])[A-Za-z0-9_+=-]{24,}={0,2}(?![A-Za-z0-9_+=-])/g, (m) => (looksSecretValue(m) ? "<redacted>" : m));
}

function envFactName(c: string): string {
  if (!/[\\/~]/.test(c) && !/^[A-Za-z]:/.test(c) && isSecretEnvName(c)) return `env ${c}`;
  return c;
}

function compactPath(p: string): string {
  if (!p) return p;
  const s = slash(p);
  if (underCI(s, HOME)) return "~" + s.slice(HOME.length);
  return s;
}

function buildFacts(r: EffectReport): string[] {
  const out: string[] = [];
  const pathFact = (p: string): string => redactFactText(compactPath(p));
  for (const o of r.obfuscated.slice(0, 3)) out.push(`obfuscated: ${o}`);
  for (const n of (r.notes || []).slice(0, 2)) out.push(redactFactText(n));
  for (const c of r.credentials.slice(0, 3)) out.push(`credential: ${pathFact(envFactName(c))}`);
  if (r.env.whole) out.push("dumps the whole environment");
  if (r.env.names.length) {
    out.push(`env names: ${shorten(redactFactText(r.env.names.slice(0, 6).join(", ")), 120)}`);
  }
  for (const h of r.network.external.slice(0, 3)) out.push(`network to ${h}`);
  if (r.network.dynamic) out.push("network to a dynamic destination");
  else if (r.network.loopback && r.network.external.length === 0) out.push("loopback network only");
  for (const w of r.writes.outside.slice(0, 2)) out.push(`writes outside project: ${pathFact(w)}`);
  if (r.writes.dynamic) out.push("writes to a dynamic path");
  for (const d of r.deletes.outside.slice(0, 2)) out.push(`deletes outside project: ${pathFact(d)}`);
  if (r.deletes.dynamic) out.push("deletes a dynamic path");
  for (const rd of r.reads.outside.slice(0, 2)) out.push(`reads outside project: ${pathFact(rd)}`);
  for (const c of r.exec.commands.slice(0, 2)) out.push(`runs: ${redactFactText(shorten(c, 90))}`);
  if (r.exec.dynamic) out.push("runs a dynamic command");
  if (!r.complete) out.push("incomplete: some code could not be read or followed");
  const level = `level: ${r.level}`;
  if (out.length >= 12) out.length = 11;
  out.push(level);
  return out.slice(0, 12);
}

function emptyReport(): EffectReport {
  return {
    complete: true,
    hash: "",
    scripts: [],
    network: { external: [], loopback: false, dynamic: false },
    credentials: [],
    env: { whole: false, names: [] },
    writes: { outside: [], dynamic: false },
    deletes: { outside: [], dynamic: false },
    reads: { outside: [] },
    exec: { commands: [], dynamic: false },
    obfuscated: [],
    notes: [],
    facts: [],
    level: "local",
  };
}

function reportFromState(state: State, scripts: EffectReport["scripts"], hash: string): EffectReport {
  const r = emptyReport();
  r.complete = state.complete;
  r.hash = hash;
  r.scripts = scripts;
  r.network = {
    external: [...state.external].sort(),
    loopback: state.loopback,
    dynamic: state.dynamicNetwork,
  };
  r.credentials = [...state.credentials].sort();
  r.env = { whole: state.envWhole, names: [...state.envNames].sort() };
  r.writes = { outside: [...state.writesOutside].sort(), dynamic: state.writesDynamic };
  r.deletes = { outside: [...state.deletesOutside].sort(), dynamic: state.deletesDynamic };
  r.reads = { outside: [...state.readsOutside].sort() };
  r.exec = { commands: [...state.commands], dynamic: state.execDynamic };
  r.obfuscated = [...state.obfuscated];
  r.notes = [...new Set(state.notes)];
  r.level = state.dangerFile ? "danger" : computeLevel(r);
  r.facts = buildFacts(r);
  return r;
}

// ---------------------------------------------------------------------------
// Language detection

function langFromExt(file: string): Lang | null {
  const ext = (file.match(/\.([A-Za-z0-9]+)$/) || [])[1]?.toLowerCase();
  if (!ext) return null;
  if (ext === "js" || ext === "jsx") return "js";
  if (ext === "mjs") return "mjs";
  if (ext === "cjs") return "cjs";
  if (ext === "ts" || ext === "tsx" || ext === "mts" || ext === "cts") return "ts";
  if (ext === "py" || ext === "pyw") return "python";
  if (ext === "sh" || ext === "bash" || ext === "zsh" || ext === "ksh") return "bash";
  if (ext === "ps1" || ext === "psm1" || ext === "pwsh") return "powershell";
  return null;
}

function langFromShebang(code: string): Lang | null {
  const first = code.split(/\r?\n/, 1)[0] || "";
  if (!first.startsWith("#!")) return null;
  if (/\bnode\b/.test(first)) return "js";
  if (/\bpython\d?\b/.test(first)) return "python";
  if (/\b(?:bash|sh|zsh)\b/.test(first)) return "bash";
  if (/\b(?:pwsh|powershell)\b/i.test(first)) return "powershell";
  return null;
}

function looksBinary(buf: Buffer): boolean {
  for (let i = 0; i < buf.length; i++) if (buf[i] === 0) return true;
  return false;
}

function sha256(s: string): string {
  return crypto.createHash("sha256").update(s, "utf8").digest("hex");
}

function sha256File(file: string, buf: Buffer): string {
  const hash = crypto.createHash("sha256");
  hash.update(normAbs(file) + "\0", "utf8");
  hash.update(buf);
  return hash.digest("hex");
}

// ---------------------------------------------------------------------------
// Public analysis

function prepareCode(state: State, code: string): void {
  if (state.family === "js") {
    state.code = stripJsComments(code);
    rewriteCreateRequire(state);
    collectAssignments(state);
    normalizeJsMembers(state);
    rewriteJsAliases(state);
    collectPythonModules(state);
    scanEnv(state);
    detectServerListen(state);
    scanJsFiles(state);
    scanJsNetwork(state);
    scanJsExec(state);
    scanJsDynamic(state);
  } else if (state.family === "python") {
    state.code = stripPyComments(code);
    collectPythonModules(state);
    collectAssignments(state);
    scanEnv(state);
    detectServerListen(state);
    scanPythonFiles(state);
    scanPythonNetwork(state);
    scanPythonExec(state);
    scanPythonDynamic(state);
  } else if (state.family === "shell") {
    state.code = stripBashComments(code);
    collectAssignments(state);
    scanEnv(state);
    detectServerListen(state);
    analyzeShell(state, state.code, 0, state.cwd);
    scanShellObfuscation(state, code);
  } else if (state.family === "powershell") {
    state.code = stripPsComments(code);
    collectAssignments(state);
    scanEnv(state);
    detectServerListen(state);
    scanPowerShellFiles(state);
    scanPowerShellNetwork(state);
    scanPowerShellExec(state);
  }
  if (state.family === "js" || state.family === "python" || state.family === "powershell") {
    scanObfuscation(state);
  }
  scanStringSecrets(state);
}

function noteShellObfuscation(state: State, text: string): void {
  const masked = maskStrings(text, "shell");
  if (pipesCodeIntoStdinInterpreter(masked, decodeStage)) {
    state.obfuscated.add("base64-decoded data is piped to a shell");
  }
  if (pipesCodeIntoStdinInterpreter(masked, downloadStage)) {
    state.obfuscated.add("downloaded code is piped to a shell");
  }
  if (/\b(?:powershell|pwsh)\b[^|\n]*(?:-EncodedCommand|-enc(?:odedcommand)?)\b/i.test(masked)) {
    state.obfuscated.add("encoded PowerShell command");
  }
  if (/\beval\b[^\n]*(?:\$\([^)]*\)|`[^`]*`)[^\n]*base64/i.test(masked)) {
    state.obfuscated.add("base64-decoded data is evaluated by the shell");
  }
}

function scanShellObfuscation(state: State, rawCode: string): void {
  scanObfuscation(state);
  noteShellObfuscation(state, rawCode);
}

function scanStringSecrets(state: State): void {
  const code = state.code;
  // Literal strings in the code (comments are already gone).
  const re = /`(?:[^`\\]|\\.)*`|"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'/g;
  for (const m of code.matchAll(re)) {
    const value = parseStringLiteral(m[0]) ?? (parseTemplate(m[0]) ? foldTemplate(state, parseTemplate(m[0])!, 0) : null);
    if (!value) continue;
    checkValueForSecret(state, value);
  }
  // Constant concatenations, including pieces assembled from separate literals.
  const concat = /((?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`)(?:\s*\+\s*(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`))+)/g;
  for (const m of code.matchAll(concat)) {
    const v = foldExpr(state, m[1], 0);
    if (v) checkValueForSecret(state, v);
  }
}

function checkValueForSecret(state: State, value: string): void {
  const expanded = expandHomeRefs(value, state.home);
  // A command line or URL is not itself a path. Shell analysis picks the path words out.
  if (/\s/.test(expanded.trim()) || /:\/\//.test(expanded)) return;
  if (!looksPathLike(expanded) && !/^~/.test(value)) return;
  const abs = isAbs(expanded) ? normAbs(expanded) : joinAbs(state.cwd, expanded);
  const secret = checkSecret(state, [value, expanded, abs, displayPath(state, abs)]);
  if (secret) addCredential(state, secret);
}

export function analyzeCode(code: string, lang: Lang, opts: AnalyzeOptions): EffectReport {
  const o = normalizeOptions(opts);
  const state = newState(o, lang, "<inline>", o.cwd, 0);
  if (state.family === "unknown") {
    state.complete = false;
    return reportFromState(state, [{ path: "<inline>", lang, bytes: Buffer.byteLength(code, "utf8") }], sha256("<inline>\0" + code));
  }
  if (Buffer.byteLength(code, "utf8") > o.maxBytes) {
    state.complete = false;
    return reportFromState(
      state,
      [{ path: "<inline>", lang, bytes: Buffer.byteLength(code, "utf8") }],
      sha256("<inline>\0oversize:" + Buffer.byteLength(code, "utf8")),
    );
  }
  state.code = code;
  prepareCode(state, code);
  return reportFromState(
    state,
    [{ path: "<inline>", lang, bytes: Buffer.byteLength(code, "utf8") }],
    sha256("<inline>\0" + code),
  );
}

function normalizeOptions(opts: AnalyzeOptions): Required<Pick<AnalyzeOptions, "cwd" | "root" | "allowed" | "isSecretPath" | "maxFiles" | "maxDepth" | "maxBytes">> {
  const processBase = normAbs(slash(process.cwd()));
  const absolute = (p: string): string => {
    const s = normAbs(expandHomeRefs(slash(p), HOME));
    return isAbs(s) ? s : joinAbs(processBase, s);
  };
  const rawCwd = (opts && opts.cwd) || process.cwd();
  const base = absolute(rawCwd);
  const rawRoot = (opts && opts.root) || rawCwd;
  return {
    cwd: base,
    root: absolute(rawRoot),
    allowed: ((opts && opts.allowed) || []).map((p) => absolute(p)),
    isSecretPath: (opts && opts.isSecretPath) || (() => false),
    maxFiles: (opts && Number.isFinite(opts.maxFiles) ? opts.maxFiles : undefined) ?? DEFAULTS.maxFiles,
    maxDepth: (opts && Number.isFinite(opts.maxDepth) ? opts.maxDepth : undefined) ?? DEFAULTS.maxDepth,
    maxBytes: (opts && Number.isFinite(opts.maxBytes) ? opts.maxBytes : undefined) ?? DEFAULTS.maxBytes,
  };
}

function placeholderReport(file: string, lang: Lang, bytes: number, hash?: string): EffectReport {
  const r = emptyReport();
  r.complete = false;
  r.scripts = [{ path: file, lang, bytes }];
  r.hash = hash || sha256(file + "\0oversize:" + bytes);
  r.level = "review";
  r.facts = buildFacts(r);
  return r;
}

function hashFileContent(file: string, size: number): string {
  if (size > 64 * 1024 * 1024) return sha256(file + "\0large:" + size);
  const hash = crypto.createHash("sha256");
  hash.update(file + "\0");
  const fd = fs.openSync(file, "r");
  try {
    const chunk = Buffer.allocUnsafe(1024 * 1024);
    let read = 0;
    while ((read = fs.readSync(fd, chunk, 0, chunk.length, null)) > 0) {
      hash.update(chunk.subarray(0, read));
    }
  } finally {
    fs.closeSync(fd);
  }
  return hash.digest("hex");
}

interface ImportSpec {
  spec: string;
  relative: boolean;
  dynamic?: boolean;
}

function importSpecs(code: string, lang: Lang, file: string, dir: string): ImportSpec[] {
  const out: ImportSpec[] = [];
  const add = (spec: string, relative: boolean, dynamic = false) => {
    if (!spec) return;
    out.push({ spec, relative, dynamic });
  };
  if (languageFamily(lang) === "js") {
    const patterns = [
      /\bimport\s+[^;\n]*?\bfrom\s*["']([^"']+)["']/g,
      /\bimport\s*["']([^"']+)["']/g,
      /\bexport\s+[^;\n]*?\bfrom\s*["']([^"']+)["']/g,
      /\brequire\s*\(\s*["']([^"']+)["']\s*\)/g,
      /\bimport\s*\(\s*["']([^"']+)["']\s*\)/g,
      /\b(?:fork|Worker)\s*\(\s*["']([^"']+)["']/g,
      /\bnew\s+URL\s*\(\s*["']([^"']+)["']\s*\)/g,
    ];
    for (const re of patterns) {
      for (const m of code.matchAll(re)) {
        const s = m[1];
        add(s, /^(?:\.{1,2}\/|\/|[A-Za-z]:[\\/]|~)/.test(s));
      }
    }
    for (const m of code.matchAll(/\b(?:import|require)\s*\(\s*`([^`]*)`\s*\)/g)) {
      if (/\.{0,2}\//.test(m[1])) add(m[1], true, true);
    }
  } else if (languageFamily(lang) === "python") {
    for (const m of code.matchAll(/^\s*from\s+(\.+)([\w.]*)\s+import\s+([^\n#]+)/gm)) {
      const dots = m[1].length;
      const mod = m[2];
      let base = dir;
      for (let i = 1; i < dots; i++) base = dirName(base);
      if (mod) {
        add(base + "/" + mod.replace(/\./g, "/"), true);
      } else {
        for (const part of m[3].split(",")) {
          const name = part.trim().split(/\s+as\s+/)[0].trim();
          if (/^[A-Za-z_]\w*$/.test(name)) add(base + "/" + name, true);
        }
      }
    }
    for (const m of code.matchAll(/\bimportlib\.import_module\s*\(\s*["'](\.+)([\w.]*)["']/g)) {
      let base = dir;
      for (let i = 1; i < m[1].length; i++) base = dirName(base);
      add(base + "/" + m[2].replace(/\./g, "/"), true);
    }
  } else if (languageFamily(lang) === "shell") {
    for (const m of code.matchAll(/(?:^|[;|&\n]\s*)(?:source|\.)\s+(?:"([^"]+)"|'([^']+)'|([^\s;|&]+))/gm)) {
      const spec = (m[1] || m[2] || m[3] || "").replace(/^\$PSScriptRoot[\\/]/, dir + "/").replace(/^\$\{PSScriptRoot\}[\\/]/, dir + "/");
      if (spec) add(spec, /^(?:\.{1,2}\/|\/|[A-Za-z]:[\\/]|~|\$PSScriptRoot)/.test(spec) || !spec.includes("/"));
    }
  } else if (languageFamily(lang) === "powershell") {
    for (const m of code.matchAll(/(?:^|[;|\n]\s*)(?:\.|&|Import-Module)\s+(?:"([^"]+)"|'([^']+)'|([^\s;|&]+))/gm)) {
      const spec = (m[1] || m[2] || m[3] || "").replace(/^\$PSScriptRoot[\\/]/, dir + "/").replace(/^\$\{PSScriptRoot\}[\\/]/, dir + "/");
      if (spec) add(spec, /^(?:\.{1,2}\/|\/|[A-Za-z]:[\\/]|~|\$PSScriptRoot)/.test(spec) || !spec.includes("/"));
    }
  }
  void file;
  return out;
}

function resolveImport(spec: string, lang: Lang, importing: string): string | null {
  let s = slash(spec);
  s = expandHomeRefs(s, HOME);
  if (languageFamily(lang) === "js") s = s.replace(/[?#].*$/, "");
  if (isAbs(s)) {
    // as is
  } else if (/^\.{1,2}\//.test(s) || s.startsWith(".") || !/^[A-Za-z]:/.test(s)) {
    s = joinAbs(dirName(importing), s);
  } else {
    s = normAbs(s);
  }
  const exts =
    languageFamily(lang) === "js"
      ? ["", ".ts", ".js", ".mjs", ".cjs", ".tsx", ".jsx", ".mts", ".cts", ".json"]
      : languageFamily(lang) === "python"
        ? ["", ".py"]
        : ["", languageFamily(lang) === "powershell" ? ".ps1" : ".sh"];
  const candidates: string[] = [];
  for (const e of exts) candidates.push(s + e);
  if (languageFamily(lang) === "js") for (const e of exts.slice(1)) candidates.push(s + "/index" + e);
  if (languageFamily(lang) === "python") candidates.push(s + "/__init__.py");
  for (const c of candidates) {
    try {
      const st = fs.statSync(c);
      if (st.isFile()) return normAbs(c);
    } catch {
      /* keep looking */
    }
  }
  return null;
}

export function analyzeFiles(paths: string[], opts: AnalyzeOptions): EffectReport {
  return analyzeFilesInner(paths, opts, true);
}

function analyzeFilesInner(paths: string[], opts: AnalyzeOptions, followImports: boolean): EffectReport {
  const o = normalizeOptions(opts);
  const reports: EffectReport[] = [];
  const seen = new Set<string>();
  interface Item {
    spec: string;
    depth: number;
    from: string;
    imported: boolean;
    fromLang?: Lang;
  }
  const queue: Item[] = (paths || []).map((spec) => ({ spec, depth: 0, from: o.cwd, imported: false }));
  let forcedIncomplete = false;
  let count = 0;
  while (queue.length) {
    const item = queue.shift()!;
    let candidate = expandHomeRefs(slash(item.spec), HOME).trim();
    if (!candidate) {
      forcedIncomplete = true;
      continue;
    }
    if (!isAbs(candidate)) candidate = joinAbs(item.from, candidate);
    candidate = normAbs(candidate);
    const key = ciKey(candidate);
    if (seen.has(key)) continue;
    seen.add(key);
    count++;
    if (count > o.maxFiles) {
      forcedIncomplete = true;
      break;
    }
    let stat: fs.Stats;
    try {
      stat = fs.statSync(candidate);
    } catch {
      forcedIncomplete = true;
      continue;
    }
    if (!stat.isFile()) {
      forcedIncomplete = true;
      continue;
    }
    let lang = langFromExt(candidate);
    if (!lang) {
      // An extensionless script can be typed by its shebang, but a known-looking
      // extension with no language is unknown.
      const hasExt = /\.[A-Za-z0-9]+$/.test(candidate);
      if (!hasExt) {
        try {
          const head = fs.readFileSync(candidate, { encoding: "utf8" }).slice(0, 200);
          lang = langFromShebang(head);
        } catch {
          lang = null;
        }
      }
      if (!lang) {
        if (item.imported && item.fromLang) {
          const family = languageFamily(item.fromLang);
          if (family === "shell") lang = "bash";
          else if (family === "powershell") lang = "powershell";
          else continue; // settings, JSON and other data files are not scripts
        } else {
          forcedIncomplete = true;
          reports.push(placeholderReport(candidate, "unknown", stat.size, hashFileContent(candidate, stat.size)));
          continue;
        }
      }
    }
    if (stat.size > o.maxBytes) {
      reports.push(placeholderReport(candidate, lang, stat.size, hashFileContent(candidate, stat.size)));
      continue;
    }
    let buf: Buffer;
    try {
      buf = fs.readFileSync(candidate);
    } catch {
      forcedIncomplete = true;
      continue;
    }
    if (looksBinary(buf)) {
      forcedIncomplete = true;
      reports.push(placeholderReport(candidate, lang, stat.size, hashFileContent(candidate, stat.size)));
      continue;
    }
    let code = buf.toString("utf8");
    // UTF-8 BOM would confuse the shebang / first-token scanners.
    if (code.charCodeAt(0) === 0xfeff) code = code.slice(1);
    const state = newState(o, lang, candidate, dirName(candidate), item.depth);
    state.code = code;
    prepareCode(state, code);
    const bytes = buf.length;
    const report = reportFromState(state, [{ path: candidate, lang, bytes }], sha256File(candidate, buf));
    reports.push(report);

    if (!followImports) continue;
    const specs = importSpecs(code, lang, candidate, dirName(candidate));
    for (const imp of specs) {
      if (!imp.relative) continue;
      if (item.depth >= o.maxDepth) {
        forcedIncomplete = true;
        continue;
      }
      if (imp.dynamic) {
        forcedIncomplete = true;
        continue;
      }
      const resolved = resolveImport(imp.spec, lang, candidate);
      if (!resolved) {
        forcedIncomplete = true;
        continue;
      }
      queue.push({ spec: resolved, depth: item.depth + 1, from: dirName(candidate), imported: true, fromLang: lang });
    }
  }
  const merged = mergeReports(...reports);
  if (forcedIncomplete) {
    merged.complete = false;
    const computed = computeLevel(merged);
    const rank = (l: string) => (l === "danger" ? 2 : l === "review" ? 1 : 0);
    if (rank(computed) > rank(merged.level)) merged.level = computed;
    merged.facts = buildFacts(merged);
  }
  return merged;
}

// ---------------------------------------------------------------------------
// Text files in languages this module does not parse: Rust, Go, Makefiles, CMake, TOML, YAML, a
// package.json. The text is scanned as text. No language is parsed and nothing is executed.
// Comments are not stripped, because the language is unknown: a commented-out command still
// counts, which is the strict direction.

// Secret files worth naming even when isSecretPath does not know the form (a config file that
// names another tool's credential, for instance).
const TEXT_SECRET_FORMS: RegExp[] = [
  /(?:^|[^A-Za-z0-9_.-])(?:~|\$HOME|\$\{HOME\}|%USERPROFILE%)?[\\/]?\.ssh[\\/](?:id_rsa|id_dsa|id_ecdsa|id_ed25519|authorized_keys|config)\b/i,
  /(?:^|[^A-Za-z0-9_.-])(?:~|\$HOME|\$\{HOME\}|%USERPROFILE%)?[\\/]?\.aws[\\/](?:credentials|config)\b/i,
  /(?:^|[^A-Za-z0-9_.-])(?:~|\$HOME|\$\{HOME\}|%USERPROFILE%)?[\\/]?\.pi[\\/]agent[\\/](?:auth|mcp-auth)\.json\b/i,
  /(?:^|[^A-Za-z0-9_.-])(?:~|\$HOME|\$\{HOME\})?[\\/]?\.(?:codex|claude)[\\/]auth\.json\b/i,
  /(?:^|[^A-Za-z0-9_.-])(?:~|\$HOME|\$\{HOME\})?[\\/]?\.kube[\\/]config\b/i,
  /(?:^|[^A-Za-z0-9_.-])(?:~|\$HOME|\$\{HOME\})?[\\/]?\.docker[\\/]config\.json\b/i,
  /(?:^|[^A-Za-z0-9_.-])(?:~|\$HOME|\$\{HOME\})?[\\/]?(?:auth\.json|credentials\.(?:json|ya?ml|toml|ini))\b/i,
  /(?:^|[^A-Za-z0-9_.-])(?:~|\$HOME|\$\{HOME\})?[\\/]?(?:id_rsa|id_dsa|id_ecdsa|id_ed25519)\b/i,
  /(?:^|[^A-Za-z0-9_.-])(?:~|\$HOME|\$\{HOME\})?[\\/]?\.(?:netrc|npmrc|pypirc|git-credentials|bash_history|zsh_history)\b/i,
  /(?:^|[^A-Za-z0-9_.-])(?:~|\$HOME|\$\{HOME\})?[\\/]?\.env(?:\.[\w.-]+)?\b/i,
];

// Dumping the environment is what turns a config file into an exfiltration source.
const TEXT_ENV_DUMP =
  /(?:^|[\s;&|(])(?:printenv\b(?!\s+\S)|env\s*\||export\s+-p\b)|process\.env(?!\s*[.[])|os\.environ(?!\s*[.[])|(?:Get-ChildItem|gci)\s+(?:-Path\s+)?env:|\/proc\/(?:\d+|self)\/environ/i;

// A network command, as it appears in build files, Rust and Go. Bare URLs are handled separately.
const TEXT_NETWORK_WORD =
  /(?<![\w./\\-])(?:curl|wget|nc|ncat|netcat|scp|ssh|sftp|rsync|ftp|lftp|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|Start-BitsTransfer|DownloadString|DownloadFile|reqwest|net\/http|http\.(?:Post|Get|Head|NewRequest)|TcpStream|TcpClient|axios|httpGet|httpPost)(?![\w-])/i;

const TEXT_DOWNLOAD_PIPE =
  /(?:curl|wget|iwr|Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer|certutil)[^\n|;]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|dash|ksh|python3?|node|perl|ruby|iex|Invoke-Expression)\b/i;

// A delete or overwrite aimed at a home directory or a path outside the project, in a language
// this module scans as text. Either half alone is at most review; together they are what an
// installer or a build script does when it wipes a user's files.
const TEXT_DESTRUCTIVE =
  /\brm\s+-(?:[A-Za-z]*[rRfF][A-Za-z]*\s+)+|\bremove_dir_all\s*\(|\bremove_file\s*\(|\bos\.Remove(?:All)?\s*\(|\bunlink\s*\(|\brmdir\s*\(|\bDeleteFile\s*\(|\bsystem\s*\(|\bexec\.Command\s*\(|\bCommand::new\s*\(|\bpopen\s*\(|\/\/go:generate\b/;
function textOutsideRef(text: string): boolean {
  if (/\$HOME|\$\{HOME\}|%USERPROFILE%|~\/|\benv::var\(\s*["']HOME["']|\bos\.UserHomeDir|\bgetenv\(\s*["']HOME["']/.test(text)) return true;
  if (/\b[A-Za-z]:[\\/]/.test(text)) return true;
  // An absolute POSIX path, not the double slash of a URL.
  if (/(?:^|[\s"'(=,:;\[])\/(?!\/)/.test(text)) return true;
  // A parent traversal.
  return /(?:^|[\s"'(=,:;\[]|\/)\.\.(?:[\\/]|\s|$)/.test(text);
}

function isLoopbackUrl(u: string): boolean {
  const m = String(u).match(/^[a-z][a-z0-9+.-]*:\/\/(?:[^@/]*@)?(\[[^\]]*\]|[^/?#:]*)/i);
  const host = (m ? m[1] : "").replace(/^\[|\]$/g, "");
  return !!host && isLoopbackHost(host);
}

function scanTextSecrets(state: State, text: string): void {
  // A path that opts.isSecretPath knows, named anywhere in the text.
  for (const raw of text.split(/[\s"',;()<>{}|&=\[\]]+/)) {
    const token = raw.replace(/[.:]+$/, "").trim();
    if (!token || token.length < 4) continue;
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(token)) continue;
    if (!/[\\/]/.test(token) && !token.startsWith("~") && !token.startsWith(".")) continue;
    const expanded = expandHomeRefs(token, state.home);
    const abs = isAbs(expanded) ? normAbs(expanded) : joinAbs(state.cwd, expanded);
    const secret = checkSecret(state, [token, expanded, abs]);
    if (secret) addCredential(state, secret);
  }
  // The common forms a config file names, even when they are relative to another tool's home.
  for (const re of TEXT_SECRET_FORMS) {
    const m = text.match(re);
    if (!m) continue;
    const seen = m[0].trim().replace(/^[^A-Za-z0-9_.~%$\\/-]+/, "");
    addCredential(state, expandHomeRefs(seen, state.home));
  }
}

function scanTextEnv(state: State, text: string): void {
  if (TEXT_ENV_DUMP.test(text)) state.envWhole = true;
}

function scanTextNetwork(state: State, text: string): void {
  const lines = text.replace(/\\\r?\n/g, " ").split(/\r?\n/);
  for (const line of lines) {
    const urls = line.match(/\b[a-z][a-z0-9+.-]*:\/\/[^\s"'`<>)\]},;]+/gi) || [];
    const command = TEXT_NETWORK_WORD.test(line);
    if (!command && !urls.length) continue;
    const external = urls.filter((u) => !isLoopbackUrl(u));
    if (external.length) {
      for (const u of external) classifyURL(state, u);
      continue;
    }
    if (urls.length) {
      state.loopback = true;
      continue;
    }
    markDynamicNetwork(state);
  }
}

/** Static analysis of text in a language this module does not parse: a Rust, Go, Makefile, CMake,
 * TOML or YAML file, or a package.json. Comments stay. `danger` when the text names a credential
 * and a non-loopback destination, or downloads and pipes code into a shell; `review` for either
 * half alone; `local` otherwise. The hash covers the text. */
export function analyzeText(text: string, opts: AnalyzeOptions): EffectReport {
  const o = normalizeOptions(opts);
  const state = newState(o, "unknown", "<text>", o.cwd, 0);
  const bytes = Buffer.byteLength(text, "utf8");
  const script: EffectReport["scripts"][number] = { path: "<text>", lang: "unknown", bytes };
  state.code = text;
  if (bytes > o.maxBytes) {
    state.complete = false;
    return reportFromState(state, [script], sha256("<text>\0oversize:" + bytes));
  }
  scanTextSecrets(state, text);
  scanTextEnv(state, text);
  scanTextNetwork(state, text);
  if (TEXT_DOWNLOAD_PIPE.test(text.replace(/\\\r?\n/g, " "))) {
    state.obfuscated.add("downloaded code is piped to a shell");
  }
  // A destructive command that names a home or an outside path deletes more than this project.
  const destructive = TEXT_DESTRUCTIVE.test(text);
  if (destructive && textOutsideRef(text)) {
    state.dangerFile = true;
    state.notes.push("deletes or overwrites outside the project");
  }
  const report = reportFromState(state, [script], sha256("<text>\0" + text));
  if (destructive && report.level === "local") {
    report.level = "review";
    report.facts[report.facts.length - 1] = "level: review";
  }
  return report;
}

// ---------------------------------------------------------------------------
// What a session's changed files would do if they ran. Code languages are analysed as code, with
// imports left alone (only the changed file is the session's doing); text files go through
// analyzeText; a package.json has its scripts read as shell. Oversize and binary files are
// skipped without claiming the report is incomplete.

const TEXT_FILE_EXTENSIONS = new Set([
  "mk", "cmake", "toml", "cfg", "ini", "rs", "go", "yml", "yaml",
  "c", "cc", "cpp", "cxx", "h", "hpp", "java", "cs", "kt", "kts", "swift", "rb", "php", "pl", "lua", "zig",
]);
const TEXT_FILE_BASENAMES = new Set([
  "makefile",
  "gnumakefile",
  "justfile",
  "cmakelists.txt",
  "meson.build",
  "meson_options.txt",
  "dockerfile",
  "build.gradle",
  "pom.xml",
]);

type ChangedKind = "code" | "text" | "package";

function changedKind(file: string): ChangedKind | null {
  const base = baseName(file).toLowerCase();
  if (base === "package.json") return "package";
  if (TEXT_FILE_BASENAMES.has(base)) return "text";
  const ext = (base.match(/\.([a-z0-9]+)$/) || [])[1] || "";
  if (TEXT_FILE_EXTENSIONS.has(ext)) return "text";
  if (langFromExt(base)) return "code";
  return null;
}

function displayRel(cwd: string, abs: string): string {
  const s = slash(abs);
  if (underCI(s, cwd) && s.length > cwd.length + 1) return s.slice(cwd.length + 1);
  return s;
}

/** Static analysis of changed files, picked by extension and name: code languages as code without
 * following imports, package.json scripts as shell plus the text, and Makefile, CMake, meson,
 * TOML, INI, Rust, Go, YAML, Dockerfile, build.gradle and pom.xml as text. Each finding names the
 * file it came from. */
export function changedFileReport(paths: string[], opts: AnalyzeOptions): EffectReport {
  const o = normalizeOptions(opts);
  const parts: { file: string; report: EffectReport }[] = [];
  let incomplete = false;
  for (const spec of paths || []) {
    if (!spec) continue;
    let candidate = expandHomeRefs(slash(String(spec)), HOME).trim();
    if (!candidate) continue;
    if (!isAbs(candidate)) candidate = joinAbs(o.cwd, candidate);
    candidate = normAbs(candidate);
    let stat: fs.Stats;
    try {
      stat = fs.statSync(candidate);
    } catch {
      continue; // a path that does not exist is not a file to read
    }
    if (!stat.isFile()) continue;
    if (stat.size > o.maxBytes) continue;
    let buf: Buffer;
    try {
      buf = fs.readFileSync(candidate);
    } catch {
      incomplete = true;
      continue;
    }
    if (looksBinary(buf)) continue;
    let text = buf.toString("utf8");
    if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
    const file = displayRel(o.cwd, candidate);
    const kind = changedKind(candidate) ?? (langFromShebang(text.split(/\r?\n/, 1)[0] || "") ? "code" : null);
    if (!kind) continue;
    if (kind === "code") {
      parts.push({ file, report: analyzeFilesInner([candidate], o, false) });
      continue;
    }
    parts.push({ file, report: analyzeText(text, o) });
    if (kind !== "package") continue;
    let scripts: Record<string, unknown> = {};
    try {
      const parsed = JSON.parse(text);
      const entry = parsed && typeof parsed === "object" ? (parsed as Record<string, unknown>).scripts : undefined;
      if (entry && typeof entry === "object") scripts = entry as Record<string, unknown>;
    } catch {
      incomplete = true; // a package.json that does not parse cannot be followed
    }
    for (const value of Object.values(scripts)) {
      if (typeof value !== "string" || !value.trim()) continue;
      parts.push({ file, report: analyzeCode(value, "bash", o) });
    }
  }
  const merged = mergeReports(...parts.map((p) => p.report));
  if (incomplete) {
    merged.complete = false;
    const computed = computeLevel(merged);
    const rank = (l: string) => (l === "danger" ? 2 : l === "review" ? 1 : 0);
    if (rank(computed) > rank(merged.level)) merged.level = computed;
  }
  // Facts name the file each finding came from.
  const facts: string[] = [];
  for (const part of parts) {
    for (const fact of part.report.facts) {
      if (/^level: /.test(fact)) continue;
      const line = `${part.file}: ${fact}`;
      if (!facts.includes(line)) facts.push(line);
    }
  }
  if (incomplete) facts.push("incomplete: a changed file could not be read or parsed");
  if (!facts.length) facts.push(parts.length ? `${parts.map((p) => p.file).join(", ")}: nothing to report` : "no changed files to read");
  facts.length = Math.min(facts.length, 11);
  facts.push(`level: ${merged.level}`);
  merged.facts = facts;
  return merged;
}

export function mergeReports(...r: EffectReport[]): EffectReport {
  const list = r.filter(Boolean);
  if (!list.length) {
    const empty = emptyReport();
    empty.facts = buildFacts(empty);
    return empty;
  }
  const merged = emptyReport();
  merged.complete = true;
  const scripts = new Map<string, EffectReport["scripts"][number]>();
  const hashes: string[] = [];
  let forceDanger = false;
  let levelRank = 0;
  const rank = (l: string) => (l === "danger" ? 2 : l === "review" ? 1 : 0);
  for (const rep of list) {
    merged.complete = merged.complete && rep.complete;
    for (const s of rep.scripts || []) scripts.set(ciKey(s.path), s);
    if (rep.hash) hashes.push(rep.hash);
    for (const e of rep.network.external) merged.network.external.push(e);
    merged.network.loopback = merged.network.loopback || rep.network.loopback;
    merged.network.dynamic = merged.network.dynamic || rep.network.dynamic;
    for (const c of rep.credentials) merged.credentials.push(c);
    merged.env.whole = merged.env.whole || rep.env.whole;
    merged.env.names.push(...rep.env.names);
    merged.writes.outside.push(...rep.writes.outside);
    merged.writes.dynamic = merged.writes.dynamic || rep.writes.dynamic;
    merged.deletes.outside.push(...rep.deletes.outside);
    merged.deletes.dynamic = merged.deletes.dynamic || rep.deletes.dynamic;
    merged.reads.outside.push(...rep.reads.outside);
    merged.exec.commands.push(...rep.exec.commands);
    merged.exec.dynamic = merged.exec.dynamic || rep.exec.dynamic;
    merged.obfuscated.push(...rep.obfuscated);
    merged.notes.push(...(rep.notes || []));
    if (rep.level === "danger") forceDanger = true;
    levelRank = Math.max(levelRank, rank(rep.level));
  }
  merged.scripts = [...scripts.values()];
  merged.network.external = [...new Set(merged.network.external)].sort();
  merged.credentials = [...new Set(merged.credentials)].sort();
  merged.env.names = [...new Set(merged.env.names)].sort();
  merged.writes.outside = [...new Set(merged.writes.outside)].sort();
  merged.deletes.outside = [...new Set(merged.deletes.outside)].sort();
  merged.reads.outside = [...new Set(merged.reads.outside)].sort();
  merged.exec.commands = [...new Set(merged.exec.commands)];
  merged.obfuscated = [...new Set(merged.obfuscated)];
  merged.notes = [...new Set(merged.notes)];
  const computed = computeLevel(merged);
  merged.level = forceDanger || computed === "danger" ? "danger" : rank(computed) >= levelRank ? computed : levelRank === 1 ? "review" : "local";
  if (!merged.scripts.length) merged.hash = "";
  else if (hashes.length === 1) merged.hash = hashes[0];
  else merged.hash = sha256([...new Set(hashes)].sort().join("\n"));
  merged.facts = buildFacts(merged);
  return merged;
}
