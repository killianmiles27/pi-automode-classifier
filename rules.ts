// Deterministic rules for pi-automode-classifier. They run before the model and settle
// most tool calls:
//   deny     - blocked outright (wipes of /, $HOME or a system directory, disk formatting)
//   ask      - needs a confirm prompt (root, remote or outward-facing actions, deletes and
//              writes outside the working directory, reads of credential files, edits to this
//              guard's own files and to Pi's own files)
//   allow    - read-only commands, builds and tests, file changes inside the working directory,
//              running a file of the project or one the agent wrote in this session
//   classify - everything else goes to the decider
// With the chat decider, asks go to it as well, except the firm and locked ones (forDecider).
//
// A compound command gets the most severe verdict of its parts. Command substitutions and
// `sh -c` strings are parsed as commands too. Syntax the parser does not model (unbalanced
// quotes) is never allowed by rule.
//
// User rules (UserRules) replace the built-in verdict of a simple command. Two things they
// cannot replace: a built-in deny, and the ask for changes to the guard's own files.
//
// The rules also follow which files a session wrote or downloaded (Scope.files), so a script
// the agent wrote runs without the model and a downloaded one asks. Only writes the rules can
// see are followed: redirects, cp, mv, tee, curl and wget, not what a program writes itself.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export type Action = "allow" | "classify" | "ask" | "deny";
// The floor class of a verdict (docs/SPEC-auto-modes.md section 6). The decision core uses it
// when a model may only make a call stricter; `worst` keeps the class of the winning verdict.
export type VerdictClass = "hard" | "locked" | "exfil" | "critical" | "firm" | "outward" | "opaque";
export interface Verdict {
  action: Action;
  reason: string;
  // Which floor this verdict belongs to. An allow has none.
  class?: VerdictClass;
  // A user allow rule cannot replace this verdict.
  locked?: boolean;
  // An ask that stays an ask with the chat decider: your own ask rules and the critical asks.
  // Every other ask goes to the decider instead.
  firm?: boolean;
  // Root, credential reads and running downloaded code: a firm ask that is also blocked without
  // a UI, whatever `withoutUi.onAsk` says. A user rule for the command still replaces it.
  critical?: boolean;
  // Set when the call asks because it changes something outside the working directory: the
  // folder a "for this session" permission would cover.
  dir?: string;
  // Set when one command decides the verdict: an allow pattern for it that the confirm prompt
  // can offer for the session.
  pattern?: string;
  // The pattern came from an ask, so it is offered for the session only, never saved.
  fromAsk?: boolean;
  // An ask the rules sent to the chat model. It skips the classifiers listed before the chat
  // model: only the chat model sees whether the user asked for it.
  ruleAsk?: boolean;
  // Set on a classify verdict that runs files the session wrote: their paths, so the decider can
  // be given what runs. These are not write targets: the call does not change them.
  runs?: string[];
  // Files the call writes, whose content the decider is given.
  files?: string[];
}

const HOME = os.homedir();
const slash = (p: string) => p.replace(/\\/g, "/");
const GIT_ROOT = process.platform === "win32" ? [process.env.ProgramFiles, process.env["ProgramFiles(x86)"]]
  .filter((p): p is string => !!p).map((p) => path.join(p, "Git")).find((p) => fs.existsSync(path.join(p, "bin", "bash.exe"))) : undefined;
function shellPath(word: string): string {
  if (process.platform !== "win32") return word;
  if (/^\/(?:mnt\/)?[a-z](?:\/|$)/i.test(word)) return word.replace(/^\/(?:mnt\/)?([a-z])(?:\/|$)/i, (_match, drive) => `${drive}:/`);
  if (/^\/dev\//.test(word)) return word;
  if (/^\/tmp(?:\/|$)/.test(word)) return path.join(os.tmpdir(), word.slice(4));
  if (GIT_ROOT && word.startsWith("/") && !word.startsWith("//")) return path.join(GIT_ROOT, word.slice(1));
  return word;
}
const RANK: Record<Action, number> = { allow: 0, classify: 1, ask: 2, deny: 3 };
function worst(...verdicts: Verdict[]): Verdict {
  const hold = (v: Verdict) => (v.locked ? 3 : v.critical ? 2 : v.firm ? 1 : 0);
  const w = verdicts.reduce((a, b) => (RANK[b.action] > RANK[a.action] || (RANK[b.action] === RANK[a.action] && hold(b) > hold(a)) ? b : a));
  // Files that run and files that are written go to the decider whichever part of the command
  // reaches them. `runs` is not a write target, so it does not hold back the fast paths.
  const files = verdicts.flatMap((v) => v.files ?? []);
  const runs = verdicts.flatMap((v) => v.runs ?? []);
  if (w.action !== "classify") return w;
  const merged = { ...w };
  if (files.length) merged.files = [...new Set(files)];
  if (runs.length) merged.runs = [...new Set(runs)];
  return merged;
}
const ALLOW: Verdict = { action: "allow", reason: "" };
const classify = (reason: string): Verdict => ({ action: "classify", reason, class: "opaque" });
const ask = (reason: string): Verdict => ({ action: "ask", reason, class: "outward" });
const deny = (reason: string): Verdict => ({ action: "deny", reason, class: "hard" });
const guardAsk = (reason: string): Verdict => ({ action: "ask", reason, class: "locked", locked: true });
const criticalAsk = (reason: string): Verdict => ({ action: "ask", reason, class: "critical", firm: true, critical: true });
// A classify for something that reaches outside the working directory (git hooks, persistence).
const outwardClassify = (reason: string): Verdict => ({ action: "classify", reason, class: "outward" });
// With the chat decider, Claude Code's split: the rules allow what is plainly routine and block
// what is plainly destructive, and the decider judges the rest instead of you being asked.
const forDecider = (v: Verdict, scope: Scope): Verdict => (scope.chatDecider && v.action === "ask" && !v.locked && !v.firm ? { ...v, action: "classify", ruleAsk: true } : v);

// ---- paths ----

// realpath that also works for a path that does not exist: resolves the deepest existing
// ancestor and keeps the rest.
function realish(p: string): string {
  // No real path is this deep, and walking up one like it means thousands of disk lookups.
  if (p.length > 2048) return p;
  const tail: string[] = [];
  let cur = p;
  for (;;) {
    try {
      return path.join(fs.realpathSync.native(cur), ...tail);
    } catch {
      const parent = path.dirname(cur);
      if (parent === cur) return p;
      tail.unshift(path.basename(cur));
      cur = parent;
    }
  }
}

export function within(p: string, dir: string, strict = false): boolean {
  const rel = path.relative(dir, p);
  if (rel === "") return !strict;
  return rel !== ".." && !rel.startsWith(".." + path.sep) && !path.isAbsolute(rel);
}

const TMP_DIRS = [...new Set(["/tmp", "/var/tmp", os.tmpdir()].map((p) => realish(shellPath(p))))];
const DEV_SINKS = /^\/dev\/(null|zero|stdout|stderr|tty|fd\/\d+)$/;

// Where the content of a file written in this session came from: the agent itself (write tool,
// heredoc, echo, printf), a download, or a command whose output the rules cannot know.
export type Origin = "authored" | "fetched" | "other";
export type SessionFiles = Map<string, Origin>;

export interface Scope {
  // Working directory, or undefined once a `cd` made it unknown.
  cwd: string | undefined;
  // Project root: file changes inside it are allowed. Undefined when Pi runs from $HOME or above.
  root: string | undefined;
  // This guard's own files and Pi's settings. Changes to them always ask.
  guarded: string[];
  // Pi's agent directory. See isPiFile.
  piDirs: string[];
  // Extra directories where file changes are allowed, like the project root.
  allowed: string[];
  rules?: UserRules;
  // Patterns allowed for the session in a prompt. Unlike your own rules they never replace a
  // firm ask: root, a credential read or downloaded code still asks.
  picked?: Matcher[];
  // Files written by earlier calls of the session.
  files: SessionFiles;
  // Files the call being checked would write. commitWrites() adds them to `files` once the
  // call is allowed to run.
  pending: SessionFiles;
  // True for a file of the project checkout: tracked or ignored by the session's git repository.
  project?: (p: string) => boolean;
  // With the chat decider, running a file the session wrote or edited goes to it instead of being
  // allowed. Otherwise writing code to a file and running it would skip the decider.
  chatDecider?: boolean;
  // Shell variables the command set to a known path before this point.
  vars?: Map<string, string>;
  // Variables of a `for` loop over literal words, so they only ever hold one of those words.
  loopVars?: Set<string>;
  // Hosts you trust for read-only ssh (`remote.trustedHosts`): a command run there that the
  // rules would allow here, reading and nothing else, runs without a judge.
  trustedHosts?: string[];
  // Set while checking the command an ssh call runs on a trusted host. Its paths are that host's,
  // so they are never inside the project and never mapped onto this machine's files.
  remote?: boolean;
  // Set for the second pass over that command: sudo in front of a read-only command is allowed
  // here, and the ssh call goes to the judges instead of needing your own words.
  remoteRoot?: boolean;
}

const expandHome = (p: string) => (p === "~" || p.startsWith("~/") ? HOME + p.slice(1) : p);
const withTargets = (paths: string[]) => [...new Set(paths.map(expandHome).flatMap((p) => [p, realish(p)]))];

export interface ScopeOptions {
  allowedPaths?: string[];
  piDirs?: string[];
  rules?: UserRules;
  picked?: Matcher[];
  files?: SessionFiles;
  project?: (p: string) => boolean;
  chatDecider?: boolean;
  trustedHosts?: string[];
}

export function makeScope(cwd: string, guarded: string[], options: ScopeOptions = {}): Scope {
  const real = realish(cwd);
  return {
    cwd: real,
    root: within(HOME, real) ? undefined : real,
    guarded: withTargets(guarded),
    piDirs: withTargets(options.piDirs ?? []),
    allowed: withTargets(options.allowedPaths ?? []),
    rules: options.rules,
    picked: options.picked,
    files: options.files ?? new Map(),
    pending: new Map(),
    project: options.project,
    chatDecider: options.chatDecider,
    trustedHosts: options.trustedHosts?.map((h) => h.trim().toLowerCase()).filter(Boolean),
  };
}

// Call after a checked tool call was allowed to run.
export function commitWrites(scope: Scope) {
  for (const [p, origin] of scope.pending) scope.files.set(p, origin);
}

// ---- user rules ----

export interface Matcher {
  source: string;
  test(text: string): boolean;
}
export type UserRules = Record<Action, Matcher[]>;

// A pattern is a glob over one whole simple command, where `*` matches any text and a
// trailing ` *` also matches no arguments. With a `re:` prefix it is a regular expression.
export function compilePattern(pattern: string): Matcher {
  let re: RegExp;
  if (pattern.startsWith("re:")) re = new RegExp(pattern.slice(3), "s");
  else {
    const words = pattern.trim().split(/\s+/).join(" ");
    const open = words.endsWith(" *");
    const body = (open ? words.slice(0, -2) : words).split("*").map((part) => part.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*");
    re = new RegExp(`^${body}${open ? "( .*)?" : ""}$`, "s");
  }
  return { source: pattern, test: (text) => re.test(text) };
}

export function compileRules(rules: Partial<Record<Action, string[]>>): UserRules {
  const compile = (action: Action) => (rules[action] ?? []).map(compilePattern);
  return { deny: compile("deny"), ask: compile("ask"), classify: compile("classify"), allow: compile("allow") };
}

// deny, ask and classify rules also match the command without its wrappers (`timeout 60`,
// `FOO=1`). An allow rule must match the command as written, or without the shell keywords
// and wrappers that do not change what runs (`then`, `timeout 60`, `nice`). It does not match
// behind `env` or a VAR=value assignment, which can change what runs.
function userVerdict(argv: string[], rules: UserRules): Verdict | undefined {
  const raw = argv.join(" ");
  const bare = unwrap(argv).join(" ");
  for (const action of ["deny", "ask", "classify"] as const) {
    const hit = rules[action].find((m) => m.test(raw) || m.test(bare));
    if (hit) {
      return {
        action,
        reason: `your ${action} rule "${hit.source}"`,
        class: action === "deny" ? "hard" : action === "ask" ? "firm" : "opaque",
        ...(action === "ask" && { firm: true }),
      };
    }
  }
  return allowedBy(argv, rules.allow) ? ALLOW : undefined;
}

function allowedBy(argv: string[], allow: Matcher[]): boolean {
  const raw = argv.join(" ");
  const plain = unwrap(argv, SAME_PROGRAM_WRAPPERS).join(" ");
  return allow.some((m) => m.test(raw) || (plain !== "" && m.test(plain)));
}

// Absolute path for a shell word, or undefined when it cannot be known (variable, ~user,
// relative path after an unknown cd).
const expandVars = (word: string, scope: Scope) => word.replace(/\$\{(\w+)\}|\$(\w+)/g, (m, a, b) => ((a ?? b) === "PWD" ? scope.cwd : scope.vars?.get(a ?? b)) ?? m);
function resolveWord(word: string, scope: Scope): string | undefined {
  word = expandVars(word, scope);
  if (/[$`]/.test(word)) return undefined;
  if (scope.remote) {
    // A path on the remote host. `~` stands for its home, so ~/.ssh/id_rsa still reads as a key.
    if (word === "~" || word.startsWith("~/")) word = REMOTE_HOME + word.slice(1);
    else if (word.startsWith("~")) return undefined;
    return path.posix.isAbsolute(word) ? path.posix.normalize(word) : undefined;
  }
  if (process.platform === "win32") {
    // Git Bash drive paths refer to Windows files, not a folder on the current drive.
    word = shellPath(word);
    if (/^\/dev\//.test(word)) return word;
  }
  if (word === "~" || word.startsWith("~/")) word = HOME + word.slice(1);
  else if (word.startsWith("~")) return undefined;
  if (!path.isAbsolute(word)) {
    if (!scope.cwd) return undefined;
    word = path.resolve(scope.cwd, word);
  }
  return realish(path.normalize(word));
}

const isGuarded = (p: string | undefined, scope: Scope) => !!p && scope.guarded.some((g) => within(p, g));
// Pi's own configuration, instructions and code: its agent directory, any `.pi` directory (a
// project's Pi config, or a dotfiles copy of the agent directory) and the context files Pi reads
// in every directory. A change to them changes what later sessions do, so it asks you, also with
// the chat decider. Your own allow rules can replace that ask.
const CONTEXT_FILES = new Set(["AGENTS.md", "AGENTS.override.md", "AGENTS.MD", "CLAUDE.md", "CLAUDE.MD"]);
const isPiFile = (p: string | undefined, scope: Scope) => !!p && (p.split(/[\\/]/).some((part) => process.platform === "win32" ? part.toLowerCase() === ".pi" : part === ".pi") || CONTEXT_FILES.has(path.basename(p)) || (process.platform === "win32" && /^(agents(?:\.override)?|claude)\.md$/i.test(path.basename(p))) || scope.piDirs.some((d) => within(p, d)));
const piAsk = (reason: string): Verdict => ({ action: "ask", reason, class: "firm", firm: true });
const inTmp = (p: string) => TMP_DIRS.some((d) => within(p, d, true));
// Provably inside the project or a temp directory.
const isLocal = (p: string | undefined, scope: Scope) =>
  !!p && ((!!scope.root && within(p, scope.root)) || TMP_DIRS.some((d) => within(p, d)) || scope.allowed.some((d) => within(p, d)));
// /, a top-level directory, $HOME or a parent of it.
export const isRootLike = (p: string) => p === "/" || path.dirname(p) === "/" || within(HOME, p) || (process.platform === "win32" && (
  path.resolve(p) === path.parse(path.resolve(p)).root ||
  path.dirname(path.resolve(p)) === path.parse(path.resolve(p)).root ||
  [process.env.SystemRoot, process.env.ProgramFiles, process.env["ProgramFiles(x86)"], process.env.ProgramData].some((d) => !!d && within(p, d))
));
const BARE_GLOB = /^(\*|\.\*|\.\[!\.\]\*|\{.*\})$/;

// The folder a session permission for `p` would cover: the git checkout or worktree it is in,
// else its parent directory. Undefined for /, $HOME and system directories, which are never
// opened as a whole.
function folderFor(p: string | undefined): string | undefined {
  if (!p) return undefined;
  const parent = path.dirname(p);
  for (let d = parent; !isRootLike(d); d = path.dirname(d)) {
    if (fs.existsSync(path.join(d, ".git"))) return d;
  }
  return isRootLike(parent) ? undefined : parent;
}
// An ask for a change outside the working directory, with the folder it could be allowed for.
// The `dir` key is there even when no folder can be offered: such an ask is about a path, so it
// never gets a command pattern.
// A path the rules cannot resolve (`$D`, `t_$h.html`) is unknown, not outside, so it goes to the judges
// on its merits. A known path outside needs the user's words, as does anything that deletes.
const outside = (reason: string, p: string | undefined): Verdict => ({ action: "ask", reason, class: p ? "outward" : "opaque", dir: folderFor(p) });
const outsideDelete = (reason: string, p: string | undefined): Verdict => ({ action: "ask", reason, class: "outward", dir: folderFor(p) });

// ---- files of the session ----

const originOf = (p: string, scope: Scope) => scope.pending.get(p) ?? scope.files.get(p);
// Records that the call writes `p`. A download stays one until the agent rewrites the whole file.
function note(p: string | undefined, origin: Origin, scope: Scope) {
  if (p && !(origin === "other" && originOf(p, scope) === "fetched")) scope.pending.set(p, origin);
}
const isFetched = (word: string, scope: Scope) => {
  const p = resolveWord(word, scope);
  return !!p && originOf(p, scope) === "fetched";
};

// A script with one of these in its name or arguments stays with the model, even when it is
// a file of the project.
const OUTWARD_WORDS = /deploy|publish|release|upload|prod/i;

// Verdict for running the file `word` with `args`, or undefined when the rules cannot tell.
// A file the agent wrote in this session and a file of the project checkout are allowed: they
// run the same code as the project's build and tests. A download asks.
function runFile(word: string, args: string[], scope: Scope): Verdict | undefined {
  const p = resolveWord(word, scope);
  if (!p) return undefined;
  const origin = originOf(p, scope);
  if (origin === "fetched") return criticalAsk(`runs a file downloaded in this session: ${word}`);
  if (isGuarded(p, scope) || !isLocal(p, scope) || OUTWARD_WORDS.test([path.basename(word), ...args].join(" "))) return undefined;
  if (origin === "authored") {
    if (!scope.chatDecider) return ALLOW;
    // A file written by this same command is in the command itself.
    return { ...classify(`runs ${word}, which this session wrote`), runs: scope.pending.has(p) ? [] : [p] };
  }
  return origin === undefined && scope.project?.(p) ? ALLOW : undefined;
}

// ---- credentials ----

// Places that hold credentials, in any home directory, and file names that do so anywhere.
// Reading one puts it into the agent's transcript, so it asks even for a read-only command.
const SECRET_PLACES = [
  /\/\.(ssh|aws|gnupg|kube|azure|oci|password-store)(\/|$)/,
  /\/\.config\/(gcloud|op|gh\/hosts\.yml)(\/|$)/,
  /\/\.docker\/config\.json$/,
  /\/\.cargo\/credentials(\.toml)?$/,
  /\/\.terraform\.d\/credentials\.tfrc\.json$/,
  /\/\.local\/share\/keyrings(\/|$)/,
  /\/Library\/Keychains(\/|$)/,
  /^\/etc\/(g?shadow-?|ssl\/private(\/.*)?|ssh\/ssh_host_\w+_key)$/,
  /^\/proc\/[^/]+\/environ$/,
  // Pi's logins and other coding agents' logins.
  /\/\.pi\/agent\/(auth|mcp-auth|antigravity-accounts)\.json$/,
  /\/\.(codex|claude)\/(auth|\.credentials)\.json$/,
  /\/\.local\/share\/opencode\/auth\.json$/,
];
const SECRET_NAMES =
  /^(id_(rsa|dsa|ecdsa|ed25519)(_[\w.-]+)?|.+\.(pem|key|p12|pfx|jks|keystore|kdbx)|\.env(\.[\w.-]+)?|credentials\.(json|ya?ml|toml|ini|csv|xml)|secrets?\.(json|ya?ml|toml|ini|env|txt)|.*service[-_]?(account|principal).*\.json|\.(netrc|npmrc|pypirc|git-credentials|vault-token|pgpass|htpasswd)|\.(bash|zsh)_history|.*\.keychain(-db)?)$/i;
// A file name that is a credential in the right directory. With an unknown working directory the
// directory is unknowable, so reading one of these bare names is judged, not allowed.
const CREDENTIAL_BARE_NAMES = new Set(["credentials", "config", "id_rsa", "auth.json", "hosts.yml"]);

// Your own credential files and folders: the config's secretPaths, absolute.
let extraSecrets: string[] = [];
export function setSecretPaths(paths: string[]) {
  extraSecrets = paths.map((p) => p.replace(/\/+$/, "")).filter(Boolean);
}

// Bash brace expansion, used only when a credential path is checked. The corpus treats a single
// alternative as an expansion too (`.a{w}s` is `.aws`), so every brace group is reduced.
// The budget counts calls, not results: results collapse into duplicates, so a cap on them never
// trips, and a guard that hangs freezes the whole session.
function braceExpand(word: string, budget = { calls: 2000 }): string[] {
  const m = /\{([^{}]*)\}/.exec(word);
  if (!m || budget.calls-- <= 0) return [word];
  const inner = m[1];
  let parts: string[];
  const numeric = /^(-?\d+)\.\.(-?\d+)$/.exec(inner);
  const alpha = /^([A-Za-z])\.\.([A-Za-z])$/.exec(inner);
  if (numeric) {
    const from = Number(numeric[1]);
    const to = Number(numeric[2]);
    const step = from <= to ? 1 : -1;
    parts = [];
    for (let n = from; n !== to + step && parts.length < 32; n += step) parts.push(String(n));
  } else if (alpha) {
    const from = alpha[1].charCodeAt(0);
    const to = alpha[2].charCodeAt(0);
    const step = from <= to ? 1 : -1;
    parts = [];
    for (let n = from; n !== to + step && parts.length < 32; n += step) parts.push(String.fromCharCode(n));
  } else if (inner.includes(",")) parts = inner.split(",");
  else parts = [inner];
  const pre = word.slice(0, m.index);
  const post = word.slice(m.index + m[0].length);
  const out: string[] = [];
  for (const part of parts) {
    if (out.length >= 128 || budget.calls <= 0) break;
    out.push(...braceExpand(pre + part + post, budget));
  }
  return [...new Set(out)].slice(0, 128);
}

// Fill the wildcards in a word with the characters and short names that turn it into a credential
// path: `auth.jso?` -> auth.json, `.docker/config.jso?` -> config.json, `hosts.y?l` -> hosts.yml.
// The check only asks whether the glob could name a secret, so ordinary globs (.md, src/*.ts) stay out.
const GLOB_FILL_BUDGET = 4000;
// Paths a many-wildcard glob is tested against, when filling it in would be too much work.
const WELL_KNOWN_SECRETS = [".ssh/id_rsa", ".ssh/id_ed25519", ".ssh/id_ecdsa", ".aws/credentials", ".pi/agent/auth.json", ".netrc", ".npmrc", ".pypirc", ".git-credentials", ".docker/config.json", ".config/gh/hosts.yml", ".kube/config", ".env", ".gnupg/secring.gpg", ".local/share/opencode/auth.json", ".codex/auth.json", ".claude/.credentials.json", "/proc/self/environ", "/etc/shadow"];
function globNamesWellKnownSecret(glob: string): boolean {
  // A bare run of wildcards says nothing: `cat *` in a project is not a credential read.
  if ((glob.match(/[A-Za-z0-9_.-]{2,}/g) ?? []).length === 0) return false;
  if (glob.length > 512) return false;
  const escaped = (text: string) => text.replace(/\*+/g, "*").replace(/\[[^\]]*\]/g, "?").replace(/[.+^${}()|\\]/g, "\\$&").replace(/\*/g, "[^/]*").replace(/\?/g, "[^/]");
  const segments = glob.replace(/\\/g, "/").replace(/\/+$/, "").split("/").filter(Boolean);
  if (!segments.length) return false;
  // Compare the glob's last segments with the same number of trailing segments of each
  // well-known path, so the home prefix of an absolute glob does not have to match and
  // `.a*/credentials` is tested exactly where it names a credential directory.
  return WELL_KNOWN_SECRETS.some((s) => {
    const secret = s.replace(/^\/+/, "").split("/").filter(Boolean);
    if (!secret.length || segments.length < secret.length) return false;
    const pattern = segments.slice(-secret.length).join("/");
    // A segment with no literal character says nothing: `cat *` and `cat */*` name no credential.
    if (!/[A-Za-z0-9]/.test(pattern)) return false;
    try {
      return new RegExp(`^${escaped(pattern)}$`, "i").test(secret.join("/"));
    } catch {
      return false;
    }
  });
}
// What a glob with wildcards only in its last part matches right now, when its directory exists
// and is not itself a credential place: `capabilities/*.json` is the files that are there, not a
// guessed credentials.json. Undefined when the directory cannot be listed, so guessing takes over.
function globOnDisk(glob: string): string[] | undefined {
  const dir = path.posix.dirname(glob);
  const base = path.posix.basename(glob);
  if (!(path.posix.isAbsolute(dir) || /^[a-z]:\//i.test(dir)) || /[?*[\]]/.test(dir) || !/[?*[]/.test(base)) return undefined;
  // A hostile word can carry thousands of wildcards; such a word is guessed at, not compiled.
  if (base.length > 200 || (base.match(/[?*[]/g) ?? []).length > 8) return undefined;
  if (SECRET_PLACES.some((place) => place.test(dir + "/x"))) return undefined;
  let names: string[];
  try {
    names = fs.readdirSync(process.platform === "win32" ? dir.replace(/^\/([a-z])\//i, "$1:/") : dir);
  } catch {
    return undefined;
  }
  const re = new RegExp(`^${base.replace(/[.+^${}()|\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".").replace(/\[!/g, "[^")}$`, process.platform === "win32" ? "i" : "");
  return names.filter((n) => re.test(n)).map((n) => `${dir}/${n}`);
}

function globFill(word: string): string[] {
  const stars = ["", "n", "x", "json", "yml", "yaml", "pem", "key", "rsa", "ed25519", "credentials", "config", "auth"];
  const ones = ["n", "m", "l", "x", "1", "a", "s", "e", "r", "t", "o", "u"];
  const out: string[] = [];
  // Counts work, not results: wildcards multiply, and a guard that hangs freezes the session.
  let budget = GLOB_FILL_BUDGET;
  const walk = (prefix: string, rest: string, depth: number) => {
    if (budget-- <= 0 || depth > 10) return;
    const m = /[?*]|\[([^\]]*)\]/.exec(rest);
    if (!m) { out.push(prefix + rest); return; }
    const before = prefix + rest.slice(0, m.index);
    const after = rest.slice(m.index + m[0].length);
    if (m[0] === "?") for (const fill of ones) walk(before + fill, after, depth + 1);
    else if (m[0] === "*") for (const fill of stars) walk(before + fill, after, depth + 1);
    else {
      const chars = m[1].startsWith("!") ? ones : m[1].replace(/\\/g, "").split("");
      for (const fill of chars.slice(0, 12)) walk(before + fill, after, depth + 1);
    }
  };
  walk("", word, 0);
  return [...new Set(out)];
}

export function isSecretPath(p: string): boolean {
  p = slash(p);
  if (p.includes("{")) return braceExpand(p).some((x) => isSecretPath(x.replace(/[{}]/g, "")));
  if (/[?*\[]/.test(p)) {
    // A glob that names a well-known credential path says so however few wildcards it has.
    if (globNamesWellKnownSecret(p)) return true;
    // Past this many wildcards, filling them in cannot finish and the word is rarely a path at all.
    if ((p.match(/[?*\[]/g) ?? []).length > 3) return false;
    const onDisk = globOnDisk(p);
    if (onDisk) return onDisk.some(isSecretPath);
    return globFill(p).some(isSecretPath);
  }
  if (process.platform === "win32") p = p.toLowerCase();
  if (extraSecrets.some((s) => { s = slash(s); if (process.platform === "win32") s = s.toLowerCase(); return p === s || p.startsWith(s + "/"); })) return true;
  const name = path.basename(p);
  // Public keys, host lists, client settings, env templates and certificates hold nothing secret.
  if (/\.pub$|^known_hosts|^authorized_keys$|^\.env\.(example|sample|template|dist|defaults?)$/i.test(name)) return false;
  if (/\/\.(ssh|aws)\/config$/.test(p)) return false;
  if (/cert|chain|public|(^|[._-])ca([._-]|$)/i.test(name) && !/priv|key/i.test(name.replace(/\.key$/i, ""))) return false;
  return SECRET_PLACES.some((place) => place.test(p) || (process.platform === "win32" && place.test(p.replace(/^[a-z]:/i, "")))) || SECRET_NAMES.test(name);
}

// Directories that hold credentials. A recursive reader of one of these prints secrets even when
// no single operand names a credential file (`grep -r key ~/.pi/agent`).
const CREDENTIAL_DIRS = [
  /\/\.(ssh|aws|gnupg|kube|azure|oci|password-store)(\/|$)/,
  /\/\.config\/(gcloud|op|gh)(\/|$)/,
  /\/\.docker(\/|$)/,
  // ~/.cargo itself, not the crate sources under registry/ and git/, which are public code.
  /\/\.cargo(\/(?!registry\/|git\/)|$)/,
  /\/\.terraform\.d(\/|$)/,
  /\/\.pi\/agent(\/|$)/,
  /\/\.(codex|claude)(\/|$)/,
  /\/\.local\/share\/opencode(\/|$)/,
  /\/Library\/Keychains(\/|$)/,
  /^\/etc(\/|$)/,
  /^\/proc\//,
];
const CREDENTIAL_CHILDREN = [".ssh", ".aws", ".gnupg", ".kube", ".pi/agent", ".config/gh", ".docker", ".cargo"];
/** True for a directory (or a home directory root) that holds credential files. */
export function isCredentialDirectory(p: string | undefined): boolean {
  if (!p) return false;
  let s = slash(p).replace(/\/+$/, "");
  if (!s) return false;
  if (process.platform === "win32") s = s.toLowerCase();
  const home = process.platform === "win32" ? slash(HOME).toLowerCase() : slash(HOME);
  // HOME itself, and any directory above it, contains the credential folders of a home.
  if (s === home || within(home, s)) return true;
  if (CREDENTIAL_DIRS.some((re) => re.test(s) || re.test(s + "/"))) return true;
  // A home-shaped root (the eval fake home, a copied home) holds credentials in child folders.
  // Only a child that actually exists counts; appending `.ssh` to every project path would make
  // every project folder look like a credential store.
  return CREDENTIAL_CHILDREN.some((child) => {
    const dir = slash(path.join(s, child));
    return fs.existsSync(dir) && CREDENTIAL_DIRS.some((re) => re.test(dir.replace(/\/+$/, "") + "/"));
  });
}

// Environment variables whose value is a credential rather than a setting. Matching one word of
// the name keeps NODE_ENV, PATH and HOME out, and strips a suffix that turns the value into a
// path (`OPENAI_API_KEY_FILE`).
const SAFE_ENV = new Set([
  "PATH", "PATHEXT", "HOME", "USERPROFILE", "PWD", "OLDPWD", "SHELL", "TERM", "TERM_PROGRAM", "LANG", "LANGUAGE",
  "LC_ALL", "LC_CTYPE", "TMP", "TEMP", "TMPDIR", "NODE_ENV", "HOSTNAME", "COMPUTERNAME", "USER", "USERNAME", "LOGNAME",
  "SHLVL", "RANDOM", "PPID", "SHELLOPTS", "BASHOPTS", "COLUMNS", "LINES", "OSTYPE", "MACHTYPE", "HOSTTYPE", "EDITOR",
  "VISUAL", "PAGER", "DISPLAY", "XAUTHORITY", "NO_COLOR", "FORCE_COLOR", "CI", "PS1", "VIRTUAL_ENV", "CONDA_PREFIX",
]);
const SECRET_ENV_WORD = /^(key|keys|apikey|token|tokens|secret|secrets|password|passwd|passphrase|credential|credentials|auth|authorization|private|signing|salt|cookie|cookies|session|dsn|pat|jwt|bearer)$/i;
/** True for a variable name that looks like it holds a token: OPENAI_API_KEY, GITHUB_TOKEN. */
export function isSecretEnvName(name: string): boolean {
  const upper = name.toUpperCase();
  if (SAFE_ENV.has(upper)) return false;
  const value = upper.replace(/_(FILE|PATH|DIR|FOLDER|NAME|PREFIX|SUFFIX|TYPE|URL)$/, "");
  if (SAFE_ENV.has(value)) return false;
  return value.split(/_+/).some((word) => SECRET_ENV_WORD.test(word));
}

// A command that prints the whole environment or a secret variable from it. Reading one of these
// into the transcript hands the agent every token the shell can see, so the model judges it.
function printsSecrets(name: string, args: string[]): boolean {
  if (["export", "declare", "typeset", "readonly"].includes(name)) {
    if (!args.length) return true;
    if (args.includes("-p")) return true;
    // -x alone lists the exported variables; with an assignment it only sets one.
    return args.includes("-x") && !args.some((a) => /^[A-Za-z_]\w*=/.test(a));
  }
  if (name === "set") return args.length === 0;
  if (name === "compgen") return args.some((a) => a === "-e" || a === "-v");
  if (name === "printenv") return args.some((a) => !a.startsWith("-") && isSecretEnvName(a));
  if (name === "echo" || name === "printf") {
    for (const arg of args) {
      for (const m of arg.matchAll(/\$\{(\w+)\}|\$(\w+)/g)) {
        if (isSecretEnvName(m[1] ?? m[2])) return true;
      }
    }
  }
  return false;
}

// A write target under .git/hooks runs on the next git command: persistence outside the file.
const isGitHook = (p: string | undefined) => !!p && /(^|[\\/])\.git[\\/]hooks([\\/]|$)/i.test(p);
const gitHookWrite = (target: string) => outwardClassify(`writes the git hook ${target}, which runs on your next git command`);

// The credential file a shell word names, if any. Handles `--file=path`, curl's `@file` and
// git's `rev:path`. In a command, words with spaces and URLs are text, not paths.
function secretIn(word: string, scope: Scope, isPath = false): string | undefined {
  if (!isPath && (/\s/.test(word) || /^[a-z][a-z0-9+.-]*:\/\//i.test(word))) return undefined;
  const text = word.replace(/^[^=/]*=/, "").replace(/^@/, "");
  for (const expanded of braceExpand(text)) {
    for (const candidate of new Set([expanded, expanded.slice(expanded.lastIndexOf(":") + 1)])) {
      if (!candidate || candidate.startsWith("-")) continue;
      const p = resolveWord(candidate, scope);
      // A glob over a folder that exists is judged by what it matches there.
      const onDisk = p && /[?*[]/.test(candidate) ? globOnDisk(slash(p)) : undefined;
      if (onDisk) {
        if (onDisk.some(isSecretPath)) return candidate;
        continue;
      }
      if (isSecretPath(expandHome(candidate)) || (p && isSecretPath(p))) return candidate;
    }
  }
  return undefined;
}

// Commands that name a path without showing what is in it.
const NAMES_ONLY = new Set(
  `ls stat test [ file du find readlink realpath basename dirname which echo printf rm rmdir unlink mkdir
   touch chmod chown chgrp setfacl tee truncate shred`.split(/\s+/),
);
// The first operand of these is a pattern, filter or script, not a file.
const PATTERN_FIRST = new Set(["grep", "egrep", "fgrep", "rg", "ag", "ack", "sed", "awk", "gawk", "jq", "yq"]);

// sed with an in-place flag rewrites its files; without one it only prints.
const sedWrites = (args: string[]) => args.some((a) => /^(-i|--in-place)/.test(a) || /^-[a-zA-Z]*i/.test(a));
// find options that delete files, run a command or write a file.
const FIND_ACTS = /^-(delete|exec|execdir|ok|okdir|fprint|fprintf|fls)$/;
// A command that cannot change a file: the read-only tools, `cd`, sed without -i, find without
// an action, and an interpreter or shell given no code and no file to run.
const readsOnlyCommand = (name: string, args: string[], scope?: Scope) =>
  READ_ONLY.has(name) || ["cd", "pushd", "popd"].includes(name)
    || (name === "sed" && !sedWrites(args))
    || (name === "find" && findReads(args, scope));
// find that only lists: no action at all, or an -exec whose own command only reads. The {} and
// glob words after -exec are not paths the guard check should resolve against the cwd.
function findReads(args: string[], scope?: Scope): boolean {
  const acts = args.filter((a) => FIND_ACTS.test(a));
  if (!acts.length) return true;
  if (acts.some((a) => a !== "-exec" && a !== "-execdir" && a !== "-ok" && a !== "-okdir")) return false;
  for (let exec = 0; exec < args.length; exec++) {
    if (!/^-(exec|execdir|ok|okdir)$/.test(args[exec])) continue;
    const end = args.findIndex((a, i) => i > exec && (a === ";" || a === "+"));
    const inner = unwrap(args.slice(exec + 1, end < 0 ? undefined : end).map((a) => (a === "{}" ? "." : a)));
    if (!inner.length || !readsOnlyCommand(path.basename(inner[0]), inner.slice(1), scope)) return false;
    if (scope && simple({ argv: inner, out: [] }, scope, 1).action !== "allow") return false;
    if (end < 0) break;
    exec = end;
  }
  return true;
}

// The credential file or credential directory a simple command would read, if any.
function credentialRead(name: string, args: string[], cmd: Simple, scope: Scope): string | undefined {
  if (NAMES_ONLY.has(name)) return undefined;
  // An in-place edit shows nothing, and a destination is written, not read.
  if (name === "sed" && sedWrites(args)) return undefined;
  let words = args;
  if (PATTERN_FIRST.has(name)) words = operands(args).slice(1);
  else if (COPIERS.has(name)) words = operands(args).slice(0, -1);
  // `--env-file .env` hands the file to a program and shows nothing.
  words = words.filter((w, i) => !/^--env-file(=|$)/.test(w) && words[i - 1] !== "--env-file");
  for (const word of [...words, ...(cmd.in ?? [])]) {
    const secret = secretIn(word, scope);
    if (secret) return secret;
  }
  // A recursive reader of a directory that holds credentials prints them even though the path
  // itself is not a credential file. `ls` stays out: it shows names, not contents.
  if (readsDirectoryRecursively(name, args)) {
    for (const word of [...words, ...(cmd.in ?? [])]) {
      const p = resolveWord(word, scope);
      if (!p) continue;
      const stat = fs.statSync(p, { throwIfNoEntry: false });
      // A file named inside a credential folder is a credential read only when it is one; a
      // directory (or a missing path that is a credential folder) is searched below.
      if (stat && !stat.isDirectory()) continue;
      if (isCredentialDirectory(p)) return word;
    }
  }
  return undefined;
}

// grep -r and rg search below their operands; tar c and cp/rsync -r copy a whole directory.
function readsDirectoryRecursively(name: string, args: string[]): boolean {
  if (name === "rg" || name === "ag" || name === "ack") return true;
  if (name === "grep" || name === "egrep" || name === "fgrep") return args.some((a) => /^-[a-zA-Z]*[rR]/.test(a) || a === "--recursive" || a === "--dereference-recursive");
  if (name === "tar") return args.some((a) => /^[a-zA-Z]*c/.test(a) && !a.startsWith("--")) || args.includes("--create");
  if (name === "cp" || name === "rsync") return args.some((a) => /^-[a-zA-Z]*[rR]/.test(a) || a === "--recursive");
  return false;
}

// ---- parser ----

export interface Simple {
  argv: string[];
  // Output redirect targets.
  out: string[];
  // Input redirect sources.
  in?: string[];
  // The targets in `out` opened with `>>`.
  append?: string[];
  // Reads a heredoc: for a shell or interpreter the body is code.
  heredoc?: boolean;
  // The bodies of the heredocs this command reads, in order and as written. The parser already
  // skips them as data; keeping them lets runTargets see code fed to a shell or interpreter.
  heredocBodies?: string[];
  // The heredoc body holds a variable or a command substitution, so it is not literal text.
  expands?: boolean;
  // Runs in a subshell: inside a command substitution, or as part of a pipeline or a background
  // job. A `cd` or an assignment there does not reach the commands that follow.
  subshell?: boolean;
}
export interface Parsed {
  cmds: Simple[];
  // Syntax that is not modelled: never allow by rule.
  opaque: boolean;
  // Parenthesised subshells: `cd` tracking is unreliable.
  grouped: boolean;
}

function matchParen(s: string, open: number): number {
  let depth = 0;
  for (let i = open; i < s.length; i++) {
    if (s[i] === "\\") i++;
    else if (s[i] === "(") depth++;
    else if (s[i] === ")" && --depth === 0) return i;
  }
  return -1;
}

export function parse(command: string, depth = 0): Parsed {
  const result: Parsed = { cmds: [], opaque: depth > 4, grouped: false };
  if (result.opaque) return result;
  const s = command;
  let cur: Simple = { argv: [], out: [] };
  let word = "";
  let hasWord = false;
  let redirect: "" | "out" | "append" | "in" = "";
  // Heredocs opened on the current line. A body is data and is skipped, except that the shell
  // runs the substitutions in a body whose delimiter is not quoted.
  const heredocs: { delimiter: string; quoted: boolean; owner: Simple }[] = [];

  const pushWord = () => {
    if (hasWord) {
      const expanded = word.replace(/\$\{HOME\}|\$HOME\b/g, HOME);
      if (redirect === "out" || redirect === "append") cur.out.push(expanded);
      else if (redirect === "") cur.argv.push(expanded);
      else (cur.in ??= []).push(expanded);
      if (redirect === "append") (cur.append ??= []).push(expanded);
      redirect = "";
    }
    word = "";
    hasWord = false;
  };
  const pushCmd = () => {
    pushWord();
    redirect = "";
    if (cur.argv.length || cur.out.length) result.cmds.push(cur);
    cur = { argv: [], out: [] };
  };
  // Parses a substitution body as extra commands.
  const absorb = (inner: string) => {
    const sub = parse(inner, depth + 1);
    for (const c of sub.cmds) c.subshell = true;
    result.cmds.push(...sub.cmds);
    result.opaque ||= sub.opaque;
  };
  // The same, and leaves a placeholder in the word.
  const nested = (inner: string) => {
    absorb(inner);
    word += "$()";
    hasWord = true;
  };
  // The substitutions the shell runs inside an unquoted heredoc body.
  const heredocBody = (body: string, owner: Simple) => {
    if (/[$`]/.test(body)) owner.expands = true;
    for (let j = 0; j < body.length; j++) {
      if (body[j] === "\\") j++;
      else if (body[j] === "$" && body[j + 1] === "(") {
        const end = matchParen(body, j + 1);
        if (end < 0) return void (result.opaque = true);
        absorb(body.slice(j + 2, end));
        j = end;
      } else if (body[j] === "`") {
        const end = body.indexOf("`", j + 1);
        if (end < 0) return void (result.opaque = true);
        absorb(body.slice(j + 1, end));
        j = end;
      }
    }
  };

  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    const next = s[i + 1];
    if (c === "\\") {
      if (next !== "\n") {
        word += next ?? "";
        hasWord = true;
      }
      i++;
    } else if (c === "'") {
      const end = s.indexOf("'", i + 1);
      if (end < 0) return { ...result, opaque: true };
      word += s.slice(i + 1, end);
      hasWord = true;
      i = end;
    } else if (c === '"') {
      hasWord = true;
      let j = i + 1;
      for (; j < s.length && s[j] !== '"'; j++) {
        if (s[j] === "\\" && j + 1 < s.length) word += s[++j];
        else if (s[j] === "$" && s[j + 1] === "(") {
          const end = matchParen(s, j + 1);
          if (end < 0) return { ...result, opaque: true };
          nested(s.slice(j + 2, end));
          j = end;
        } else if (s[j] === "`") {
          const end = s.indexOf("`", j + 1);
          if (end < 0) return { ...result, opaque: true };
          nested(s.slice(j + 1, end));
          j = end;
        } else word += s[j];
      }
      if (j >= s.length) return { ...result, opaque: true };
      i = j;
    } else if (c === "`") {
      const end = s.indexOf("`", i + 1);
      if (end < 0) return { ...result, opaque: true };
      nested(s.slice(i + 1, end));
      i = end;
    } else if ((c === "$" || c === "<" || c === ">") && next === "(") {
      const end = matchParen(s, i + 1);
      if (end < 0) return { ...result, opaque: true };
      nested(s.slice(i + 2, end));
      i = end;
    } else if (c === "<") {
      pushWord();
      const heredoc = next === "<" && s[i + 2] !== "<" ? /^<<-?\s*(['"]?)([\w.-]+)\1/.exec(s.slice(i)) : null;
      if (heredoc) {
        heredocs.push({ delimiter: heredoc[2], quoted: heredoc[1] !== "", owner: cur });
        cur.heredoc = true;
        i += heredoc[0].length - 1;
      } else {
        // An input file or here-string is data: skip the word that follows.
        if (next === "<") i += s[i + 2] === "<" ? 2 : 1;
        redirect = "in";
      }
    } else if (c === ">" || (c === "&" && next === ">")) {
      // A number right before `>` is a file descriptor, not an argument.
      if (hasWord && /^\d+$/.test(word)) {
        word = "";
        hasWord = false;
      }
      pushWord();
      if (c === "&") i++;
      const append = s[i + 1] === ">";
      if (append || s[i + 1] === "|") i++;
      if (s[i + 1] === "&") {
        // fd duplication such as 2>&1 has no file target.
        i++;
        while (/[\d-]/.test(s[i + 1] ?? "")) i++;
      } else redirect = append ? "append" : "out";
    } else if (c === " " || c === "\t") {
      pushWord();
    } else if (c === "\n" || c === ";") {
      pushCmd();
      while (c === "\n" && heredocs.length) {
        const doc = heredocs.shift()!;
        const end = new RegExp(`^\\s*${doc.delimiter.replace(/[.\-]/g, "\\$&")}\\s*$`, "m").exec(s.slice(i + 1));
        const body = end ? s.slice(i + 1, i + 1 + end.index) : s.slice(i + 1);
        if (!doc.quoted) heredocBody(body, doc.owner);
        (doc.owner.heredocBodies ??= []).push(body);
        i = end ? i + end.index + end[0].length : s.length;
      }
    } else if (c === "&" || c === "|") {
      // `|`, `|&` and a single `&` fork: both sides of a pipe, and the background job.
      const forks = next !== c;
      if (forks) cur.subshell = true;
      if (next === c || (c === "|" && next === "&")) i++;
      pushCmd();
      if (forks && c === "|") cur.subshell = true;
    } else if (c === "(" || c === ")") {
      result.grouped = true;
      pushCmd();
    } else if (c === "#" && !hasWord) {
      const end = s.indexOf("\n", i);
      i = end < 0 ? s.length : end - 1;
    } else {
      word += c;
      hasWord = true;
    }
  }
  pushCmd();
  return result;
}

// ---- command tables ----

export const READ_ONLY = new Set(
  `ls cat bat head tail less more wc rg grep egrep fgrep fd tree stat file du df pwd echo printf
   which whereis type whoami id groups date cal uname hostname uptime printenv ps pgrep free nproc
   lscpu lsblk lsusb lspci lsmod findmnt readlink realpath basename dirname sort uniq cut tr jq yq
   column diff cmp comm nl tac rev fold paste join seq true false test [ sleep export unset wait
   sha256sum sha1sum md5sum b3sum xxd hexdump od strings nm ldd man tldr tokei cloc fastfetch
   journalctl dmesg ss dig nslookup host traceroute tracert whois ping getent locale zcat xzcat bzcat zstdcat
   set shopt local declare typeset readonly break continue return exit shift :`.split(/\s+/),
);

// Build, test, lint and format tools that work on the project.
const DEV_TOOLS = new Set(
  `make just ninja cmake ctest meson pytest tox nox ruff mypy pyright black isort flake8 eslint
   prettier tsc vitest jest mocha rustfmt rustc gcc g++ cc c++ clang clang++ shellcheck shfmt
   stylua luacheck biome golangci-lint hadolint yamllint markdownlint ccache`.split(/\s+/),
);

// Per-tool subcommands. Anything not listed goes to the model.
const SUBCOMMANDS: Record<string, { allow: string; ask?: Record<string, string> }> = {
  git: {
    allow: `status diff log show rev-parse rev-list ls-files ls-tree ls-remote blame describe shortlog
      grep cat-file merge-base name-rev show-ref symbolic-ref count-objects check-ignore
      add commit switch fetch pull merge rebase cherry-pick revert mv init clone apply am bisect
      submodule worktree sparse-checkout notes range-diff format-patch archive bundle whatchanged version help`,
    ask: {
      push: "git push is visible to others",
      "filter-branch": "rewrites git history",
      "filter-repo": "rewrites git history",
    },
  },
  gh: { allow: `search status version help`, ask: {} },
  cargo: {
    allow: `build check test clippy fmt run bench doc tree metadata nextest clean add remove update
      fetch vendor expand audit deny outdated machete info search pkgid locate-project version help`,
    ask: { publish: "cargo publish is visible to others", yank: "cargo yank is visible to others", login: "stores a registry token" },
  },
  go: { allow: `build test vet run fmt mod generate list get env version doc tool`, ask: {} },
  uv: { allow: `sync lock add remove pip venv tree export version help`, ask: { publish: "uv publish is visible to others" } },
  pip: { allow: `install list show freeze check download wheel uninstall help`, ask: {} },
  pip3: { allow: `install list show freeze check download wheel uninstall help`, ask: {} },
  docker: {
    allow: `build ps images logs inspect version info history top stats diff port`,
    ask: { push: "docker push is visible to others", login: "stores registry credentials" },
  },
  systemctl: {
    allow: `status show cat list-units list-unit-files list-timers list-sockets list-dependencies
      is-active is-enabled is-failed get-default help show-environment list-jobs`,
    ask: {},
  },
  loginctl: { allow: `list-sessions list-users list-seats show-session show-user session-status user-status`, ask: {} },
  niri: { allow: `validate`, ask: {} },
};
for (const pm of ["npm", "pnpm", "yarn", "bun"]) {
  SUBCOMMANDS[pm] = {
    allow: `test t run run-script ci install i ls list outdated audit why explain build start lint add
      remove rm uninstall update up dedupe prune view info pack link rebuild version help`,
    ask: { publish: `${pm} publish is visible to others`, login: "stores a registry token", adduser: "stores a registry token", unpublish: "visible to others", deprecate: "visible to others" },
  };
}

const GH_READ = new Set(["view", "list", "diff", "checks", "status", "watch", "download"]);
// docker <group> <action>: the actions of each group that only read.
const DOCKER_GROUPS: Record<string, string> = {
  image: "ls list inspect history",
  container: "ls list inspect logs top stats port diff",
  network: "ls list inspect",
  volume: "ls list inspect",
  context: "ls list inspect show",
  system: "df info",
};
// Tools where every subcommand not in `allow` changes the system: ask instead of classify.
const ASK_BY_DEFAULT: Record<string, string> = {
  systemctl: "changes a system service",
  loginctl: "changes a login session",
};

// Commands that always need a prompt.
const ALWAYS_ASK: Record<string, string> = {
  sudo: "runs as root", doas: "runs as root", su: "switches user", pkexec: "runs as root",
  ssh: "runs on a remote host", scp: "copies to or from a remote host", sftp: "connects to a remote host",
  ftp: "connects to a remote host", telnet: "opens a raw network connection", nc: "opens a raw network connection",
  ncat: "opens a raw network connection", netcat: "opens a raw network connection", socat: "opens a raw network connection",
  shutdown: "powers off the machine", reboot: "reboots the machine", poweroff: "powers off the machine", halt: "halts the machine",
  stow: "changes symlinks in $HOME", mount: "changes mounts", umount: "changes mounts", swapon: "changes swap", swapoff: "changes swap",
  modprobe: "loads a kernel module", rmmod: "unloads a kernel module", insmod: "loads a kernel module",
  kill: "kills a process", pkill: "kills processes", killall: "kills processes",
  iptables: "changes the firewall", nft: "changes the firewall", ufw: "changes the firewall", "firewall-cmd": "changes the firewall",
  useradd: "changes user accounts", usermod: "changes user accounts", userdel: "changes user accounts", passwd: "changes a password", visudo: "changes sudo rules",
  apt: "changes system packages", "apt-get": "changes system packages", dnf: "changes system packages", yum: "changes system packages",
  zypper: "changes system packages", snap: "changes system packages", flatpak: "changes system packages", brew: "changes system packages",
  twine: "uploads a package", fdisk: "edits disk partitions", parted: "edits disk partitions", sgdisk: "edits disk partitions",
};

// ---- ssh to a host you trust ----
//
// `ssh <trusted host> '<command>'` is checked as that command, run on that host. What the rules
// would allow here (reading: ls, find, df, cat, docker ps, systemctl status) runs. The same with
// sudo in front goes to the judges on its merits. Anything else, a change, a script, a shell, an
// interactive login, an untrusted host or an unusual ssh option, keeps the usual ask.
const REMOTE_HOME = "/home/~remote";
// Options that only tune the connection. Forwarding, proxies, local commands, control masters,
// agent and X11 forwarding, log files and other config files are missing on purpose.
const SSH_BARE_FLAGS = /^-[46CTtqvnxk]+$/;
const SSH_VALUE_FLAGS = new Set(["i", "p", "l", "o", "c", "m"]);
const SSH_SAFE_OPTIONS = new Set([
  "batchmode", "connecttimeout", "connectionattempts", "stricthostkeychecking", "userknownhostsfile", "identityfile",
  "identitiesonly", "port", "user", "serveraliveinterval", "serveralivecountmax", "loglevel", "requesttty", "compression",
  "preferredauthentications", "passwordauthentication", "pubkeyauthentication", "numberofpasswordprompts", "tcpkeepalive",
  "hostkeyalias", "checkhostip", "visualhostkey", "addressfamily", "ciphers", "macs", "kexalgorithms", "hostkeyalgorithms",
]);
// Project tools run code that the remote host's files decide, which nothing here has read.
const REMOTE_RUNNER = /(?:^|[\s;&|(])(npm|pnpm|yarn|bun|npx|node|deno|make|just|ninja|cmake|pytest|tox|nox|cargo|go|uv|pip3?|python3?|ruby|perl|php|dotnet|mvn|gradle|gradlew|poetry|rake|bundle|ansible\S*)(?=[\s;&|)]|$)/;
// The destination and remote command of an ssh call to a trusted host using only plain options,
// or undefined for any other ssh call.
function trustedTarget(args: string[], scope: Scope): { dest: string; rest: string[] } | undefined {
  let i = 0;
  for (; i < args.length; i++) {
    const a = args[i];
    if (a === "--") { i++; break; }
    if (!a.startsWith("-")) break;
    if (SSH_BARE_FLAGS.test(a)) continue;
    const flag = a[1];
    if (!SSH_VALUE_FLAGS.has(flag)) return undefined;
    const value = a.length > 2 ? a.slice(2) : args[++i];
    if (value === undefined) return undefined;
    if (flag === "o") {
      const key = value.split(/[=\s]/)[0].toLowerCase();
      if (!SSH_SAFE_OPTIONS.has(key)) return undefined;
    }
  }
  const dest = args[i];
  const rest = args.slice(i + 1);
  if (!dest || !rest.length || /[$`*?{}[\]]/.test(dest)) return undefined;
  const host = dest.replace(/^[^@]*@/, "").toLowerCase();
  const hosts = scope.trustedHosts ?? [];
  if (!hosts.includes(dest.toLowerCase()) && !hosts.includes(host)) return undefined;
  return { dest, rest };
}

function trustedSsh(args: string[], scope: Scope, depth: number): Verdict | undefined {
  const target = trustedTarget(args, scope);
  if (!target) return undefined;
  const { dest, rest } = target;
  // ssh joins its arguments with spaces and the remote shell parses the result.
  const remote = rest.join(" ");
  if (REMOTE_RUNNER.test(remote) || depth > 2) return undefined;
  const there: Scope = { ...scope, cwd: undefined, root: undefined, guarded: [], piDirs: [], allowed: [], rules: undefined, picked: undefined, files: new Map(), pending: new Map(), project: undefined, vars: undefined, loopVars: undefined, remote: true };
  const plain = evaluateParsed(parse(remote, depth + 1), there, depth + 1);
  if (plain.action === "allow") return { action: "allow", reason: `reads only, on trusted host ${dest}` };
  const asRoot = evaluateParsed(parse(remote, depth + 1), { ...there, remoteRoot: true }, depth + 1);
  if (asRoot.action === "allow") return classify(`ssh ${dest} reads as root on a trusted host`);
  return undefined;
}

// Commands that delete or overwrite the paths xargs feeds them from stdin.
const DESTRUCTIVE_XARGS = new Set(["rm", "rmdir", "unlink", "mv", "chmod", "chown", "chgrp", "tee", "dd", "shred", "truncate", "patch"]);

// Commands whose operands are written to. "last" means only the final operand is a destination.
const WRITERS: Record<string, "all" | "last"> = {
  cp: "last", ln: "last", install: "last", rsync: "last",
  mv: "all", tee: "all", truncate: "all", touch: "all", mkdir: "all", rmdir: "all", chmod: "all",
  chown: "all", chgrp: "all", setfacl: "all", shred: "all", unlink: "all", patch: "all",
};
// The first operand of these is a mode, owner or script, not a path.
const FIRST_OPERAND_NOT_PATH = new Set(["chmod", "chown", "chgrp", "sed"]);
// Writers whose destination gets the content of their source, and the other writers that
// change a file's content.
const COPIERS = new Set(["cp", "mv", "ln", "install", "rsync"]);
const CONTENT_WRITERS = new Set(["tee", "truncate", "shred", "patch"]);

// Variables that load other code into the program they are set for. NODE_OPTIONS only with
// an option that loads a file; it often just sets a heap size.
const LOADS_CODE = /^(LD_PRELOAD|LD_AUDIT|DYLD_INSERT_LIBRARIES|BASH_ENV|ENV|NODE_OPTIONS|PERL5OPT|RUBYOPT)=(.*)$/s;
const NODE_LOADS = /(^|\s)(-r|--require|--import|--loader|--experimental-loader)(=|\s|$)/;
// Variables that change what a command runs or where it writes when set on the command line or
// exported: git's environment config and program hooks, make's flags, an interpreter's import or
// startup path, a compiler wrapper, a package manager's registry. A plain setting such as
// NODE_ENV=test, CI=1 or DEBUG=x is not one of them.
const ENV_FLAGS = /^(MAKEFLAGS|MFLAGS|GOFLAGS|GIT_CONFIG_\w+|NPM_CONFIG_\w+|YARN_\w+)$/i;
const ENV_PATH = /^(GIT_DIR|GIT_WORK_TREE|GIT_CONFIG|GIT_EXEC_PATH|GIT_TEMPLATE_DIR|PYTHONSTARTUP|PYTHONPATH|PYTHONHOME|NODE_PATH|LD_LIBRARY_PATH)$/;
const ENV_PROGRAM = /^(PAGER|EDITOR|VISUAL|LESSOPEN|LESSCLOSE|MANPAGER|GIT_PAGER|GIT_EDITOR|GIT_SSH|GIT_SSH_COMMAND|GIT_EXTERNAL_DIFF|RUSTC|RUSTC_WRAPPER|CARGO_BUILD_RUSTC_WRAPPER|CC|CXX|MAKE|AR)$/;
// The reason an assignment changes what a command runs, if it does. `scope` is the working
// directory the assignment is made in, so a project-relative import path stays ordinary.
function envLoadsCode(word: string, scope: Scope): string | undefined {
  const m = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/s.exec(word);
  if (!m) return undefined;
  const name = m[1];
  const value = m[2].replace(/^(["'])([\s\S]*)\1$/, "$2");
  const loader = LOADS_CODE.exec(word);
  if (loader && (loader[1] !== "NODE_OPTIONS" || NODE_LOADS.test(loader[2]))) return `sets ${loader[1]}, which loads other code into the program`;
  if (ENV_FLAGS.test(name)) return `sets ${name}, which changes what the command runs`;
  if (ENV_PATH.test(name)) {
    if (!value) return undefined;
    // A path built at run time cannot be proven to stay under the project.
    if (/[$`]/.test(value)) return `sets ${name} to a path computed at run time`;
    const p = resolveWord(value, scope);
    const here = scope.cwd;
    if (!p || !here || !(within(p, here) || (!!scope.root && within(p, scope.root)))) return `sets ${name} to a path outside the working directory`;
    return undefined;
  }
  if (ENV_PROGRAM.test(name)) {
    // A bare program name comes from PATH; a path, an expansion or a pipe names a program of its
    // own, which the rules cannot see.
    if (!/[$`\\/|~]/.test(value)) return undefined;
    return `sets ${name} to a program the rules cannot see`;
  }
  return undefined;
}
const WRAPPERS = new Set(["env", "nice", "ionice", "timeout", "time", "command", "builtin", "nohup", "setsid", "stdbuf", "exec", "chrt", "taskset"]);
// Wrappers that run the same program with the same environment and PATH lookup.
const SAME_PROGRAM_WRAPPERS = new Set(["timeout", "time", "nice", "ionice", "nohup", "setsid", "stdbuf"]);
const KEYWORDS = new Set(["if", "then", "elif", "else", "do", "while", "until", "!", "{", "}"]);
const NOOP_KEYWORDS = new Set(["fi", "done", "esac", "for", "in"]);
const SHELLS = new Set(["bash", "sh", "zsh", "dash", "ksh"]);
const INTERPRETERS = new Set(["python", "python3", "node", "perl", "ruby", "php", "lua", "deno", "bun"]);
const PY_MODULES = new Set(["pytest", "unittest", "venv", "pip", "build", "ruff", "mypy", "black", "isort", "compileall", "json.tool"]);
// tool -> subcommand that runs the rest of the line as a command.
const RUNNERS: Record<string, string> = { uv: "run", poetry: "run", pipenv: "run", pdm: "run", hatch: "run", pnpm: "exec", bundle: "exec" };

const operands = (args: string[]) => args.filter((a) => !a.startsWith("-"));
// Drops a wrapper's leading options; `takesValue` matches the ones followed by a value.
function afterFlags(args: string[], takesValue: RegExp): string[] {
  let i = 0;
  while (i < args.length && args[i].startsWith("-")) i += takesValue.test(args[i]) ? 2 : 1;
  return args.slice(i);
}
const hasFlag = (args: string[], short: string, long?: string) =>
  args.some((a) => (long !== undefined && longOption(a, long)) || (/^-[a-zA-Z]+$/.test(a) && a.includes(short)));

// GNU long options accept any unambiguous prefix of the option they name: `sort --outp=` is
// `sort --output=`, and git accepts `--outp` too. A spelling that is a different option of the
// tool in its own right (`curl --head`, which is not `--header`) is not an abbreviation.
const LONG_MIN_ABBREVIATION = 5;
const LONG_IS_ANOTHER_OPTION = new Set(["--head", "--hea"]);
function longOption(a: string, name: string): boolean {
  if (a === name) return true;
  if (!name.startsWith("--") || !a.startsWith("--")) return false;
  const flag = a.includes("=") ? a.slice(0, a.indexOf("=")) : a;
  if (flag === name) return true;
  return flag.length >= LONG_MIN_ABBREVIATION && flag.length < name.length && name.startsWith(flag) && !LONG_IS_ANOTHER_OPTION.has(flag);
}

// The value of an option, attached (`--out=/x`, `--outp /x`, `-o/x`) or as the next word.
function optionArg(args: string[], ...names: string[]): string | undefined {
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    for (const name of names) {
      if (a === name) return args[i + 1];
      if (name.startsWith("--")) {
        if (a.startsWith(name + "=")) return a.slice(name.length + 1);
        if (longOption(a, name)) return a.includes("=") ? a.slice(a.indexOf("=") + 1) : args[i + 1];
      }
      if (/^-[A-Za-z]$/.test(name) && a.startsWith(name) && a.length > name.length) return a.slice(name.length);
    }
  }
  return undefined;
}

// Every value an option takes, in order. `sed -e a -e b` reads both scripts, not only the first.
function optionArgs(args: string[], ...names: string[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    let used = false;
    for (const name of names) {
      if (a === name) {
        if (args[i + 1] !== undefined) out.push(args[++i]);
        used = true;
        break;
      }
      if (name.startsWith("--") && longOption(a, name)) {
        if (a.includes("=")) out.push(a.slice(a.indexOf("=") + 1));
        else if (args[i + 1] !== undefined) out.push(args[++i]);
        used = true;
        break;
      }
      if (/^-[A-Za-z]$/.test(name) && a.startsWith(name) && a.length > name.length) {
        out.push(a.slice(name.length));
        used = true;
        break;
      }
    }
    if (used) continue;
  }
  return out;
}

// The words left after dropping the values of the given options, so an option value is not read
// as a path operand (`cp -t DIR a`: DIR is the destination, not a source).
function withoutOptionValues(args: string[], ...names: string[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    let used = false;
    for (const name of names) {
      if (a === name) {
        i++;
        used = true;
        break;
      }
      if (name.startsWith("--") && longOption(a, name)) {
        if (!a.includes("=")) i++;
        used = true;
        break;
      }
      if (/^-[A-Za-z]$/.test(name) && a.startsWith(name) && a.length > name.length) {
        used = true;
        break;
      }
    }
    if (!used) out.push(a);
  }
  return out;
}

// A file a command writes, with the same floors as every other write target.
function writePathVerdict(name: string, target: string, scope: Scope): Verdict | undefined {
  const p = resolveWord(target, scope);
  if (p && DEV_SINKS.test(p)) return undefined;
  if (isGuarded(p, scope)) return guardAsk(`${name} changes the auto-mode guard's own files`);
  if (isPiFile(p, scope)) return piAsk(`${name} changes Pi's own files: ${target}`);
  if (isGitHook(p)) return gitHookWrite(target);
  if (!isLocal(p, scope)) return outside(`${name} writes outside the working directory: ${target}`, p);
  return undefined;
}

// The other end of a link. A link to a home, a credential store, Pi's files or the guard lets a
// later project-looking path reach it, so it asks now, while the target is still visible.
function linkVerdict(name: string, target: string, scope: Scope): Verdict | undefined {
  let verdict: Verdict | undefined;
  const alternatives = braceExpand(expandHome(target));
  for (const alternative of alternatives) {
    const p = resolveWord(alternative, scope);
    if (!p) {
      verdict = worst(verdict ?? ALLOW, classify(`${name} links to a path the rules cannot resolve: ${target}`));
      continue;
    }
    if (DEV_SINKS.test(p)) continue;
    if (isGuarded(p, scope)) return guardAsk(`${name} links to the auto-mode guard's own files: ${target}`);
    if (isPiFile(p, scope)) return guardAsk(`${name} links to Pi's own files: ${target}`);
    if (isSecretPath(alternative) || isSecretPath(p) || (psDirExists(p) && isCredentialDirectory(p)) || (isRootLike(p) && !inTmp(p))) {
      return criticalAsk(`${name} links to a credential location or its parent: ${target}`);
    }
    if (!isLocal(p, scope)) verdict = worst(verdict ?? ALLOW, outside(`${name} links to a target outside the working directory: ${target}`, p));
  }
  return verdict;
}

// Formatters that rewrite their operands in place, and the flags that make them do it.
const FORMATTERS: Record<string, (args: string[]) => boolean> = {
  prettier: (args) => args.some((a) => a === "--write" || a === "-w"),
  black: (args) => !args.some((a) => /^(--check|--diff|--code)$/.test(a)),
  isort: (args) => !args.some((a) => /^--(check|check-only|diff|show-files|show-config)/.test(a)),
  shfmt: (args) => args.some((a) => a === "-w" || a === "--write"),
  rustfmt: (args) => !args.some((a) => /^--(check|emit|print)/.test(a)),
  eslint: (args) => args.some((a) => a === "--fix") && !args.includes("--fix-dry-run"),
  ruff: (args) => args.some((a) => a === "--fix") || (operands(args)[0] === "format" && !args.some((a) => a === "--check" || a === "--diff")),
  biome: (args) => args.some((a) => a === "--write" || a === "--apply"),
  stylua: (args) => !args.some((a) => a === "--check"),
  gofmt: (args) => args.some((a) => a === "-w"),
};
const FORMATTER_VALUE_FLAGS = new Set([
  "--config", "--config-path", "--config-precedence", "--parser", "--print-width", "--tab-width", "--trailing-comma",
  "--ignore-path", "--plugin", "--stdin-filepath", "--cache-location", "--loglevel", "--range-start", "--range-end",
  "--line-length", "--target-version", "--include", "--exclude", "--ext", "--rulesdir", "--resolve-plugins-relative-to",
  "--output-file", "--format", "--stdin-filename", "--log-level", "-o", "--output", "--cache", "--cache-dir",
]);

// The operands of a formatter: the words it rewrites, not the values of its own options.
function formatterOperands(args: string[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--") { out.push(...args.slice(i + 1)); break; }
    if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      const flag = eq > 0 ? a.slice(0, eq) : a;
      if (eq < 0 && FORMATTER_VALUE_FLAGS.has(flag)) i++;
      continue;
    }
    if (a.startsWith("-") && a !== "-") {
      if (FORMATTER_VALUE_FLAGS.has(a)) i++;
      continue;
    }
    out.push(a);
  }
  return out;
}

function formatterVerdict(name: string, args: string[], scope: Scope): Verdict | undefined {
  const writes = FORMATTERS[name]?.(args);
  if (!writes) return undefined;
  for (const target of formatterOperands(args)) {
    const p = resolveWord(target, scope);
    if (!p || DEV_SINKS.test(p)) continue;
    if (isGuarded(p, scope)) return guardAsk(`${name} changes the auto-mode guard's own files`);
    if (isPiFile(p, scope)) return piAsk(`${name} changes Pi's own files: ${target}`);
    if (isGitHook(p)) return gitHookWrite(target);
    // The formatter rewrites an existing file. A path that does not exist is not rewritten, so it
    // cannot widen the guard just by being named.
    if (!isLocal(p, scope) && fs.existsSync(p)) return outside(`${name} writes outside the working directory: ${target}`, p);
  }
  return undefined;
}

// Tools that load a config or script file named by a flag. A path outside the project is a config
// the guard cannot see, so it stays with the model.
function configOption(name: string, args: string[]): string | undefined {
  const pick = (...flags: string[]) => {
    for (const f of flags) { const v = optionArg(args, f); if (v !== undefined) return v; }
    return undefined;
  };
  if (name === "make") return pick("-f", "--file", "--makefile");
  if (name === "cmake") return pick("-P", "--script");
  if (name === "eslint") return pick("--config", "-c") ?? pick("--rulesdir", "--resolve-plugins-relative-to");
  if (name === "vitest" || name === "jest" || name === "mocha") return pick("--config", "-c");
  if (name === "pytest") {
    const config = pick("-c");
    if (config !== undefined) return config;
    // -p names a plugin module; only a path-like value can name a file outside the project.
    const plugin = pick("-p");
    return plugin && /[\\/]/.test(plugin) ? plugin : undefined;
  }
  if (name === "tox") return pick("-c", "--conf");
  return undefined;
}

function configVerdict(name: string, args: string[], scope: Scope): Verdict | undefined {
  const target = configOption(name, args);
  if (target === undefined) return undefined;
  const p = resolveWord(target, scope);
  if (!p || !isLocal(p, scope)) return outwardClassify(`runs config from outside the working directory: ${target}`);
  return undefined;
}


function writeTargets(cmd: string, args: string[], scope: Scope, literalInput = false): Verdict {
  // `cp -t DIR a b` and `install --target-directory DIR a b` name the destination itself; every
  // remaining word is a source and its basename lands inside DIR.
  const targetDir = COPIERS.has(cmd) ? optionArg(args, "-t", "--target-directory") : undefined;
  const given = operands(targetDir === undefined ? args : withoutOptionValues(args, "-t", "--target-directory"));
  const paths = FIRST_OPERAND_NOT_PATH.has(cmd) ? given.slice(1) : given;
  const sources = targetDir !== undefined ? paths : paths.slice(0, -1);
  const destWord = targetDir !== undefined ? targetDir : paths.at(-1);
  const dest = destWord !== undefined && (targetDir !== undefined || paths.length > 1) ? resolveWord(destWord, scope) : undefined;
  const intoDir = targetDir !== undefined || (COPIERS.has(cmd) && paths.length > 1 && (sources.length > 1 || paths.at(-1)!.endsWith("/") || (!!dest && fs.statSync(dest, { throwIfNoEntry: false })?.isDirectory())));
  // For a link, the first operand is the other end, not content that is read. A link to a home,
  // a credential store, Pi's files or the guard must ask while that target is still visible.
  // `cp -s`/`cp -l` make a link as well, so they take the same check as ln.
  let link: Verdict | undefined;
  if (cmd === "ln" || (cmd === "cp" && (hasFlag(args, "s", "--symbolic-link") || hasFlag(args, "l", "--link")))) {
    for (const source of sources) {
      const v = linkVerdict(cmd, source, scope);
      if (v && (v.locked || v.critical)) return v;
      if (v) link = link ? worst(link, v) : v;
    }
  }
  const targets = intoDir ? [destWord!] : WRITERS[cmd] === "last" ? paths.slice(-1) : paths;
  let hook: Verdict | undefined;
  for (const t of targets) {
    // Copied into a directory, the files land inside it: `cp a.rs /tmp` writes /tmp/a.rs. The
    // directory itself is checked too, since `cp -t /etc a` writes inside /etc.
    const landing = intoDir && dest ? sources.map((s) => path.join(dest, path.basename(s))) : [];
    const written = intoDir && dest ? [dest, ...landing] : [resolveWord(t, scope)];
    for (const p of written) {
      if (p && DEV_SINKS.test(p)) continue;
      if (isGuarded(p, scope)) return guardAsk(`${cmd} changes the auto-mode guard's own files`);
      if (isPiFile(p, scope)) return piAsk(`${cmd} changes Pi's own files: ${t}`);
      if (isGitHook(p)) hook ??= gitHookWrite(t);
      if (!isLocal(p, scope)) return cmd === "mkdir" ? { ...outside(`mkdir creates a folder outside the working directory: ${t}`, p), class: "opaque" } : outside(`${cmd} writes outside the working directory: ${t}`, p);
    }
  }
  if (COPIERS.has(cmd) && paths.length > 1) {
    for (const source of sources) {
      const from = resolveWord(source, scope);
      const kept = from && originOf(from, scope);
      note(dest && intoDir ? path.join(dest, path.basename(source)) : dest, kept === "authored" || kept === "fetched" ? kept : "other", scope);
      if (cmd === "mv") note(from, "other", scope);
    }
  } else if (CONTENT_WRITERS.has(cmd)) {
    const literal = cmd === "tee" && literalInput;
    // Appending literal text leaves the file's origin as it was.
    if (!(literal && hasFlag(args, "a", "--append"))) for (const t of targets) note(resolveWord(t, scope), literal ? "authored" : "other", scope);
  }
  return worst(hook ?? ALLOW, link ?? ALLOW);
}

function rm(args: string[], scope: Scope): Verdict {
  const recursive = hasFlag(args, "r", "--recursive") || hasFlag(args, "R");
  let verdict = ALLOW;
  for (const t of operands(args)) {
    const p = resolveWord(t, scope);
    const bare = BARE_GLOB.test(path.basename(t));
    // A path held in a variable can be relative to a directory the rules followed; only a path
    // written out is certain enough for the hard deny, and anything else still asks.
    const held = /[$`]/.test(t);
    if (recursive && p && !held && (isRootLike(p) || (bare && isRootLike(path.dirname(p))))) {
      return deny(`rm -r of ${t} would wipe a home or system directory`);
    }
    if (isGuarded(p, scope)) verdict = worst(verdict, guardAsk("rm deletes the auto-mode guard's own files"));
    else if (isPiFile(p, scope)) verdict = worst(verdict, piAsk(`rm deletes Pi's own files: ${t}`));
    else if (!isLocal(p, scope)) verdict = worst(verdict, outsideDelete(`rm deletes outside the working directory: ${t}`, p));
    else if (recursive && scope.root && (p === scope.root || (bare && path.dirname(p!) === scope.root) || /(^|[\\/])\.git([\\/]|$)/i.test(p!))) {
      verdict = worst(verdict, ask(`rm -r of ${t} deletes the whole project or its git data`));
    }
  }
  return verdict;
}

// Git config keys that run a command, load a file, or redirect where a later command goes. Setting
// one is persistence even when the config file itself is inside the checkout.
function gitConfigRuns(key: string, value: string | undefined): boolean {
  const k = key.toLowerCase();
  if (/^core\.(hookspath|sshcommand|fsmonitor|pager|editor|gitproxy|askpass|attributesfile)$/.test(k)) return true;
  if (/^diff\.external$/.test(k) || /^diff\..*\.textconv$/.test(k)) return true;
  if (/^filter\./.test(k)) return true;
  if (/^alias\./.test(k)) return /^!/.test(value ?? "");
  if (/^credential\./.test(k) || /^http\.proxy$/.test(k) || /^sequence\.editor$/.test(k) || /^gpg\.program$/.test(k)) return true;
  if (/^url\..*\.(push)?insteadof$/.test(k) || /^include\.path$/.test(k) || /^includeif\..*\.path$/.test(k)) return true;
  if (/^merge\..*\.driver$/.test(k) || /^diff\..*\.command$/.test(k) || /^remote\..*\.(url|pushurl|uploadpack|receivepack)$/.test(k) || /^gpg\..*\.program$/.test(k)) return true;
  return false;
}

// The first operand after `git worktree add`, skipping its own option values. That operand is the
// path of the new checkout.
function worktreeAddTarget(rest: string[]): string | undefined {
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (a === "-b" || a === "-B" || a === "--reason" || a === "--orphan") { i++; continue; }
    if (a.startsWith("-")) continue;
    return a;
  }
  return undefined;
}

function gitCloneTarget(rest: string[]): string | undefined {
  const valueFlags = new Set(["-b", "--branch", "--depth", "-o", "--origin", "--reference", "--separate-git-dir", "--template", "--jobs", "-c", "--config", "--upload-pack", "--filter"]);
  const words: string[] = [];
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (valueFlags.has(a)) { i++; continue; }
    if (a.startsWith("-")) continue;
    words.push(a);
  }
  return words[1];
}

function git(args: string[], scope: Scope): Verdict {
  // Skip global options to find the subcommand. -c and --config-env can name a command git runs.
  let i = 0;
  while (i < args.length && args[i].startsWith("-")) {
    if (args[i] === "-C") {
      if (!isLocal(resolveWord(args[i + 1] ?? "", scope), scope)) return classify("git on a repository outside the working directory");
      i += 2;
    } else if (args[i] === "-c" || args[i] === "--config-env" || args[i].startsWith("--config-env=")) {
      const fromEnv = args[i].startsWith("--config-env");
      const raw = args[i] === "-c" || !args[i].includes("=") ? args[i + 1] : args[i].slice(args[i].indexOf("=") + 1);
      if (raw) {
        const eq = raw.indexOf("=");
        const key = eq >= 0 ? raw.slice(0, eq) : raw;
        const value = eq >= 0 ? raw.slice(eq + 1) : (fromEnv ? "!" : "");
        if (gitConfigRuns(key, value)) return outwardClassify(`git -c ${key} runs a command git cannot show`);
      }
      i += args[i] === "-c" || !args[i].includes("=") ? 2 : 1;
    } else i++;
  }
  const sub = args[i];
  const rest = args.slice(i + 1);
  const has = (...flags: string[]) => rest.some((a) => flags.some((f) => a === f || longOption(a, f)));
  // A long flag, or its letter alone or in a cluster such as `-SW`.
  const flag = (long: string, letter: string) => has(long) || rest.some((a) => new RegExp(`^-[a-zA-Z]*${letter}[a-zA-Z]*$`).test(a));
  if (!sub) return ALLOW;
  if (sub === "reset" && has("--hard")) return ask("git reset --hard discards local changes");
  if (sub === "clean" && rest.some((a) => /^-[a-zA-Z]*f/.test(a) || a === "--force")) return ask("git clean -f deletes untracked files");
  if (sub === "checkout" && (has("--", ".") || has("-f", "--force"))) return ask("git checkout discards local changes");
  // Only --staged alone keeps the working tree; --worktree with it still discards changes.
  if (sub === "restore" && (!flag("--staged", "S") || flag("--worktree", "W"))) return ask("git restore discards local changes");
  // Without --force git refuses to remove a worktree or submodule that has local changes.
  if (sub === "worktree" && operands(rest)[0] === "remove") {
    // The worktree is deleted with its files, so a target outside the checkout (a sibling of the
    // project is the usual `../x` and stays allowed) asks like any other outside delete.
    const target = operands(rest)[1];
    if (target !== undefined) {
      const p = resolveWord(target, scope);
      const sibling = !!p && !!scope.root && path.dirname(scope.root) === path.dirname(p);
      if (!p || (!isLocal(p, scope) && !sibling)) return outside(`git worktree remove deletes a checkout outside the working directory: ${target}`, p);
    }
    if (flag("--force", "f")) return ask("git worktree remove --force deletes the worktree with its uncommitted changes");
  }
  if (sub === "submodule" && operands(rest)[0] === "deinit" && flag("--force", "f")) return ask("git submodule deinit --force deletes submodule working trees with their local changes");
  // These run a shell command or a program the guard cannot see, and repeat it.
  if (sub === "submodule" && operands(rest)[0] === "foreach") return outwardClassify("git submodule foreach runs a shell command in every submodule");
  if (sub === "rebase" && rest.some((a) => a === "--exec" || /^--exec=/.test(a) || /^-x/.test(a))) return outwardClassify("git rebase --exec runs a shell command after each commit");
  if (sub === "bisect" && operands(rest)[0] === "run") return outwardClassify("git bisect run executes an arbitrary program repeatedly");
  if (sub === "branch") return has("-D") || (has("-d", "--delete") && has("-f", "--force")) ? ask("git branch -D deletes a branch") : ALLOW;
  if (sub === "stash") return has("drop", "clear") ? ask("git stash drop deletes stashed changes") : ALLOW;
  if (sub === "tag") return has("-d", "--delete") ? ask("git tag -d deletes a tag") : ALLOW;
  if (sub === "reset" || sub === "clean" || sub === "checkout" || sub === "restore") return ALLOW;
  // A checkout outside the project is a write. A sibling of the project is the usual `../x`
  // worktree next to the checkout and stays allowed, as it was before.
  if (sub === "worktree" && operands(rest)[0] === "add") {
    const target = worktreeAddTarget(rest.slice(1));
    if (target === undefined) return classify("git worktree add without a readable target");
    const p = resolveWord(target, scope);
    if (!p) return classify(`git worktree add to a path the rules cannot resolve: ${target}`);
    const sibling = !!scope.root && path.dirname(scope.root) === path.dirname(p);
    if (!isLocal(p, scope) && !sibling) return outside(`git worktree add writes a checkout outside the working directory: ${target}`, p);
    return ALLOW;
  }
  if (sub === "clone") {
    const target = gitCloneTarget(rest);
    if (target !== undefined) {
      const p = resolveWord(target, scope);
      if (!p || !isLocal(p, scope)) return outside(`git clone writes a checkout outside the working directory: ${target}`, p);
    }
    return ALLOW;
  }
  if (sub === "format-patch") {
    const out = optionArg(rest, "-o", "--output-directory");
    if (out !== undefined) { const v = writePathVerdict("git format-patch", out, scope); if (v) return v; }
  }
  if (sub === "archive") {
    const out = optionArg(rest, "-o", "--output");
    if (out !== undefined) { const v = writePathVerdict("git archive", out, scope); if (v) return v; }
  }
  if (sub === "bundle" && operands(rest)[0] === "create") {
    const file = operands(rest)[1];
    if (file !== undefined) { const v = writePathVerdict("git bundle create", file, scope); if (v) return v; }
  }
  if (sub === "apply") {
    if (has("--unsafe-paths")) return ask("git apply --unsafe-paths may write outside the checkout");
    const dir = optionArg(rest, "--directory");
    if (dir !== undefined) {
      const p = resolveWord(dir, scope);
      if (!p || !isLocal(p, scope)) return outside(`git apply writes under a directory outside the working directory: ${dir}`, p);
    }
  }
  // A mailbox can add lines to a project script; what it changes is not visible to the rules.
  if (sub === "am") return outwardClassify("git am applies patches the rules cannot read");
  // log/diff/show write their whole output to --output, outside the project when it names one.
  if (sub === "log" || sub === "diff" || sub === "show") {
    const out = optionArg(rest, "--output");
    if (out !== undefined) { const v = writePathVerdict(`git ${sub}`, out, scope); if (v) return v; }
  }
  if (sub === "config") {
    // Hooks and commands git runs later are persistence: they stay with the model even though
    // the config file is inside the repository.
    const words = withoutOptionValues(rest, "-f", "--file").filter((a) => !a.startsWith("-"));
    const [key, value] = words;
    const changes = rest.some((a) => /^(--unset|--unset-all|--add|--replace-all|--rename-section|--remove-section|--edit|-e)$/.test(a));
    // --file/-f writes the config to a named file, which may be outside the project.
    const file = optionArg(rest, "-f", "--file");
    const setting = changes || value !== undefined;
    if (file !== undefined && setting) {
      const v = writePathVerdict("git config", file, scope);
      if (v) return v;
    }
    if (key && setting && gitConfigRuns(key, value)) {
      return outwardClassify(`git config ${key} changes a command git runs later`);
    }
    if (has("--global", "--system")) {
      // Reading a key (`git config --global user.name`) changes nothing; setting one names a value.
      return setting ? ask("changes git config outside the repository") : ALLOW;
    }
    return ALLOW;
  }
  if (sub === "remote") return has("add", "set-url", "remove", "rm", "rename") ? ask("changes where git pushes and fetches") : ALLOW;
  if (sub === "reflog") return has("expire", "delete") ? ask("deletes git recovery data") : ALLOW;
  if (sub === "gc") return has("--prune=now", "--aggressive") ? ask("deletes git recovery data") : ALLOW;
  return subcommand("git", [sub, ...rest]);
}

function gh(args: string[]): Verdict {
  const [group, action] = operands(args);
  if (!group) return ALLOW;
  if (group === "api") {
    // -X POST, -XPOST, --method POST and --method=POST all name the HTTP method.
    let method: string | undefined;
    for (let i = 0; i < args.length; i++) {
      const a = args[i];
      if (/^-X\w+$/.test(a)) method = a.slice(2);
      else if (a === "-X") method = args[++i];
      else if (longOption(a, "--method")) method = a.includes("=") ? a.slice(a.indexOf("=") + 1) : args[++i];
    }
    const fields = args.some((a) => /^(-f|-F)(=|$)/.test(a) || /^-f./.test(a) || longOption(a, "--field") || longOption(a, "--raw-field") || longOption(a, "--input"));
    if (method ? method.toUpperCase() !== "GET" : fields) return ask("gh api call that changes remote data");
    return ALLOW;
  }
  if (group === "auth") return action === "status" ? ALLOW : classify("gh auth");
  if (["pr", "issue", "release", "repo", "run", "workflow", "gist", "label", "project", "secret", "variable", "cache"].includes(group)) {
    if (action && GH_READ.has(action)) return ALLOW;
    if (group === "repo" && action === "clone") return ALLOW;
    return ask(`gh ${group} ${action ?? ""} is visible to others`.replace(/\s+/g, " "));
  }
  return subcommand("gh", args);
}

// LlamaStash's CLI. Reads run; stopping a model can cut off other sessions that use it.
const LLAMASTASH_READ = new Set(["list", "status", "logs", "requests", "completions", "knobs", "show", "last-params", "help"]);
function llamastash(args: string[]): Verdict {
  const [sub, second, third] = operands(args);
  if (!sub || LLAMASTASH_READ.has(sub)) return ALLOW;
  if (sub === "api-key") return criticalAsk("llamastash api-key prints the proxy's API key");
  if (sub === "stop" || (sub === "daemon" && (second === "stop" || second === "restart"))) return ask("llamastash stops models that other sessions may be using");
  if (sub === "integrations") return piAsk("llamastash integrations changes other tools' configs, Pi's among them");
  if ((sub === "daemon" && second === "status") || (sub === "config" && second === "bindings") || (sub === "favorites" && second === "list")) return ALLOW;
  if (sub === "presets" && (third === "list" || third === "show")) return ALLOW;
  if (sub === "doctor" && !args.includes("--fix")) return ALLOW;
  return { ...classify(`llamastash ${sub}`), pattern: `llamastash ${sub} *` };
}

function subcommand(tool: string, args: string[]): Verdict {
  const table = SUBCOMMANDS[tool];
  const sub = operands(args)[0];
  if (!sub) return ALLOW;
  if (table.ask?.[sub]) return ask(table.ask[sub]);
  if (table.allow.split(/\s+/).includes(sub)) return ALLOW;
  return ASK_BY_DEFAULT[tool] ? ask(`${tool} ${sub} ${ASK_BY_DEFAULT[tool]}`) : { ...classify(`${tool} ${sub}`), pattern: `${tool} ${sub} *` };
}

// Orca coordination (spec section 11). The subcommand decides, never a blanket: reads are
// allowed, coordination that can start or stop another agent's work is judged, and anything
// that touches another machine or the GUI asks. A PATH assignment, or a program that is not
// Orca's own executable, means the name cannot be trusted.
const ORCA_READ: Record<string, string> = {
  skills: "list get",
  worktree: "list show current ps",
  repo: "list show",
  terminal: "list show",
  orchestration: `send ask reply check inbox worker_done run-current run-show run-list task-list task-update
    dispatch-show worker-show worker-read worker-list gate-list request-show`,
};
const ORCA_JUDGE: Record<string, string> = {
  worktree: "create set",
  repo: "add set",
  orchestration: `worker-start worker-stop worker-abandon worker-release dispatch task-create run-create reset`,
};
const ORCA_ASK = new Set(["computer", "account", "serve"]);
const ORCA_INSTALL = /(^|\/)orca\/resources\/bin\/orca(\.exe)?$/i;
const orcaProgram = (program: string) => {
  if (/^orca(\.exe)?$/i.test(program)) return true;
  const p = slash(program);
  // A path into Orca's install, and only an absolute one: `./orca` is any file named orca.
  return /^(\/|[a-z]:\/)/i.test(p) && ORCA_INSTALL.test(p);
};
const orcaPattern = (sub: string | undefined, second: string | undefined) =>
  sub && /^[a-z][\w-]*$/i.test(sub) ? `orca ${sub}${second && /^[a-z][\w-]*$/i.test(second) ? ` ${second}` : ""} *` : undefined;
function orca(args: string[], words: string[]): Verdict {
  // Any command that can reach a remote host asks, whatever its subcommand.
  if (args.some((a) => /^--(pairing-code|environment)(=|$)/.test(a))) return ask(`orca ${args.find((a) => /^--(pairing-code|environment)(=|$)/.test(a))} reaches a remote host`);
  if (args.some((a) => /^--on(=|$)/.test(a))) return ask("orca --on reaches another terminal, possibly on a remote host");
  // A changed PATH can point `orca` at another program.
  if (words.some((w) => /^PATH=/.test(w))) {
    const judged = classify("orca with a changed PATH");
    const pattern = orcaPattern(args[0], args[1]);
    return pattern ? { ...judged, pattern } : judged;
  }
  const [sub = "", second] = args;
  if (!sub || /^(--help|-h|--version|-v|help)$/i.test(sub)) return ALLOW;
  if (sub === "status" || sub === "agent-context") return ALLOW;
  const allow = ORCA_READ[sub];
  if (allow && allow.split(/\s+/).includes(second ?? "")) return ALLOW;
  if (ORCA_ASK.has(sub)) return ask(`orca ${sub} ${sub === "serve" ? "opens a server" : "drives the GUI or another account"}`);
  if (sub === "worktree" && ["rm", "remove", "delete"].includes(second ?? "")) return ask("orca worktree rm removes a worktree");
  if (ORCA_JUDGE[sub]?.split(/\s+/).includes(second ?? "")) return { ...classify(`orca ${sub} ${second}`), pattern: orcaPattern(sub, second) };
  return { ...classify(`orca ${sub}${second ? ` ${second}` : ""}`), pattern: orcaPattern(sub, second) };
}

// A nested agent started with the guard off, or the guard's own mode variables changed. These
// are locked: no user allow rule and no model can replace them.
function bypass(name: string, args: string[], assigned: string[], exported: boolean): Verdict | undefined {
  const option = (...names: string[]) => args.some((a) => names.some((n) => a === n || a.startsWith(`${n}=`)));
  if (/^pi(\.(exe|cmd|bat))?$/i.test(name)) {
    if (option("--no-extensions", "-ne")) return guardAsk("pi --no-extensions drops the auto-mode guard");
    if (option("--extension", "-e")) return guardAsk("pi loads an extension, which can drop the auto-mode guard");
    if (assigned.some((w) => /^PI_CODING_AGENT_DIR=/.test(w))) return guardAsk("changes PI_CODING_AGENT_DIR, which moves Pi's guard and extensions");
  }
  if (/^claude(\.(exe|cmd|bat))?$/i.test(name) && option("--dangerously-skip-permissions")) {
    return guardAsk("claude --dangerously-skip-permissions turns off its permission checks");
  }
  if (/^codex(\.(exe|cmd|bat))?$/i.test(name) && option("--dangerously-bypass-approvals-and-sandbox", "--yolo")) {
    return guardAsk("codex drops its approval checks");
  }
  if (/^opencode(\.(exe|cmd|bat))?$/i.test(name) && option("--dangerously-skip-permissions", "--skip-permissions", "--yolo", "--auto-approve", "--bypass-permissions", "--no-permissions")) {
    return guardAsk("opencode bypasses its permission checks");
  }
  // The child reads these: PI_AUTOMODE_MODE overrides the mode, and an exported
  // PI_CODING_AGENT_DIR moves the guard itself.
  if (assigned.some((w) => /^PI_AUTOMODE_MODE=/.test(w))) return guardAsk("sets PI_AUTOMODE_MODE, which overrides the auto-mode guard in a child Pi");
  if (exported && assigned.some((w) => /^PI_CODING_AGENT_DIR=/.test(w))) {
    return guardAsk("changes PI_CODING_AGENT_DIR, which moves Pi's guard and extensions");
  }
  return undefined;
}

// cmd.exe /c hides its text from the bash parser. A line that deletes a path the rules cannot
// prove is a project file of an existing directory stays critical; any other line is judged.
const CMD_DELETE = /(?:^|[\s&|;(])(del|erase|rmdir|rd|deltree)\b([^&|;]*)/gi;
function cmdDeletesSystemPath(text: string, scope: Scope): boolean {
  for (const m of text.matchAll(CMD_DELETE)) {
    const words = m[2].split(/\s+/).filter((w) => w && !w.startsWith("/") && !w.startsWith("-") && !/^[a-z]+:$/i.test(w));
    if (!words.length) return true;
    for (const word of words) {
      const p = resolveWord(word.replace(/^["']|["']$/g, ""), scope);
      // A wildcard, an unknown path, a path outside the project and a working directory that
      // does not exist cannot be proven to stay in the working directory.
      if (!p || !isLocal(p, scope) || /[*?]/.test(word) || !scope.cwd || !fs.existsSync(scope.cwd)) return true;
    }
  }
  return false;
}

function cmdLinkVerdict(text: string, scope: Scope): Verdict | undefined {
  const words = text.split(/\s+/).map((w) => w.replace(/^["']|["']$/g, ""));
  const at = words.findIndex((w) => /^mklink(\.exe)?$/i.test(w));
  if (at < 0) return undefined;
  const rest = words.slice(at + 1).filter((w) => w && !w.startsWith("/"));
  const target = rest[1];
  if (!target) return classify("cmd mklink without a readable target");
  return linkVerdict("mklink", target, scope);
}

function cmdVerdict(args: string[], scope: Scope): Verdict {
  const at = args.findIndex((a) => /^\/[ck]$/i.test(a));
  const text = (at >= 0 ? args.slice(at + 1) : args).join(" ");
  const link = cmdLinkVerdict(text, scope);
  if (link) return link;
  return cmdDeletesSystemPath(text, scope)
    ? criticalAsk("cmd.exe deletes a path the rules cannot prove is in the working directory")
    : classify("cmd.exe command");
}

// ---- PowerShell writes inside the project ----

// The writer cmdlets whose targets this vocabulary can read. Any other writer stays critical.
const PS_LOCAL_WRITERS = new Set(["set-content", "add-content", "new-item", "out-file", "copy-item", "move-item", "remove-item", "rename-item", "tee-object"]);
const PS_PATH_FLAGS = new Set(["-path", "-literalpath", "-filepath", "-pspath"]);
// Flags whose next word is not a path.
const PS_VALUE_FLAGS = new Set(["-value", "-encoding", "-itemtype", "-filter", "-include", "-exclude", "-credential", "-stream", "-delimiter", "-width", "-inputobject", "-newname", "-language", "-replace", "-type", "-variable"]);

// Words of one PowerShell command, with the quotes removed.
function psWords(text: string): string[] {
  const out: string[] = [];
  let word = "";
  let quote: string | undefined;
  let has = false;
  for (const c of text) {
    if (quote) {
      if (c === quote) quote = undefined;
      else word += c;
    } else if (c === "'" || c === '"') {
      quote = c;
      has = true;
    } else if (/\s/.test(c)) {
      if (has) out.push(word);
      word = "";
      has = false;
    } else {
      word += c;
      has = true;
    }
  }
  if (has) out.push(word);
  return out;
}

// Words for the writer parser: quotes removed, while a parenthesised expression stays together.
function psWriteWords(text: string): string[] {
  return psExprWords(text).map((word) => {
    const eq = word.indexOf("=");
    if (word.startsWith("-") && eq > 1) {
      const value = word.slice(eq + 1);
      return word.slice(0, eq + 1) + (psUnquote(value) ?? value);
    }
    if (word.startsWith("-")) return word;
    return psUnquote(word) ?? word;
  });
}

// Command positions of a PowerShell line, split on newlines, `;` and `|` outside quotes.
function psSegments(text: string): string[] {
  const out: string[] = [];
  let cur = "";
  let quote: string | undefined;
  for (const c of text) {
    if (quote) {
      cur += c;
      if (c === quote) quote = undefined;
    } else if (c === "'" || c === '"') {
      quote = c;
      cur += c;
    } else if (c === "\n" || c === ";" || c === "|" || c === "{" || c === "}") {
      out.push(cur);
      cur = "";
    } else cur += c;
  }
  out.push(cur);
  return out;
}

// The write targets of one local-writer cmdlet. `undefined` means the targets cannot be read.
function psTargets(canonical: string, words: string[]): { paths: string[]; recurse: boolean; link?: { type: string; targets: string[] } } | undefined {
  const paths: string[] = [];
  const destinations: string[] = [];
  const positionals: string[] = [];
  let newName: string | undefined;
  let itemType: string | undefined;
  let linkTarget: string | undefined;
  let linkValue: string | undefined;
  let recurse = false;
  for (let i = 1; i < words.length; i++) {
    const word = words[i];
    const eq = word.indexOf("=");
    if (word.startsWith("-") && eq > 1) {
      const flag = word.slice(0, eq).toLowerCase();
      if (flag === "-destination") destinations.push(word.slice(eq + 1));
      else if (flag === "-newname") newName = word.slice(eq + 1);
      else if (flag === "-itemtype" || flag === "-type") itemType = word.slice(eq + 1);
      else if (flag === "-target") linkTarget = word.slice(eq + 1);
      else if (flag === "-value") linkValue = word.slice(eq + 1);
      else if (PS_PATH_FLAGS.has(flag)) paths.push(word.slice(eq + 1));
      continue;
    }
    if (/^-[a-z][\w-]*$/i.test(word)) {
      const flag = word.toLowerCase();
      if (flag === "-recurse" || flag === "-r") recurse = true;
      if (flag === "-destination") {
        const value = words[++i];
        if (value !== undefined) destinations.push(value);
      } else if (flag === "-newname") {
        newName = words[++i];
      } else if (flag === "-itemtype" || flag === "-type") {
        itemType = words[++i];
      } else if (flag === "-target") {
        linkTarget = words[++i];
      } else if (flag === "-value") {
        linkValue = words[++i];
      } else if (PS_PATH_FLAGS.has(flag)) {
        const value = words[++i];
        if (value !== undefined) paths.push(value);
      } else if (PS_VALUE_FLAGS.has(flag)) i++;
      continue;
    }
    positionals.push(word);
  }
  const all = [...paths, ...destinations, ...positionals];
  const linkType = itemType?.toLowerCase();
  const isLink = !!linkType && ["symboliclink", "junction", "hardlink"].includes(linkType);
  const link = isLink ? { type: linkType!, targets: [linkTarget, linkValue].filter((x): x is string => !!x) } : undefined;
  switch (canonical) {
    case "set-content":
    case "add-content":
    case "out-file":
    case "tee-object":
      return { paths: all.slice(0, 1), recurse };
    case "rename-item": {
      // -NewName is a path relative to the item's folder and may climb out of it.
      const source = all[0];
      if (!source) return { paths: [], recurse };
      return { paths: newName ? [source, path.join(path.dirname(source), newName)] : [source], recurse };
    }
    case "new-item": {
      // -Name is created under -Path, and may contain `..`.
      const base = paths[0];
      const name = positionals[0];
      return { paths: base && name ? [path.join(base, name)] : base ? [base] : name ? [name] : [], recurse, link };
    }
    case "copy-item":
      // Only the destination is written; the source is read. A pipeline source has no target.
      return { paths: [destinations[0] ?? positionals[1] ?? (paths.length > 1 ? paths[1] : undefined)].filter(Boolean) as string[], recurse };
    default:
      // remove-item and move-item change every path operand they are given.
      return { paths: all, recurse };
  }
}

interface PsWrites {
  found: boolean;
  ok: boolean;
  verdict?: Verdict;
  // The local writers that were written as an alias (sc, rm, ni…), with how many of them the
  // segment parse read. The alias scan in powershellVerdict only skips that many.
  aliases?: Map<string, number>;
}

// Whether the file writes of a PowerShell line all have literal targets inside the working
// directory or temp. Without a scope nothing can be proven, so the old critical ask stays.
function psWrites(text: string, bare: string, scope: Scope | undefined): PsWrites {
  const vars = psAssignments(text);
  const writers = [...bare.matchAll(new RegExp(PS_WRITERS.source, "gi"))]
    .map((m) => /([a-z][a-z0-9]*-[a-z0-9]+)$/i.exec(m[0].trim())?.[1].toLowerCase() ?? "");
  // Out-File and Tee-Object do not match PS_WRITERS, which wants `<verb>-<noun>` twice.
  const outFile = /\b(out-file|tee-object)\b/i.test(bare);

  interface Target { word: string; recurse: boolean }
  const targets: Target[] = [];
  const parsedNames: string[] = [];
  const aliases = new Map<string, number>();
  const fail = (verdict = criticalAsk("PowerShell writes a file")): PsWrites => ({ found: true, ok: false, verdict });
  for (const segment of psSegments(text)) {
    const words = psWriteWords(segment);
    if (!words.length) continue;
    if (words[0].startsWith("$") && words[1] === "=") continue;
    // Redirects can follow any command position.
    for (let i = 0; i < words.length; i++) {
      const match = /^(?:\d+|\*)?(>>?)(.*)$/.exec(words[i]);
      if (!match) continue;
      const rest = match[2];
      const target = rest.startsWith("&") ? "" : rest || (words[++i] ?? "");
      // $null and a file descriptor duplicate are not files.
      if (!target || target === "$null" || /^\d+$/.test(target)) continue;
      targets.push({ word: target, recurse: false });
    }
    const raw = words[0].toLowerCase();
    const canonical = PS_ALIASES[raw] ?? raw;
    if (!PS_LOCAL_WRITERS.has(canonical)) continue;
    if (PS_ALIASES[raw]) aliases.set(canonical, (aliases.get(canonical) ?? 0) + 1);
    parsedNames.push(canonical);
    const extracted = psTargets(canonical, words);
    if (!extracted || !extracted.paths.length) return { found: true, ok: false, verdict: criticalAsk("PowerShell writes a file") };
    // A symbolic link, junction or hard link makes a later project-looking path reach its target.
    if (extracted.link) {
      if (!extracted.link.targets.length) return fail(criticalAsk("PowerShell creates a link to an unknown target"));
      for (const target of extracted.link.targets) {
        const v = psLinkVerdict(target, scope, vars);
        if (v) return fail(v);
      }
    }
    // Copy-Item and Move-Item read their source as well as writing the destination.
    if (canonical === "copy-item" || canonical === "move-item") {
      for (const source of psCopySources(words)) {
        const v = psCopySourceVerdict(source, scope, vars);
        if (v) return fail(v);
      }
    }
    for (const word of extracted.paths) targets.push({ word, recurse: extracted.recurse });
  }
  if (!writers.length && !outFile && !targets.length && !parsedNames.length) return { found: false, ok: true };
  if (!scope) return fail();
  // Cmdlets that change something other than a file (Stop-Process, Invoke-RestMethod, Start-Job) are
  // not credential reads or root: they are judged like any outward action, not gated.
  const other = writers.find((w) => !PS_LOCAL_WRITERS.has(w));
  if (other) return fail(ask(`PowerShell runs ${other}`));

  // Every writer the vocabulary sees must have been read here. An alias (sc, rm) adds a parsed
  // name the regex does not see, which is fine; a writer the regex sees but the segment parse
  // missed (inside parentheses, say) is not.
  const unread = [...writers];
  for (const name of parsedNames) {
    const at = unread.indexOf(name);
    if (at >= 0) unread.splice(at, 1);
  }
  if (unread.length || !targets.length) return fail();

  let bad: Verdict | undefined;
  for (const { word, recurse } of targets) {
    // A variable, wildcard or subexpression cannot be resolved here.
    if (!word || /[$`*?[\]{}()]/.test(word)) return fail();
    const p = resolveWord(word, scope);
    if (!p) return fail();
    // The write must land in the project (or temp), and the working directory must exist: that is
    // what proves a literal target really is inside it (a synthetic or removed cwd proves nothing).
    if (isGuarded(p, scope)) return fail(criticalAsk("PowerShell changes the auto-mode guard's own files"));
    if (isPiFile(p, scope)) return fail(criticalAsk(`PowerShell changes Pi's own files: ${word}`));
    if (!isLocal(p, scope) || !scope.cwd || !fs.existsSync(scope.cwd)) return fail();
    if (recurse && scope.root && (p === scope.root || /(^|[\\/])\.git([\\/]|$)/i.test(p))) {
      bad ??= ask("PowerShell removes the whole project or its git data");
    }
  }
  if (bad) return { found: true, ok: false, verdict: bad };
  return { found: true, ok: true, aliases };
}

// A header value that looks like a token rather than a media type or a short setting.
function tokenLooking(value: string): boolean {
  const after = value.includes(":") ? value.slice(value.indexOf(":") + 1) : value;
  for (const m of after.matchAll(/[A-Za-z0-9_\-]{12,}/g)) {
    const token = m[0];
    if (token.length >= 20 || (token.length >= 12 && /[A-Z_0-9]/.test(token))) return true;
  }
  return false;
}

function headerValues(args: string[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "-H") { if (args[i + 1] !== undefined) out.push(args[++i]); }
    else if (longOption(a, "--header")) {
      if (a.includes("=")) out.push(a.slice(a.indexOf("=") + 1));
      else if (args[i + 1] !== undefined) out.push(args[++i]);
    } else if (/^-H./.test(a)) out.push(a.slice(2));
  }
  return out;
}

const URL_TOKEN = /[?&](token|key|secret|password|passwd|api_key|apikey)=/i;
function tokenQuery(args: string[]): string | undefined {
  return args.find((a) => /^https?:\/\//i.test(a) && URL_TOKEN.test(a));
}

function network(cmd: string, args: string[], scope: Scope): Verdict {
  const sends = `${cmd} sends data to a remote host`;
  if (cmd === "curl") {
    if (args.some((a) => a === "-K" || a.startsWith("-K") || longOption(a, "--config"))) return ask(sends);
    for (const header of headerValues(args)) if (header.startsWith("@") || tokenLooking(header)) return ask(sends);
    const cookie = optionArg(args, "-b", "--cookie");
    if (cookie?.startsWith("@")) return ask(sends);
  } else {
    if (args.some((a) => longOption(a, "--config") || a === "-K")) return ask(sends);
    for (const header of headerValues(args)) if (header.startsWith("@") || tokenLooking(header)) return ask(sends);
    if (args.some((a) => longOption(a, "--load-cookies"))) return ask(sends);
  }
  if (tokenQuery(args)) return ask(sends);
  if (cmd === "curl") {
    // -d/--data, --json, -F/--form and -T/--upload-file send a body; GNU accepts the prefixes.
    const sendsData = args.some((a) => /^(-d|-F|-T)(=|$)/.test(a) || /^-[a-zA-Z]*[dFT]/.test(a)
      || ["--data", "--data-raw", "--data-binary", "--data-urlencode", "--json", "--form", "--form-string", "--upload-file"].some((f) => longOption(a, f)));
    if (sendsData) return ask("curl sends data to a remote host");
    let method: string | undefined;
    for (let i = 0; i < args.length; i++) {
      const a = args[i];
      if (/^-X\w+$/.test(a)) method = a.slice(2);
      else if (a === "-X") method = args[++i];
      else if (longOption(a, "--request")) method = a.includes("=") ? a.slice(a.indexOf("=") + 1) : args[++i];
    }
    if (method && !/^(GET|HEAD|OPTIONS)$/i.test(method)) return ask(`curl -X ${method} changes remote data`);
  } else if (args.some((a) => longOption(a, "--post-data") || longOption(a, "--post-file") || longOption(a, "--body-data") || longOption(a, "--body-file") || longOption(a, "--method"))) {
    return ask("wget sends data to a remote host");
  }
  const curl = cmd === "curl";
  // A URL or header built from a variable or a substitution can carry local data out. The name
  // of the file it saves to stays local.
  const outFlags = curl ? ["-o", "--output"] : ["-O", "--output-document", "-o", "--output-file"];
  const literal = (a: string) => a.replace(/\$\{(\w+)\}|\$(\w+)/g, (m, x, y) => (scope.loopVars?.has(x ?? y) ? "" : m));
  const isOut = (flag: string) => outFlags.some((f) => flag === f || (f.startsWith("--") && longOption(flag, f)));
  if (args.some((a, i) => /[$`]/.test(literal(a)) && !isOut(args[i - 1] ?? ""))) return ask(`${cmd} request built from local data`);
  const opts = optionValues(args, curl ? "AbcCdDeEFHKmoPQrtTuUwxXyYz" : "aABDeiIlOoPQRtTUwX", [...DOWNLOAD_FILES[cmd].other, ...DOWNLOAD_FILES[cmd].saved, DOWNLOAD_FILES[cmd].dir].flat());
  const values = (flags: string[]) => opts.filter(([flag]) => flags.some((f) => flag === f || (f.startsWith("--") && longOption(flag, f)))).map(([, value]) => value ?? "");
  const writes = (file: string) => {
    const p = resolveWord(file, scope);
    if (file === "-" || (p && DEV_SINKS.test(p))) return { p: undefined };
    if (isPiFile(p, scope)) return { p, outside: piAsk(`${cmd} writes Pi's own files: ${file}`) };
    return isLocal(p, scope) ? { p } : { p, outside: outside(`${cmd} writes outside the working directory: ${file}`, p) };
  };
  for (const file of values(DOWNLOAD_FILES[cmd].other)) {
    const w = writes(file);
    if (w.outside) return w.outside;
  }
  const saved = values(DOWNLOAD_FILES[cmd].saved);
  for (const file of saved) {
    const w = writes(file);
    if (w.outside) return w.outside;
    if (w.p) note(w.p, "fetched", scope);
  }
  // wget, and curl -O, save under the URL's file name, in the current directory or the one
  // named by --output-dir (curl) or -P (wget).
  const remoteName = curl ? opts.some(([flag]) => ["-O", "--remote-name", "--remote-name-all"].includes(flag)) : !saved.length;
  if (!remoteName) return ALLOW;
  const named = values(DOWNLOAD_FILES[cmd].dir).at(-1);
  const dir = named === undefined ? scope.cwd : resolveWord(named, scope);
  if (isPiFile(dir, scope)) return piAsk(`${cmd} writes into Pi's own files: ${named ?? dir}`);
  if (!isLocal(dir, scope)) return outside(`${cmd} writes outside the working directory${named ? `: ${named}` : ""}`, dir);
  for (const url of args.filter((a) => /^https?:\/\//.test(a))) {
    const file = path.basename(url.split(/[?#]/)[0]);
    if (file && dir) note(path.join(dir, file), "fetched", scope);
  }
  return ALLOW;
}

// The options of curl and wget that name a file they write: the download itself (`saved`), other
// files such as a cookie jar or a log (`other`), and the directory a remote name is saved in.
const DOWNLOAD_FILES: Record<string, { saved: string[]; other: string[]; dir: string[] }> = {
  curl: { saved: ["-o", "--output"], other: ["-c", "--cookie-jar", "-D", "--dump-header", "--trace", "--trace-ascii", "--stderr"], dir: ["--output-dir"] },
  wget: { saved: ["-O", "--output-document"], other: ["-o", "--output-file", "-a", "--append-output"], dir: ["-P", "--directory-prefix"] },
};

// Options with their values. `valued` holds the short options that take one, so a cluster like
// `-fsSLo file`, `-ofile` or `-qO-` reads right; `long` the long options whose value may be the
// next word.
function optionValues(args: string[], valued: string, long: string[]): [string, string | undefined][] {
  const out: [string, string | undefined][] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--") break;
    if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      out.push(eq > 0 ? [a.slice(0, eq), a.slice(eq + 1)] : [a, long.some((l) => l === a || longOption(a, l)) ? args[++i] : undefined]);
    } else if (a.length > 1 && a.startsWith("-")) {
      for (let j = 1; j < a.length; j++) {
        if (!valued.includes(a[j])) {
          out.push([`-${a[j]}`, undefined]);
          continue;
        }
        out.push([`-${a[j]}`, j + 1 < a.length ? a.slice(j + 1) : args[++i]]);
        break;
      }
    }
  }
  return out;
}

function find(args: string[], scope: Scope): Verdict {
  const firstOption = args.findIndex((a) => /^(-|\(|!)/.test(a));
  const roots = firstOption < 0 ? args : args.slice(0, firstOption);
  if (!args.some((a) => FIND_ACTS.test(a))) return ALLOW;
  const exec = args.findIndex((a) => /^-(exec|execdir|ok|okdir)$/.test(a));
  // -exec settles on its own command: one that only reads (ls, cat, wc, diff) writes nothing,
  // so it runs even when the search crosses Pi's own files or leaves the working directory.
  let inner: string[] | undefined;
  if (exec >= 0) {
    const end = args.findIndex((a, i) => i > exec && (a === ";" || a === "+"));
    // {} stands for one match under the search roots, never a root itself: `find . -name
    // __pycache__ -exec rm -rf {} +` deletes the matches, not the project.
    // Without a test that picks matches, every path under the root matches, the root included.
    // A name test of only wildcards and dots (`-name '*'`, `-name '.*'`) can still match the root.
    const picks =
      args.some((a) => /^-(i?name|i?path|i?wholename|i?regex|newer\w*|[acm](time|min)|size|empty|user|group|perm)$/.test(a)) &&
      !args.some((a, i) => /^-i?(name|path|wholename|regex)$/.test(a) && /^[*.?\\]*$/.test(args[i + 1] ?? ""));
    // A literal -name keeps its name, so `-name .git` still reads as deleting git data.
    const literal = args.find((a, i) => /^-i?name$/.test(args[i - 1] ?? "") && !/[*?[\\]/.test(a));
    const under = picks ? `${(roots[0] ?? ".").replace(/\/+$/, "")}/${literal ?? "find-match"}` : ".";
    inner = args.slice(exec + 1, end < 0 ? undefined : end).map((a) => (a === "{}" ? under : a));
    const rootPaths = (roots.length ? roots : ["."]).map((r) => ({ r, p: resolveWord(r, scope) }));
    const secret = rootPaths.find(({ r, p }) => secretIn(r, scope) || (p && isSecretPath(p)));
    if (secret) return criticalAsk(`find reads a credential location: ${secret.r}`);
    // Outside the project only commands that show names, not contents (ls, stat, du), skip the check.
    const execNames = args.flatMap((a, i) => (/^-(exec|execdir|ok|okdir)$/.test(a) && args[i + 1] ? [path.basename(args[i + 1])] : []));
    const namesOnly = execNames.every((n) => NAMES_ONLY.has(n));
    if (findReads(args, scope) && rootPaths.every(({ p }) => !isPiFile(p, scope) && (namesOnly || isLocal(p, scope)))) return ALLOW;
  }
  for (const r of roots.length ? roots : ["."]) {
    const p = resolveWord(r, scope);
    if (isPiFile(p, scope)) return piAsk(`find deletes or runs commands in Pi's own files: ${r}`);
    if (!isLocal(p, scope)) return outsideDelete(`find deletes or runs commands outside the working directory: ${r}`, p);
  }
  if (exec < 0) return classify("find -delete");
  return worst(classify("find -exec"), simple({ argv: inner!, out: [] }, scope, 1));
}

// sed `w`/`W` commands write files named inside the script; `e` and the `e` flag on s/// run a
// shell command. `-f` names a script file, `-e`/`--expression` supply a script on the line.
const SED_WRITE = /(?:^|[;\n{}])\s*[wW]\s+(\S+)|(?:^|[^\\])\/[wW]\s+(\S+)/g;
const SED_BARE_WRITE = /(?:^|[;\n{}])\s*[wW]\s*(?=$|[;\n}])/;
const SED_EXEC_COMMAND = /(?:^|[;\n{}])\s*e(?:\s|$)/;
function sedScriptWrites(script: string): string[] {
  const out: string[] = [];
  for (const m of script.matchAll(SED_WRITE)) out.push(m[1] ?? m[2]);
  return out;
}
// The `e` flag on a substitution, as in `s|a|b|e`, and the `e` command on its own.
function sedScriptExecs(script: string): boolean {
  if (SED_EXEC_COMMAND.test(script)) return true;
  for (const m of script.matchAll(/(?:^|[;\n{}])\s*s(.)/g)) {
    const delimiter = m[1];
    const rest = script.slice((m.index || 0) + m[0].length);
    let part = 0;
    for (let i = 0; i < rest.length; i++) {
      if (rest[i] === "\\") { i++; continue; }
      if (rest[i] !== delimiter) continue;
      if (++part !== 2) continue;
      const flags = /^[a-zA-Z0-9]*/.exec(rest.slice(i + 1))?.[0] ?? "";
      if (flags.includes("e")) return true;
      break;
    }
  }
  return false;
}

function sedVerdict(args: string[], scope: Scope): Verdict {
  if (sedWrites(args)) return writeTargets("sed", args, scope);
  let verdict: Verdict = ALLOW;
  const scripts: string[] = [];
  const scriptFiles = optionArgs(args, "-f", "--file");
  // -e/--expression may be repeated; the first operand is the script only when neither is given.
  const expressions = optionArgs(args, "-e", "--expression");
  if (expressions.length) scripts.push(...expressions);
  else if (!scriptFiles.length) {
    const first = operands(withoutOptionValues(args, "-f", "--file"))[0];
    if (first !== undefined) scripts.push(first);
  }
  for (const file of scriptFiles) {
    const p = resolveWord(file, scope);
    if (p && !isLocal(p, scope)) return outwardClassify(`sed runs a script from outside the working directory: ${file}`);
    // A script file of the project is still a script: read what it names.
    try {
      if (p && fs.statSync(p, { throwIfNoEntry: false })?.isFile()) scripts.push(fs.readFileSync(p, "utf8"));
    } catch { /* unreadable stays with the normal checks */ }
  }
  for (const script of scripts) {
    if (sedScriptExecs(script)) verdict = worst(verdict, outwardClassify("sed runs a shell command from its script"));
    for (const target of sedScriptWrites(script)) {
      const v = writePathVerdict("sed", target, scope);
      if (v) verdict = worst(verdict, v);
    }
    // A `w` command with no visible file name can write anywhere the shell can.
    if (SED_BARE_WRITE.test(script) && !sedScriptWrites(script).length) verdict = worst(verdict, outwardClassify("sed writes a file whose name the rules cannot see"));
  }
  return verdict;
}

// awk writes with `>`/`>>` and runs commands with `| "cmd"` or system(). A target held in an awk
// variable cannot be resolved here, so it stays with the model instead of being allowed.
function awkVerdict(args: string[], scope: Scope): Verdict {
  let program = "";
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "-v" || a === "-F" || a === "-f" || a === "--assign" || a === "--field-separator" || a === "--file") { i++; continue; }
    if (/^-(v|F|f)/.test(a) || a.startsWith("--")) continue;
    program = a;
    break;
  }
  if (/system\s*\(/.test(program) || /\|\s*"/.test(program)) return outwardClassify("awk that runs commands");
  for (const m of program.matchAll(/(>>?|\|)\s*([^\s;|})]+)/g)) {
    const op = m[1];
    const raw = m[2];
    if (op === "|") return outwardClassify("awk that runs commands");
    if (!raw || raw.startsWith("&") || /^\d+$/.test(raw)) continue;
    const literal = /^(['"]).*\1$/.test(raw) ? raw.slice(1, -1) : undefined;
    if (literal === undefined) return outwardClassify("awk writes a file whose name is held in a variable");
    const v = writePathVerdict("awk", literal, scope);
    if (v) return v;
  }
  return ALLOW;
}

// dig, nslookup, host, getent, ping, traceroute and whois send the name they query. A token
// encoded in the name leaves the machine even though the command only reads.
const DNS_QUERY = new Set(["dig", "nslookup", "host", "getent", "ping", "traceroute", "tracert", "whois"]);
function dnsEncoded(args: string[]): string | undefined {
  for (const word of args) {
    if (word.startsWith("-") || word.startsWith("+") || !/[A-Za-z]/.test(word)) continue;
    const name = word.replace(/^["']|["']$/g, "").replace(/^\[|\]$/g, "");
    if (!/^[A-Za-z0-9_.-]+$/.test(name)) continue;
    if (name.includes("_")) return word;
    for (const label of name.split(".")) {
      if (label.length > 24) return word;
      if (label.length > 8 && /[A-Z]/.test(label)) return word;
    }
  }
  return undefined;
}

// Empty when nothing is left to run. With `only`, drops just the keywords and those wrappers
// (by exact name) and stops at an assignment.
function unwrap(words: string[], only?: Set<string>): string[] {
  const argv = [...words];
  const assignment = (word: string) => !only && /^[A-Za-z_][A-Za-z0-9_]*=/.test(word);
  for (;;) {
    while (argv.length && (KEYWORDS.has(argv[0]) || assignment(argv[0]))) argv.shift();
    if (!argv.length || NOOP_KEYWORDS.has(argv[0])) return [];
    const wrapper = only ? argv[0] : path.basename(argv[0]);
    if (!(only ?? WRAPPERS).has(wrapper)) return argv;
    argv.shift();
    // `command -v name` looks a command up and runs nothing.
    if (wrapper === "command" && /^-[vV]$/.test(argv[0] ?? "")) return [];
    // Wrapper options and their values: flags, numbers, durations, VAR=value.
    while (argv.length && (/^(-.*|\d+(\.\d+)?[smhd]?)$/.test(argv[0]) || assignment(argv[0]))) argv.shift();
  }
}

// Where the output of a simple command comes from. Literal text is the agent's own: echo and
// printf without a variable or substitution, and cat of a heredoc.
function outputOrigin(cmd: Simple, scope: Scope): Origin {
  const [program = "", ...args] = unwrap(cmd.argv);
  const name = path.basename(program);
  if (name === "curl" || name === "wget") return "fetched";
  const literal = !cmd.expands && !args.some((a) => /[$`]/.test(a));
  if (literal && (name === "echo" || name === "printf" || (name === "cat" && cmd.heredoc && !operands(args).length))) return "authored";
  return args.some((a) => isFetched(a, scope)) ? "fetched" : "other";
}

function redirects(cmd: Simple, scope: Scope): Verdict {
  let verdict = ALLOW;
  const origin = cmd.out.length ? outputOrigin(cmd, scope) : "other";
  for (const target of cmd.out) {
    const p = resolveWord(target, scope);
    if (p && DEV_SINKS.test(p)) continue;
    if (p && /^\/dev\//.test(p)) return deny(`writes to the device ${target}`);
    if (isGuarded(p, scope)) verdict = worst(verdict, guardAsk("redirect overwrites the auto-mode guard's own files"));
    else if (isPiFile(p, scope)) verdict = worst(verdict, piAsk(`redirect writes Pi's own files: ${target}`));
    else if (isGitHook(p)) verdict = worst(verdict, gitHookWrite(target));
    else if (!isLocal(p, scope)) verdict = worst(verdict, outside(`redirect writes outside the working directory: ${target}`, p));
    // Appending literal text leaves the file's origin as it was.
    if (!(origin === "authored" && cmd.append?.includes(target))) note(p, origin, scope);
  }
  return verdict;
}

// Redirect targets are always checked by the built-in rules (allowedPaths is the way to open
// a directory). For the command itself a user rule replaces the built-in verdict.
function simple(cmd: Simple, scope: Scope, depth = 0): Verdict {
  const out = redirects(cmd, scope);
  if (out.action === "deny") return out;
  let builtin = command(cmd, scope, depth);
  // An ask the user can allow for the session as a pattern, so the next call like it does not ask.
  if (builtin.action === "ask" && !builtin.locked && !builtin.firm && !builtin.pattern && !("dir" in builtin)) {
    const pattern = askPattern(unwrap(cmd.argv));
    if (pattern) builtin = { ...builtin, pattern, fromAsk: true };
  }
  if (builtin.action === "deny" || builtin.locked) return worst(out, builtin);
  const mine = scope.rules && userVerdict(cmd.argv, scope.rules);
  if (mine) return worst(out, mine);
  if (scope.picked && !builtin.firm && allowedBy(cmd.argv, scope.picked)) return worst(out, ALLOW);
  return worst(out, builtin);
}

const clip80 = (text: string) => (text.length > 80 ? `${text.slice(0, 80)}...` : text);
function command(cmd: Simple, scope: Scope, depth: number): Verdict {
  let verdict = ALLOW;
  const argv = unwrap(cmd.argv);
  const assigned = cmd.argv.slice(0, cmd.argv.length - argv.length);
  if (["export", "declare", "typeset", "readonly"].includes(argv[0])) assigned.push(...argv.slice(1));
  const loader = assigned.map((w) => envLoadsCode(w, scope)).find(Boolean);
  if (loader) verdict = outwardClassify(loader);
  // `env` or `printenv` on their own print every variable, and tokens often live there.
  const bareEnv = cmd.argv.length && path.basename(cmd.argv[0]) === "env" && cmd.argv.slice(1).every((w) => w.startsWith("-") || /^[A-Za-z_][A-Za-z0-9_]*=/.test(w));
  if (bareEnv || (path.basename(argv[0] ?? "") === "printenv" && argv.length === 1)) return worst(verdict, classify("prints environment variables, which can hold tokens"));
  if (!argv.length) return verdict;

  const name = path.basename(argv[0]);
  const args = argv.slice(1);
  const config = configVerdict(name, args, scope);
  if (config) verdict = worst(verdict, config);
  // `assigned` holds the assignments and wrapper words unwrap() removed, plus export's arguments.
  // A word that is merely an argument to a command is not an assignment.
  const exported = ["export", "declare", "typeset", "readonly"].includes(name);
  // Orca's own coordination CLI: the subcommand decides, not the name. A path is trusted only
  // when it is Orca's install, not a temp file or something this session wrote.
  if (orcaProgram(argv[0])) {
    const resolved = resolveWord(argv[0], scope);
    if (!/[\\/]/.test(argv[0]) || (resolved && !inTmp(resolved) && originOf(resolved, scope) === undefined)) return worst(verdict, orca(args, assigned));
  }
  // A nested agent started with the guard off, and the guard's mode variables.
  const off = bypass(name, args, assigned, exported);
  if (off) return worst(verdict, off);
  // Printing the environment, or a variable that holds a token, shows the agent a credential.
  if (printsSecrets(name, args)) verdict = worst(verdict, classify("prints environment variables, which can hold tokens"));

  // Bash's parser cannot determine the semantics of another shell's inline code.
  if (/^(powershell|pwsh)(\.exe)?$/i.test(name)) {
    // -Command carries the text, so the vocabulary can read it; -File and -EncodedCommand hide it.
    const at = args.findIndex((a) => /^-(command|c)$/i.test(a));
    if (at >= 0 && args[at + 1]) return powershellVerdict(args.slice(at + 1).join(" "), scope);
    // -ExecutionPolicy Bypass drops a Windows protection, so it keeps the critical ask.
    const bypassPolicy = args.some((a, i) => /^-e(xecutionpolicy)?$/i.test(a) && /^(bypass|unrestricted)$/i.test(args[i + 1] ?? ""));
    const file = args.findIndex((a) => /^-(file|f)$/i.test(a));
    if (!bypassPolicy) {
      const script = file >= 0 ? args[file + 1] : args.find((a) => !a.startsWith("-"));
      if (script && /(\.ps1|\.psm1)$/i.test(script)) {
        const p = resolveWord(script, scope);
        if (p) return { ...classify(`runs a PowerShell script: ${script}`), runs: [p] };
      }
    }
    return criticalAsk("PowerShell needs review; the command is hidden from the rules");
  }
  if (/^cmd(\.exe)?$/i.test(name)) return worst(verdict, cmdVerdict(args, scope));

  if (["case", "function", "select", "source", ".", "trap", "alias"].includes(name)) return worst(verdict, classify(`shell ${name}`));
  if (/^mkfs(\.|$)/.test(name) || name === "wipefs") return deny(`${name} formats a disk`);

  // The guard's own files: only commands that can write them ask.
  // `cd` moves the shell, not a file; sed without -i and find without an action only read; and
  // an option word (`-n`, `--depth`, a bare `-` for stdin) is never a path, though an attached
  // value such as --output=/path still is.
  const named = args.filter((a) => !a.startsWith("-") || a.includes("="));
  if (!readsOnlyCommand(name, args, scope) && ((scope.cwd !== undefined && isGuarded(scope.cwd, scope)) || named.some((a) => isGuarded(resolveWord(a.replace(/^[^=]*=/, ""), scope), scope)))) {
    verdict = worst(verdict, guardAsk(`${name} touches the auto-mode guard's own files`));
  }
  const secret = credentialRead(name, args, cmd, scope);
  if (secret) verdict = worst(verdict, criticalAsk(`${name} reads a credential file: ${secret}`));
  // With an unknown working directory, a bare credential-shaped name cannot be proven to be a
  // project file, so the read goes to the judges instead of being allowed.
  if (!secret && !scope.cwd && !NAMES_ONLY.has(name) && !(name === "sed" && sedWrites(args))) {
    const bare = args.find((a) => !a.includes("=") && CREDENTIAL_BARE_NAMES.has(path.basename(a.replace(/^@/, "")).toLowerCase()));
    if (bare) verdict = worst(verdict, classify(`reads ${bare} with an unknown working directory, where it could be a credential`));
  }
  // Pi's package commands change its settings and what code every session loads.
  if (name === "pi" && ["install", "remove", "uninstall", "update", "config"].includes(args[0])) verdict = worst(verdict, piAsk(`pi ${args[0]} changes Pi's own setup`));
  // A program in a temp directory, or one this session wrote or downloaded, is not the tool its
  // name says: /tmp/file is not file(1).
  if (argv[0].includes("/")) {
    const p = resolveWord(argv[0], scope);
    if (p && (inTmp(p) || originOf(p, scope) !== undefined)) return worst(verdict, runFile(argv[0], args, scope) ?? classify(`runs ${argv[0]}`));
  }

  if (name === "sudo" || name === "doas") {
    const inner = afterFlags(args, /^-[ugCDhpRrTU]$/);
    // On a trusted host, root for a command that only reads. A shell, a login or an edit is never that.
    if (scope.remoteRoot && inner.length && !args.some((a) => /^-[a-zA-Z]*[sieE]/.test(a) || /^--(shell|login|edit|preserve-env)/.test(a))) {
      const v = simple({ argv: inner, out: [] }, scope, depth + 1);
      if (v.action === "allow") return worst(verdict, v);
    }
    return worst(verdict, criticalAsk(`${name} runs as root`), inner.length ? simple({ argv: inner, out: [] }, scope, depth + 1) : ALLOW);
  }
  if (name === "ssh" && scope.trustedHosts?.length && !scope.remote) {
    const trusted = trustedSsh(args, scope, depth);
    if (trusted) return worst(verdict, trusted);
  }
  if (ALWAYS_ASK[name]) return worst(verdict, (name === "su" || name === "pkexec" ? criticalAsk : ask)(`${name} ${ALWAYS_ASK[name]}`));
  if (args.length === 1 && /^(--version|-V|--help|-h)$/.test(args[0])) return verdict;

  if (SHELLS.has(name)) {
    if (args[0] === "-n") return verdict;
    const c = args.findIndex((a) => /^-[a-zA-Z]*c$/.test(a));
    if (c >= 0 && depth <= 3) return worst(verdict, evaluateParsed(parse(args[c + 1] ?? ""), scope, depth + 1));
    const [script, ...rest] = afterFlags(args, /^[-+]o$/);
    return worst(verdict, (c < 0 && script && !cmd.heredoc && runFile(script, rest, scope)) || classify(`runs a script with ${name}`));
  }
  if (name === "eval") return worst(verdict, evaluateParsed(parse(args.join(" ")), scope, depth + 1));
  // `uv run pytest` and similar: the rest of the line is the command.
  if (RUNNERS[name] && operands(args)[0] === RUNNERS[name]) {
    const inner = afterFlags(args.slice(args.indexOf(RUNNERS[name]) + 1), /^(--with|--python|-p|--project|--group|--extra|--env-file|--directory)$/);
    return worst(verdict, inner.length ? simple({ argv: inner, out: [] }, scope, depth + 1) : ALLOW);
  }
  if (name === "rsync" && operands(args).some((a) => /^[\w.@-]+:/.test(a))) return worst(verdict, ask("rsync copies to or from a remote host"));
  if (name === "xargs") {
    const inner = afterFlags(args, /^-[InPLsdE]$/);
    // `... | xargs rm -rf`: the targets come from stdin, so the rules cannot see them at all.
    const destructive = inner.length > 0 && DESTRUCTIVE_XARGS.has(path.basename(inner[0]));
    return worst(verdict, destructive ? criticalAsk("xargs deletes paths the rules cannot see") : classify("xargs"), inner.length ? simple({ argv: [...inner, "$()"], out: [] }, scope, depth + 1) : ALLOW);
  }
  if (name === "cd" || name === "pushd" || name === "popd") return verdict;

  // Commands whose write target or whose executable lives in a flag.
  if (name === "sort") {
    const out = optionArg(args, "-o", "--output");
    if (out !== undefined) { const v = writePathVerdict("sort", out, scope); if (v) return worst(verdict, v); }
    return verdict;
  }
  if (name === "yq" && args.some((a) => /^(-i|--in-place)(=|$)/.test(a))) {
    for (const t of operands(args).slice(1)) { const v = writePathVerdict("yq", t, scope); if (v) return worst(verdict, v); }
    return verdict;
  }
  if (name === "xxd" && args.some((a) => /^-r/.test(a))) {
    const files = args.filter((a) => !a.startsWith("-") || a === "-");
    const out = files.length >= 2 ? files.at(-1) : undefined;
    if (out && out !== "-") { const v = writePathVerdict("xxd", out, scope); if (v) return worst(verdict, v); }
    return verdict;
  }
  if (name === "tsc") {
    for (const flag of ["--outFile", "--outDir", "--declarationDir"]) {
      const out = optionArg(args, flag);
      if (out !== undefined) { const v = writePathVerdict(`tsc ${flag}`, out, scope); if (v) return worst(verdict, v); }
    }
  }
  if (FORMATTERS[name]) {
    const v = formatterVerdict(name, args, scope);
    if (v) return worst(verdict, v);
  }
  if (name === "man" && args.some((a) => a === "-P" || /^--pager(=|$)/.test(a))) return worst(verdict, outwardClassify("man -P runs a pager command the rules cannot see"));
  if (name === "rg" && args.some((a) => a === "--pre" || /^--pre=/.test(a))) return worst(verdict, outwardClassify("rg --pre runs a command for each searched file"));
  if (name === "less" && assigned.some((a) => /^LESSOPEN=/.test(a))) return worst(verdict, outwardClassify("less runs the LESSOPEN command it is given"));
  if (name === "journalctl" && args.some((a) => /^--(vacuum|rotate|flush)/.test(a))) return worst(verdict, ask("journalctl deletes, rotates or flushes journal files"));
  if (name === "date") {
    if (args.some((a) => a === "-s" || a === "--set" || /^--set=/.test(a))) return worst(verdict, ask("date --set changes the system clock"));
    const values = new Set(["-d", "--date", "-r", "--reference", "-f", "--file"]);
    for (let j = 0; j < args.length; j++) {
      const a = args[j];
      if (values.has(a)) { j++; continue; }
      if (a.startsWith("+") || a.startsWith("-")) continue;
      return worst(verdict, ask("date with a time operand changes the system clock"));
    }
  }
  if (name === "hostname") {
    if (args.some((a) => /^(--set|-F|--file|-b|--boot)(=|$)/.test(a))) return worst(verdict, ask("hostname changes the machine name"));
    if (args.some((a) => !a.startsWith("-"))) return worst(verdict, ask("hostname with an operand changes the machine name"));
  }
  if (name === "dmesg" && args.some((a) => a === "-c" || a === "-C" || a === "--clear" || a === "--read-clear" || /^-[a-zA-Z]*c/.test(a))) return worst(verdict, ask("dmesg clears the kernel log"));
  if (name === "ps") {
    const env = args.some((a) => (a.startsWith("-") ? /^-[a-zA-Z]*w[a-zA-Z]*$/.test(a) && /e/.test(a) : /e/.test(a)));
    if (env) return worst(verdict, classify("prints environment variables, which can hold tokens"));
  }
  if (DNS_QUERY.has(name)) {
    const bad = dnsEncoded(args);
    if (bad) return worst(verdict, outwardClassify(`may encode data in a DNS name: ${bad}`));
  }

  if (name === "rm") return worst(verdict, rm(args, scope));
  if (name === "dd") {
    const of = args.find((a) => a.startsWith("of="))?.slice(3);
    if (of === undefined) return worst(verdict, classify("dd"));
    const p = resolveWord(of, scope);
    if (p && /^\/dev\//.test(p) && !DEV_SINKS.test(p)) return deny(`dd writes to the device ${of}`);
    if (isPiFile(p, scope)) return worst(verdict, piAsk(`dd writes Pi's own files: ${of}`));
    return worst(verdict, isLocal(p, scope) ? classify("dd") : outside(`dd writes outside the working directory: ${of}`, p));
  }
  if ((name === "chmod" || name === "chown" || name === "chgrp") && hasFlag(args, "R", "--recursive")) {
    for (const t of operands(args).slice(1)) {
      const p = resolveWord(t, scope);
      if (p && isRootLike(p)) return deny(`${name} -R on ${t} would change a home or system directory`);
    }
  }
  if (name === "sed") return worst(verdict, sedVerdict(args, scope));
  if (name === "awk" || name === "gawk") return worst(verdict, awkVerdict(args, scope));
  if (WRITERS[name]) return worst(verdict, writeTargets(name, args, scope, !!cmd.heredoc && !cmd.expands));
  if (name === "tar" || name === "zip" || name === "unzip" || name === "gzip" || name === "gunzip" || name === "xz" || name === "zstd") {
    if (name === "tar" && args.some((a) => /^(--to-command|--checkpoint-action|--use-compress-program|--info-script|--new-volume-script)(=|$)/.test(a) || a === "-I" || /^-I./.test(a))) {
      return worst(verdict, outwardClassify("tar runs a command the rules cannot see"));
    }
    // Archives read and write paths given as operands and after -f / -C / -d. A change-directory or
    // destination flag writes where it names, even when that path is attached (-C/dir, -d/dir).
    const destDirs = name === "tar" ? optionArgs(args, "-C", "--directory") : name === "unzip" ? optionArgs(args, "-d") : [];
    for (const dir of destDirs) {
      const v = writePathVerdict(`${name} -${name === "tar" ? "C" : "d"}`, dir, scope);
      if (v && v.action !== "allow") return worst(verdict, v);
    }
    for (const a of withoutOptionValues(args, ...(name === "tar" ? ["-C", "--directory"] : name === "unzip" ? ["-d"] : [])).filter((x) => !x.startsWith("-"))) {
      if (!isLocal(resolveWord(a, scope), scope)) return worst(verdict, classify(`${name} with a path outside the working directory`));
    }
    return verdict;
  }
  if (name === "curl" || name === "wget") return worst(verdict, network(name, args, scope));
  if (name === "find") return worst(verdict, find(args, scope));
  if (name === "git") return worst(verdict, git(args, scope));
  if (name === "gh") return worst(verdict, gh(args));
  if (name === "llamastash") return worst(verdict, llamastash(args));
  if (name === "crontab") return worst(verdict, args.length === 1 && args[0] === "-l" ? ALLOW : ask("crontab changes scheduled jobs"));
  if (name === "sysctl") return worst(verdict, args.some((a) => a === "-w" || a.includes("=")) ? ask("sysctl changes kernel settings") : ALLOW);
  if (name === "pacman" || name === "paru" || name === "yay") {
    return worst(verdict, /^-(Q|Ss|Si|Sl|Sg|F|T|V|h)/.test(args[0] ?? "-h") ? ALLOW : ask(`${name} changes system packages`));
  }
  if (name === "npm" && operands(args)[0] === "config" && ["set", "delete", "edit"].includes(operands(args)[1])) {
    return worst(verdict, ask("npm config changes settings outside the project"));
  }
  if (name === "docker") {
    const [group, action] = operands(args);
    if (group === "compose" || group === "buildx") return worst(verdict, classify(`docker ${group}`));
    if (group && Object.hasOwn(DOCKER_GROUPS, group)) {
      return worst(verdict, DOCKER_GROUPS[group].split(" ").includes(action) ? ALLOW : classify(`docker ${group} ${action ?? ""}`.trim()));
    }
  }
  // Package tools reach the network for the packages they are given. A URL, a git address or a
  // registry flag names where the code comes from, in any subcommand and in any position.
  const moduleTool = /^python3?$/.test(name) && args[0] === "-m" && args[1] ? args[1] : name;
  const moduleArgs = moduleTool === name ? args : args.slice(2);
  if (["pip", "pip3", "npm", "pnpm", "yarn", "bun", "cargo", "go", "uv"].includes(moduleTool)) {
    const from = moduleArgs.find((a) => /^(git\+|https?:|ssh:|git:|github:|gitlab:|bitbucket:|file:)/i.test(a) || /^[\w.-]+\/[\w.-]+#/.test(a) || /^git@/.test(a) || /^(--index-url|--extra-index-url|--registry|--git)(=|$)/.test(a) || (/^pip/.test(moduleTool) && /^-i(=|$)/.test(a)));
    if (from) return worst(verdict, ask(`${moduleTool} fetches code from outside the registry: ${clip80(from)}`));
    if (moduleTool === "go") {
      const sub = operands(moduleArgs)[0];
      // go env -w writes the user's Go environment file, outside the project.
      if (sub === "env" && moduleArgs.some((a) => /^-[a-zA-Z]*w[a-zA-Z]*$/.test(a))) return worst(verdict, ask("go env -w writes the user's Go environment file outside the project"));
      // A module path with a host and a dot, or a version, is fetched from outside the registry.
      if (sub === "install" || sub === "get") {
        const remote = operands(moduleArgs).slice(1).find((a) => /^[\w.-]+\.[a-z]{2,}\//i.test(a) || /^[^/]+@[^/]+/.test(a));
        if (remote) return worst(verdict, ask(`go ${sub} fetches a module from outside the registry: ${clip80(remote)}`));
      }
    }
  }
  if (SUBCOMMANDS[name]) return worst(verdict, subcommand(name, args));
  if (READ_ONLY.has(name) || DEV_TOOLS.has(name)) return verdict;
  if (/^python3?$/.test(name) && args[0] === "-m" && PY_MODULES.has(args[1]) && !cmd.heredoc) {
    // The module reads and writes like the tool of the same name: json.tool takes an input and an
    // output operand, and the formatters rewrite the paths they are given. Credential reads were
    // already checked above, so this must not return early.
    const module = args[1];
    const rest = args.slice(2);
    if (module === "json.tool") {
      const files = operands(rest);
      const out = files.length >= 2 ? files[1] : undefined;
      if (out !== undefined) {
        const v = writePathVerdict("python -m json.tool", out, scope);
        if (v) verdict = worst(verdict, v);
      }
    }
    if (FORMATTERS[module]) {
      const v = formatterVerdict(module, rest, scope);
      if (v) verdict = worst(verdict, v);
    }
    return verdict;
  }
  if (INTERPRETERS.has(name)) {
    // `python3 scripts/x.py`: the script is the first argument. Inline code (-c, -e, a heredoc) stays with the model.
    const script = !cmd.heredoc && args[0] && !args[0].startsWith("-") ? runFile(args[0], args.slice(1), scope) : undefined;
    return worst(verdict, script ?? classify(`runs code with ${name}`));
  }
  // A program named by its path, such as ./scripts/build.sh or target/debug/app.
  if (argv[0].includes("/")) {
    const program = runFile(argv[0], args, scope);
    if (program) return worst(verdict, program);
  }
  return worst(verdict, { ...classify(`unknown command ${name}`), pattern: allowPattern(argv) });
}

// The allow pattern a confirm prompt offers for a command the rules do not know: the command
// and its subcommand or first flag, such as `terraform plan *`. None for a program named by
// path, whose name says nothing about what it is.
// For an ask: the subcommand, plus the word that says what changes for `gh pr edit *`,
// `git config --global *` and `git remote add *`. None when the first word is a flag or an
// operand, for root, for `gh api`, and for programs whose arguments are what they send: the
// pattern would cover the next call's flags and files too, such as `curl -sS -d @.env`.
const NO_ASK_PATTERN = new Set(["sudo", "doas", "curl", "wget", "scp", "rsync", "sftp", "ftp", "nc", "ncat", "netcat", "socat", "ssh", "telnet", "http", "https", "xh", "rclone"]);
function askPattern(argv: string[]): string | undefined {
  const [program, sub = "", next = ""] = argv;
  if (!/^[\w.+-]+$/.test(program ?? "") || NO_ASK_PATTERN.has(program) || !/^[a-z][\w-]*$/.test(sub)) return undefined;
  if (program === "gh" && sub === "api") return undefined;
  const third = program === "gh" ? /^[a-z][\w-]*$/.test(next) : program === "git" && ["config", "remote"].includes(sub) && /^(--)?[a-z][\w-]*$/.test(next);
  return `${program} ${sub}${third ? ` ${next}` : ""} *`;
}

function allowPattern(argv: string[]): string | undefined {
  if (!/^[\w.+-]+$/.test(argv[0])) return undefined;
  const first = argv[1] !== undefined && /^(-{1,2})?[A-Za-z][\w-]*$/.test(argv[1]) ? ` ${argv[1]}` : "";
  return `${argv[0]}${first} *`;
}

// ---- whole tool calls ----

const FORK_BOMB = /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/;
// A download piped into a shell, or into an interpreter that reads its program from stdin.
// `curl ... | python3 -c "..."` is not one: the download is the program's input.
const PIPE_TO_SHELL = /\b(curl|wget)\b[^|;&\n]*\|\s*(sudo\s+)?(env\s+)?(ba|z|da|k)?sh\b|\b(curl|wget)\b[^|;&\n]*\|\s*(python3?|node|perl|ruby)\s*(-\s*)?($|[|;&\n)])/;
// An ssh call next to a shell or interpreter on this machine may feed it what the remote host
// sends, which nothing here has read. The trusted-host fast path does not apply then.
const LOCAL_RUNNERS = /^(ba|z|da|k|fi)?sh$|^(python[\d.]*|node|perl|ruby|pwsh|powershell|eval|source|\.|xargs)$/;
// True when a command reaches other machines only through ssh to hosts in remote.trustedHosts,
// with plain options, and feeds nothing the host sends into local code. Such a change (not a
// read, which the rules already allow) may go to the second opinion as a step of the task.
export function onlyTrustedSsh(command: string, scope: Scope): boolean {
  if (!scope.trustedHosts?.length) return false;
  const parsed = parse(command);
  if (sshFeedsLocalCode(parsed)) return false;
  const ssh = parsed.cmds.map((c) => unwrap(c.argv)).filter((argv) => path.basename(argv[0] ?? "") === "ssh");
  return ssh.length > 0 && ssh.every((argv) => !!trustedTarget(argv.slice(1), scope));
}

function sshFeedsLocalCode(parsed: Parsed): boolean {
  const names = parsed.cmds.map((c) => path.basename(unwrap(c.argv)[0] ?? ""));
  return names.includes("ssh") && names.some((n) => LOCAL_RUNNERS.test(n));
}

// `NAME=value` words of a command that only sets variables (or exports them).
function assignments(argv: string[]): [string, string][] | undefined {
  const words = argv[0] === "export" ? argv.slice(1) : argv;
  const pairs = words.map((w) => /^([A-Za-z_]\w*)=(.*)$/s.exec(w));
  return words.length && pairs.every(Boolean) ? pairs.map((m) => [m![1], m![2]]) : undefined;
}

function evaluateParsed(parsed: Parsed, scope: Scope, depth: number): Verdict {
  let verdict: Verdict = parsed.opaque ? classify("shell syntax the rules do not model") : ALLOW;
  // Relative paths are only trusted while the working directory is known.
  const local: Scope = { ...scope, vars: new Map(), loopVars: new Set() };
  const hasCd = parsed.cmds.some((c) => ["cd", "pushd", "popd"].includes(c.argv[0]));
  if (hasCd && parsed.grouped) local.cwd = undefined;
  // A variable is followed only when the command names it once, in the assignment, and at the
  // top level: a branch, a loop, `read` or a second assignment could give it another value. A
  // nested shell does not see unexported variables, so it starts with none.
  const words = parsed.cmds.flatMap((c) => [...c.argv, ...c.out, ...(c.in ?? [])]).join(" ");
  const namedOnce = (name: string) => (words.match(new RegExp(`(^|[^$\\w{])${name}(?!\\w)`, "g")) ?? []).length === 1;
  const track = depth === 0 && !parsed.grouped;
  // The patterns of the parts that decide. A prompt offers one only when it covers them all.
  const patterns = new Set<string | undefined>(parsed.opaque ? [undefined] : []);
  for (const cmd of parsed.cmds) {
    const [kw, name, inKw, ...values] = cmd.argv;
    if (track && kw === "for" && inKw === "in" && values.length > 0 && values.every((w) => /^[\w./@:+-]+$/.test(w) || /^https?:\/\/[^\s$`]+$/.test(w)) && namedOnce(name)) local.loopVars!.add(name);
    const part = simple(cmd, local, depth);
    if (part.action === "classify" || part.action === "ask") patterns.add(part.pattern);
    verdict = worst(verdict, part);
    if (verdict.action === "deny") return verdict;
    if (cmd.subshell) {
      if (["cd", "pushd", "popd"].includes(cmd.argv[0])) local.cwd = undefined;
    } else if (cmd.argv[0] === "cd" && local.cwd) {
      local.cwd = cmd.argv.length === 2 ? resolveWord(cmd.argv[1], local) : cmd.argv.length === 1 ? HOME : undefined;
    } else if (cmd.argv[0] === "pushd" && local.cwd && cmd.argv.length === 2) {
      // pushd with one directory moves the shell there, like cd.
      local.cwd = resolveWord(cmd.argv[1], local);
    } else if (cmd.argv[0] === "pushd" || cmd.argv[0] === "popd") local.cwd = undefined;
    for (const [name, value] of (track && !cmd.subshell && assignments(cmd.argv)) || []) {
      // A relative literal is kept as text and resolved where it is used, so a later `cd` is
      // honoured the way the shell honours it. A value built at run time is only followed when
      // it expands to an absolute path.
      if (/[$`]/.test(value)) {
        const expanded = expandVars(value, local);
        const p = (/^(\/|~\/|~$)/.test(expanded) || path.isAbsolute(expanded)) ? resolveWord(value, local) : undefined;
        if (p && namedOnce(name)) local.vars!.set(name, p);
      } else if (namedOnce(name)) {
        local.vars!.set(name, value);
      }
    }
  }
  return verdict.pattern && patterns.size > 1 ? { ...verdict, pattern: undefined } : verdict;
}

// A guarded path written anywhere in the command text, in either slash style, any case.
function mentionsGuarded(text: string, scope: Scope): string | undefined {
  const norm = (p: string) => p.replace(/\\+/g, "/").replace(/^\/([a-z])\//i, "$1:/").toLowerCase();
  const hay = norm(text);
  return scope.guarded.map(norm).find((g) => g.length > 3 && hay.includes(g));
}

export function bashVerdict(command: string, scope: Scope): Verdict {
  if (FORK_BOMB.test(command)) return deny("fork bomb");
  const parsed = parse(command);
  const trusting = !!scope.trustedHosts?.length && sshFeedsLocalCode(parsed);
  const verdict = evaluateParsed(parsed, trusting ? { ...scope, trustedHosts: undefined } : scope, 0);
  if (verdict.action === "deny") return verdict;
  const named = verdict.action === "classify" && mentionsGuarded(command, scope);
  const guarded = named ? worst(verdict, guardAsk(`code that names the auto-mode guard's own files: ${named}`)) : verdict;
  return forDecider(PIPE_TO_SHELL.test(command) ? worst(guarded, criticalAsk("downloads code and runs it")) : guarded, scope);
}

// PowerShell: the Bash parser does not read the language, so a small vocabulary stands in for it.
// A line runs when every command position is a read-only cmdlet and no writer or executor appears
// anywhere; anything the vocabulary does not know asks. `Get-Volume | Select-Object` runs,
// `Set-Content`, `Remove-Item`, `Out-File`, `Invoke-*`, redirection and encoded commands ask.
const PS_READERS = new Set([
  "test-path", "resolve-path", "split-path", "join-path", "convert-path", "measure-object",
  "compare-object", "join-string", "group-object", "sort-object", "select-object", "select-string",
  "select-xml", "where-object", "foreach-object", "measure-command",
  "out-string", "out-host", "out-null",
  "write-output", "write-host", "write-verbose", "write-debug", "write-information", "write-warning", "write-error",
  "convertto-json", "convertto-csv", "convertto-xml", "convertto-html", "convertfrom-json", "convertfrom-csv", "convertfrom-stringdata",
  "foreach", "for", "while", "if", "else", "elseif", "try", "catch", "finally", "switch", "return",
  "set-strictmode", "set-location", "set-psdebug",
]);
const PS_READER_PREFIXES = ["get-", "format-"];
// ForEach-Object member names that only read a property.
const PS_SAFE_MEMBERS = new Set([
  "name", "fullname", "basename", "extension", "length", "count", "id", "processname", "path", "directory",
  "directoryname", "lastwritetime", "creationtime", "mode", "status", "displayname", "value", "key", "keys",
  "values", "version", "source", "definition", "line", "linenumber", "matches", "tostring", "trim", "toupper", "tolower",
]);
// .NET types whose static members only compute: [math]::Round, [string]::Join, [convert]::ToInt32.
// Any other [type]::member can touch files, the registry or the network, so it asks.
const PS_PURE_TYPES = new Set([
  "math", "string", "convert", "int", "int16", "int32", "int64", "uint32", "uint64", "long", "double", "single",
  "decimal", "datetime", "datetimeoffset", "timespan", "guid", "char", "bool", "boolean", "byte", "version", "regex",
]);
// .NET and object methods that change something: $file.Delete(), (Get-Item x).MoveTo(y).
const PS_DESTRUCTIVE_METHODS = /\.\s*(delete|deletedirectory|move|moveto|copy|copyto|writeall\w+|appendall\w+|create|createdirectory|openwrite|setattributes|remove|unlink|rename|truncate|kill|terminate|stop|start|restart|pause|invoke|put|setvalue|deletevalue|deletesubkey\w*|uninstall|install|encrypt|decrypt)\s*\(/i;
// Cmdlets that change something, whatever their noun.
const PS_WRITERS = /(?:^|[\s|;(){}\[\]])(set|new|remove|clear|add|move|copy|rename|out-file|tee|export|import|start|stop|restart|suspend|resume|enable|disable|register|unregister|install|uninstall|update|publish|save|backup|restore|grant|revoke|initialize|resize|invoke|format-volume|mount|dismount|write-eventlog|exit)-[\w]+/i;
// Aliases, as canonical cmdlets. Writers are caught by PS_WRITERS after the mapping.
const PS_ALIASES: Record<string, string> = {
  ls: "get-childitem", dir: "get-childitem", gci: "get-childitem", gi: "get-item", cat: "get-content",
  gc: "get-content", type: "get-content", ps: "get-process", gps: "get-process", gv: "get-variable",
  gsv: "get-service", gcm: "get-command", gm: "get-member", gl: "get-location", pwd: "get-location",
  gdr: "get-psdrive", ghy: "get-history", gsn: "get-pssession",
  echo: "write-output", write: "write-output", where: "where-object", "?": "where-object", "%": "foreach-object",
  group: "group-object", sort: "sort-object", select: "select-object", compare: "compare-object",
  ft: "format-table", fl: "format-list", fw: "format-wide",
  rm: "remove-item", del: "remove-item", erase: "remove-item", rd: "remove-item", rmdir: "remove-item",
  si: "set-item", sc: "set-content", ac: "add-content", ni: "new-item",
  cp: "copy-item", copy: "copy-item", cpi: "copy-item", mv: "move-item", move: "move-item", mi: "move-item",
  rni: "rename-item", ren: "rename-item", sal: "set-alias", nal: "new-alias", rv: "remove-variable",
  iex: "invoke-expression", icm: "invoke-command", iwr: "invoke-webrequest", irm: "invoke-restmethod",
  kill: "stop-process", spps: "stop-process", saps: "start-process", start: "start-process",
};

// ---- PowerShell path expressions ----

// Split a PowerShell segment into words, keeping a parenthesised expression or a quoted string
// together: `-Path (Join-Path $HOME '.ssh/*')` is three words, not seven.
function psExprWords(text: string): string[] {
  const out: string[] = [];
  let word = "";
  let quote: string | undefined;
  let depth = 0;
  let has = false;
  for (const c of text) {
    if (quote) {
      word += c;
      if (c === quote) quote = undefined;
      continue;
    }
    if (c === "'" || c === '"') { quote = c; word += c; has = true; continue; }
    if (c === "(") { depth++; word += c; has = true; continue; }
    if (c === ")") { if (depth > 0) depth--; word += c; has = true; continue; }
    if (/\s/.test(c) && depth === 0) {
      if (has) out.push(word);
      word = "";
      has = false;
      continue;
    }
    word += c;
    has = true;
  }
  if (has) out.push(word);
  return out;
}

function psUnquote(s: string): string | undefined {
  const t = s.trim();
  if (t.length < 2 || (t[0] !== "'" && t[0] !== '"')) return undefined;
  const quote = t[0];
  for (let i = 1; i < t.length; i++) {
    if (t[i] === "`") { i++; continue; }
    if (t[i] === quote) return i === t.length - 1 ? t.slice(1, -1) : undefined;
  }
  return undefined;
}

function psBalanced(s: string): boolean {
  let depth = 0;
  let quote: string | undefined;
  for (const c of s) {
    if (quote) { if (c === quote) quote = undefined; continue; }
    if (c === "'" || c === '"') quote = c;
    else if (c === "(") depth++;
    else if (c === ")" && --depth < 0) return false;
  }
  return depth === 0 && quote === undefined;
}

function psSplitTop(s: string, op: string): string[] {
  const out: string[] = [];
  let start = 0;
  let quote: string | undefined;
  let depth = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (quote) { if (c === quote) quote = undefined; continue; }
    if (c === "'" || c === '"') quote = c;
    else if (c === "(") depth++;
    else if (c === ")") depth--;
    else if (depth === 0 && s.startsWith(op, i)) {
      out.push(s.slice(start, i));
      start = i + op.length;
      i += op.length - 1;
    }
  }
  out.push(s.slice(start));
  return out;
}

function psPlainLiteral(word: string): boolean {
  const s = word.trim();
  const unquoted = psUnquote(s);
  if (unquoted !== undefined) return !(s.startsWith('"') && /[$`]/.test(unquoted));
  return !/[$`()~+]/.test(s);
}

function psDirExists(p: string | undefined): boolean {
  return !!p && !!fs.statSync(p, { throwIfNoEntry: false })?.isDirectory();
}

// Fold the simple expressions the corpus uses: a quoted literal, a variable assigned earlier, ~,
// $HOME, $env:USERPROFILE, Join-Path and `+` concatenation. Anything else stays unknown.
function psFoldPath(expr: string, vars: Map<string, string>): string | undefined {
  let s = expr.trim();
  if (!s) return undefined;
  while (s.startsWith("(") && s.endsWith(")") && psBalanced(s.slice(1, -1))) s = s.slice(1, -1).trim();
  const quoted = psUnquote(s);
  if (quoted !== undefined) {
    // Single quotes are literal; double quotes expand the home variables PowerShell knows.
    if (s.startsWith('"')) {
      const expanded = quoted.replace(/\$\{?home\}?/gi, HOME).replace(/\$\{?env:userprofile\}?/gi, HOME);
      return /[$`]/.test(expanded) ? undefined : expanded;
    }
    return quoted;
  }
  if (/^\$[\w:]+$/i.test(s)) {
    const name = s.toLowerCase();
    if (name === "$home" || name === "$env:userprofile") return HOME;
    if (name === "$env:temp" || name === "$env:tmp") return os.tmpdir();
    return vars.get(name);
  }
  if (s === "~") return HOME;
  if (/^~[\\/]/.test(s)) return path.join(HOME, s.slice(2));
  // A home variable inside a larger path: $HOME/.aws, $env:USERPROFILE\Documents.
  s = s.replace(/\$\{?home\}?/gi, HOME).replace(/\$\{?env:userprofile\}?/gi, HOME);
  const join = /^join-path\b/i.exec(s);
  if (join) {
    const terms = psExprWords(s.slice(join[0].length).trim());
    if (!terms.length) return undefined;
    let out = psFoldPath(terms[0], vars);
    if (out === undefined) return undefined;
    for (const term of terms.slice(1)) {
      const part = psFoldPath(term, vars);
      if (part === undefined) return undefined;
      out = path.join(out, part);
    }
    return out;
  }
  const plus = psSplitTop(s, "+");
  if (plus.length > 1) {
    let out = "";
    for (const part of plus) {
      const value = psFoldPath(part, vars);
      if (value === undefined) return undefined;
      out += value;
    }
    return out;
  }
  if (/[$`]/.test(s) || /[()]/.test(s)) return undefined;
  return s.replace(/\\/g, "/");
}

// Variables assigned once in the same PowerShell line. A second assignment makes the value
// unknown, so a later reader of that variable asks instead of being allowed.
function psAssignments(text: string): Map<string, string> {
  const counts = new Map<string, number>();
  const vars = new Map<string, string>();
  for (const m of text.matchAll(/(?:^|[;\n])\s*\$([A-Za-z_][\w:]*)\s*=\s*([^;\n]+)/g)) {
    const name = `$${m[1].toLowerCase()}`;
    const count = (counts.get(name) ?? 0) + 1;
    counts.set(name, count);
    const folded = psFoldPath(m[2], vars);
    if (count === 1 && folded !== undefined) vars.set(name, folded);
    else vars.delete(name);
  }
  return vars;
}

// Reader cmdlets whose argument names a file or a directory.
const PS_PATH_READERS = new Set([
  "get-content", "get-childitem", "get-item", "get-filehash", "get-acl", "get-command", "get-psdrive",
  "get-location", "select-string", "select-xml", "get-help", "resolve-path", "test-path",
]);
const PS_DIR_READERS = new Set(["get-content", "get-childitem", "select-string", "select-xml"]);

// The path arguments of a reader. A -Path family flag names them explicitly; otherwise the first
// positional is the path (Select-String takes its pattern first).
function psReaderPaths(words: string[], canonical: string): string[] {
  const paths: string[] = [];
  const positionals: string[] = [];
  let sawPath = false;
  for (let i = 1; i < words.length; i++) {
    const word = words[i];
    const eq = word.indexOf("=");
    if (word.startsWith("-") && eq > 1) {
      const flag = word.slice(0, eq).toLowerCase();
      if (PS_PATH_FLAGS.has(flag)) { paths.push(word.slice(eq + 1)); sawPath = true; }
      continue;
    }
    if (/^-[a-z][\w-]*$/i.test(word)) {
      const flag = word.toLowerCase();
      if (PS_PATH_FLAGS.has(flag)) {
        if (words[i + 1] !== undefined) paths.push(words[++i]);
        sawPath = true;
      } else if (PS_VALUE_FLAGS.has(flag) || flag === "-pattern" || flag === "-algorithm") i++;
      continue;
    }
    if (!word.startsWith("-")) positionals.push(word);
  }
  if (!sawPath) {
    const at = canonical === "select-string" && positionals.length > 1 ? 1 : 0;
    if (positionals[at] !== undefined) paths.push(positionals[at]);
  }
  return paths;
}

function psReadPathVerdict(word: string, canonical: string, scope: Scope | undefined, vars: Map<string, string>): Verdict | undefined {
  const folded = psFoldPath(word, vars);
  const plain = psPlainLiteral(word);
  const fromVar = /^\$[\w:]+$/i.test(word.trim()) && vars.has(word.trim().toLowerCase());
  if (folded === undefined) return plain || fromVar ? undefined : classify("PowerShell reads a path built from an expression");
  const p = scope ? resolveWord(folded, scope) : path.isAbsolute(folded) ? realish(folded) : undefined;
  if (p && scope && isGuarded(p, scope)) return guardAsk(`PowerShell reads the auto-mode guard's own files: ${word}`);
  if (isSecretPath(expandHome(folded)) || (p && isSecretPath(p))) return criticalAsk(`PowerShell reads a credential file: ${word}`);
  if (PS_DIR_READERS.has(canonical) && (isCredentialDirectory(expandHome(folded)) || (p && isCredentialDirectory(p)))) {
    const stat = p ? fs.statSync(p, { throwIfNoEntry: false }) : fs.statSync(expandHome(folded), { throwIfNoEntry: false });
    if (!stat || stat.isDirectory()) return criticalAsk(`PowerShell reads a directory that holds credentials: ${word}`);
  }
  if (!plain && !fromVar && p && scope && !isLocal(p, scope)) return classify(`PowerShell reads a path built from an expression: ${word}`);
  return undefined;
}

function psCopySources(words: string[]): string[] {
  const paths: string[] = [];
  const positionals: string[] = [];
  let destination: string | undefined;
  for (let i = 1; i < words.length; i++) {
    const word = words[i];
    const eq = word.indexOf("=");
    if (word.startsWith("-") && eq > 1) {
      const flag = word.slice(0, eq).toLowerCase();
      if (flag === "-destination") destination = word.slice(eq + 1);
      else if (PS_PATH_FLAGS.has(flag)) paths.push(word.slice(eq + 1));
      continue;
    }
    if (/^-[a-z][\w-]*$/i.test(word)) {
      const flag = word.toLowerCase();
      if (flag === "-destination") { if (words[i + 1] !== undefined) destination = words[++i]; }
      else if (PS_PATH_FLAGS.has(flag)) { if (words[i + 1] !== undefined) paths.push(words[++i]); }
      else if (PS_VALUE_FLAGS.has(flag)) i++;
      continue;
    }
    if (!word.startsWith("-")) positionals.push(word);
  }
  if (destination !== undefined && positionals.length > 1) positionals.pop();
  else if (destination === undefined && positionals.length > 1) positionals.pop();
  const sources = [...paths, ...positionals];
  return sources.filter((s) => s !== destination);
}

function psCopySourceVerdict(word: string, scope: Scope | undefined, vars: Map<string, string>): Verdict | undefined {
  const folded = psFoldPath(word, vars);
  if (folded === undefined) return classify("PowerShell copies from a path built from an expression");
  const p = scope ? resolveWord(folded, scope) : path.isAbsolute(folded) ? realish(folded) : undefined;
  if (p && scope && isGuarded(p, scope)) return guardAsk(`PowerShell copies the auto-mode guard's own files: ${word}`);
  if (isSecretPath(expandHome(folded)) || (p && isSecretPath(p)) || (p && psDirExists(p) && isCredentialDirectory(p))) return criticalAsk(`PowerShell copies a credential file: ${word}`);
  if (p && scope && !isLocal(p, scope)) return classify(`PowerShell copies from outside the working directory: ${word}`);
  return undefined;
}

// New-Item's other end: a symbolic link, junction or hard link makes a later project-looking path
// reach whatever it names, so the target is checked while it is still visible.
function psLinkVerdict(word: string, scope: Scope | undefined, vars: Map<string, string>): Verdict | undefined {
  const folded = psFoldPath(word, vars);
  if (folded === undefined) return classify("PowerShell creates a link to a path built from an expression");
  const p = scope ? resolveWord(folded, scope) : path.isAbsolute(folded) ? realish(folded) : undefined;
  if (p && scope && isGuarded(p, scope)) return guardAsk(`PowerShell links to the auto-mode guard's own files: ${word}`);
  if (p && scope && isPiFile(p, scope)) return guardAsk(`PowerShell links to Pi's own files: ${word}`);
  if (isSecretPath(expandHome(folded)) || (p && isSecretPath(p)) || (p && psDirExists(p) && isCredentialDirectory(p)) || (p && isRootLike(p) && !inTmp(p))) {
    return criticalAsk(`PowerShell links to a credential location or its parent: ${word}`);
  }
  if (p && scope && !isLocal(p, scope)) return outside(`PowerShell links to a target outside the working directory: ${word}`, p);
  return undefined;
}

function psReadVerdict(text: string, scope: Scope | undefined, vars: Map<string, string>): Verdict | undefined {
  let verdict: Verdict | undefined;
  for (const segment of psSegments(text)) {
    const words = psExprWords(segment);
    if (!words.length) continue;
    if (words[0].startsWith("$") && words[1] === "=") continue;
    const canonical = PS_ALIASES[words[0].toLowerCase()] ?? words[0].toLowerCase();
    if (canonical === "copy-item" || canonical === "move-item") {
      for (const source of psCopySources(words)) {
        const v = psCopySourceVerdict(source, scope, vars);
        if (v) verdict = verdict ? worst(verdict, v) : v;
      }
    } else if (PS_PATH_READERS.has(canonical)) {
      for (const word of psReaderPaths(words, canonical)) {
        const v = psReadPathVerdict(word, canonical, scope, vars);
        if (v) verdict = verdict ? worst(verdict, v) : v;
      }
    }
  }
  return verdict;
}

export function powershellVerdict(command: string, _scope?: Scope): Verdict {
  const text = command.replace(/\r/g, "");
  // Text inside quotes cannot run, so only the bare text decides what runs.
  // "…$(cmd)…" runs cmd: judge each subexpression with the same vocabulary.
  for (const str of text.replace(/'[^']*'/g, "''").match(/"[^"]*"/g) ?? []) {
    for (let at = str.indexOf("$("); at >= 0; at = str.indexOf("$(", at + 2)) {
      let depth = 0, end = at + 1;
      for (; end < str.length; end++) { if (str[end] === "(") depth++; else if (str[end] === ")" && --depth === 0) break; }
      const body = str.slice(at + 2, end).trim();
      // A variable or property read: "$($x.Count)", "$($_.Length)".
      if (/^\$[\w:]+(\.\w+)*$/.test(body)) continue;
      const inner = powershellVerdict(body, _scope);
      if (inner.action !== "allow") return criticalAsk(`PowerShell runs a subexpression inside a string: ${inner.reason}`);
    }
  }
  const bare = text.replace(/'[^']*'/g, "''").replace(/"[^"]*"/g, '""');
  const bareWriters = bare.replace(/\bset-(strictmode|location|psdebug)\b/gi, "safe");
  // File writes are allowed only when every literal target is provably inside the project or
  // temp. Without a scope, or with a target the vocabulary cannot read, the critical ask stays.
  const readVerdict = psReadVerdict(text, _scope, psAssignments(text));
  const writes = psWrites(text, bareWriters, _scope);
  if (writes.found && !writes.ok) return worst(readVerdict ?? ALLOW, writes.verdict!);
  // A credential read or a guard-file read is the stricter answer. A classify from the path
  // vocabulary waits, so a later critical check can still win.
  if (readVerdict?.action === "ask") return readVerdict;
  const writesOk = writes.found && writes.ok;
  // The environment holds tokens. Printing one of them puts it in the transcript; PATH, HOME
  // and NODE_ENV are settings, not credentials.
  for (const m of text.matchAll(/\$\{?env:(\w+)\}?/gi)) {
    if (isSecretEnvName(m[1])) return classify("prints environment variables, which can hold tokens");
  }
  if (/\b(get-childitem|gci|dir|ls|gi)\b[^|;\n]*\s(env:|environment::)/i.test(bare)) return classify("prints environment variables, which can hold tokens");
  if (/\b(iex|invoke-expression|invoke-command|icm)\b/i.test(bare) || /-e(nc|ncodedcommand)?\b/i.test(bare)) return criticalAsk("PowerShell evaluates or runs an encoded command");
  // A method call or a static .NET call is outside the cmdlet vocabulary; only pure types pass.
  if (PS_DESTRUCTIVE_METHODS.test(bare)) return criticalAsk("PowerShell calls a method that changes files");
  if (/[)\]]\s*\.\s*\w+\s*\(/.test(bare)) return criticalAsk("PowerShell calls a method on an expression");
  for (const call of bare.matchAll(/\[([\w.]+)\]\s*::/g)) {
    const type = call[1].toLowerCase().replace(/^system\./, "");
    // Reading a setting from the environment is a read, unless the name holds a token.
    if (type === "environment" && /\[(?:system\.)?environment\]\s*::\s*getenvironmentvariable\s*\(\s*''/i.test(bare) && [...text.matchAll(/getenvironmentvariable\s*\(\s*["']([^"']+)/gi)].every((m) => !isSecretEnvName(m[1])) && !/\[(?:system\.)?environment\]\s*::\s*(?!getenvironmentvariable)/i.test(bare)) continue;
    if (!PS_PURE_TYPES.has(type)) return _scope ? classify(`PowerShell calls ${call[1]}`) : criticalAsk(`PowerShell calls ${call[1]}`);
  }
  if (!writesOk && (/(^|[^>])(\d|\*)?>>?\s*(?!\$null\b)[^&\s]/i.test(bare) || /\b(out-file|tee-object)\b/i.test(bare))) return criticalAsk("PowerShell writes a file");
  // ForEach-Object given a member name calls it: `gci | % Delete`, `gsv x | % Stop`. Only plain
  // property reads pass.
  for (const m of bare.matchAll(/(?:^|[|;\s(])(?:%|foreach-object|foreach)\s+(?:-membername\s+)?([A-Za-z_]\w*)/gi)) {
    if (!PS_SAFE_MEMBERS.has(m[1].toLowerCase())) return criticalAsk(`PowerShell calls the member ${m[1]} on each object`);
  }
  // Setting a property changes the object: `$_.Attributes = 'Hidden'`, `$f.IsReadOnly = $true`.
  if (/\$[\w:]+(\.\w+)+\s*[+\-*/]?=(?!=)/.test(bare)) return criticalAsk("PowerShell sets a property");
  // Credentials: the same files a Bash read would ask for, plus the secret and clipboard stores.
  if (/\b(get-credential|get-secret|get-storedcredential|get-clipboard)\b/i.test(bare)) return criticalAsk("PowerShell reads a credential store");
  for (const word of text.split(/[\s|;(){}]+/)) {
    const w = word.replace(/^['"]|['"]$/g, "").replace(/^(-[\w]+:)/, "").replace(/^\$(env:userprofile|home)\b/i, "~").replace(/\\/g, "/");
    if (_scope && w && !w.startsWith("-") && secretIn(w, _scope)) return criticalAsk(`PowerShell reads a credential file: ${w}`);
    if (!_scope && w && isSecretPath(expandHome(w))) return criticalAsk(`PowerShell reads a credential file: ${w}`);
  }
  // Set-StrictMode and Set-Location only change the shell itself, like cd.
  const writer = PS_WRITERS.exec(bareWriters);
  if (writer && !writesOk) return _scope ? ask(`PowerShell runs ${writer[0].trim()}`) : criticalAsk(`PowerShell runs ${writer[0].trim()}`);
  // A writer written as an alias (rm, sc, si, ni, cp, mv…) is a writer too.
  for (const word of bare.split(/[\s|;(){}[\]]+/)) {
    const canonical = PS_ALIASES[word.toLowerCase()];
    if (canonical && !PS_READERS.has(canonical) && !PS_READER_PREFIXES.some((p) => canonical.startsWith(p))) {
      if (writesOk) {
        const left = writes.aliases?.get(canonical) ?? 0;
        if (left > 0) {
          writes.aliases!.set(canonical, left - 1);
          continue;
        }
      }
      return criticalAsk(`PowerShell runs ${word} (${canonical})`);
    }
  }
  // The same pieces cut from the original text, quotes intact, when both cuts agree.
  const barePieces = bare.split(/\n|;|\|/);
  const quoted = psSplit(text);
  const aligned = quoted && quoted.length === barePieces.length ? quoted : undefined;
  let pieceAt = -1;
  for (const piece of barePieces) {
    pieceAt++;
    // Strip an assignment, then skip the pieces that are not a command: a hashtable entry, a
    // subexpression, a continuation of a block, a comment or a bare string. A bare variable is
    // a read ("$env:PATH" prints it) and a validated local writer is allowed with its write.
    const line = piece.trim().replace(/^\$[\w:]+(\[[^\]]*\])?\s*=\s*/, "");
    if (!line || /^[@({[}\])\'"#-]/.test(line) || /^[\w.'"]+=/.test(line) || /^\$(?:[\w:]+|\{[\w:]+\})(\.[\w]+)*$/.test(line)) continue;
    const word = line.split(/\s+/)[0].replace(/^microsoft\.[\w.]*\\/i, "").toLowerCase();
    const canonical = PS_ALIASES[word] ?? word;
    if (PS_READERS.has(canonical) || PS_READER_PREFIXES.some((p) => canonical.startsWith(p))) continue;
    if (writesOk && PS_LOCAL_WRITERS.has(canonical)) continue;
    // A native program (git, npm, node), not a cmdlet: the shell rules know what these do. Only a
    // plain line, since PowerShell syntax in it would be misread as bash.
    if (_scope && !/^[a-z]+-[a-z]/.test(word)) {
      const original = aligned ? aligned[pieceAt]?.trim() : text.split(/\n|;|\|/).map((p) => p.trim()).find((p) => p.toLowerCase().startsWith(word));
      if (original && (aligned ? psPlainNative(original) : !/[$@(){}`]/.test(original))) {
        const native = bashVerdict(original, _scope);
        if (native.action === "allow") continue;
        return native;
      }
    }
    return ask(`PowerShell ${word} needs review`);
  }
  return worst(readVerdict ?? ALLOW, ALLOW);
}

// PowerShell text cut at `;`, `|` and newlines outside quotes, or undefined when a quote is left
// open. Inside '…' a doubled '' is a quote; inside "…" a backtick escapes the next character.
function psSplit(text: string): string[] | undefined {
  const pieces: string[] = [];
  let quote = "", start = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quote === "'") {
      if (c === "'") { if (text[i + 1] === "'") i++; else quote = ""; }
    } else if (quote === '"') {
      if (c === "`") i++;
      else if (c === '"') quote = "";
    } else if (c === "'" || c === '"') quote = c;
    else if (c === ";" || c === "|" || c === "\n") {
      pieces.push(text.slice(start, i));
      start = i + 1;
    }
  }
  if (quote) return undefined;
  pieces.push(text.slice(start));
  return pieces;
}

// A native program line whose words a Bash parse reads the same way PowerShell passes them:
// single-quoted text is literal in both. What PowerShell would expand or Windows PowerShell 5.1
// would re-quote differently is refused: `$`, `@`, `(`, `{`, a backtick outside single quotes, a
// double quote or a '' inside them, an empty argument, a backslash before a closing quote.
function psPlainNative(line: string): boolean {
  let outside = "";
  for (let i = 0; i < line.length; i++) {
    if (line[i] !== "'") { outside += line[i]; continue; }
    const end = line.indexOf("'", i + 1);
    if (end < 0) return false;
    const inner = line.slice(i + 1, end);
    if (!inner || inner.includes('"') || line[end + 1] === "'" || inner.endsWith("\\")) return false;
    outside += "''";
    i = end;
  }
  return !/[$@(){}`]/.test(outside) && !/""|\\"/.test(outside);
}

/** A PowerShell command as the Bash text it is equivalent to, when it is only plain native
 * program lines (`ssh killian 'ls /srv'`, `git status`), else undefined. */
export function psAsBash(command: string): string | undefined {
  const text = command.replace(/\r/g, "");
  const pieces = psSplit(text);
  if (!pieces) return undefined;
  for (const piece of pieces) {
    const line = piece.trim();
    if (!line) continue;
    if (/^[a-z]+-[a-z]/i.test(line) || !psPlainNative(line)) return undefined;
  }
  return text;
}

// ---- scripts and inline programs a command runs ----

// What an action will run, found with the same parser the rules use. Pure: nothing here starts a
// process or touches the network. Paths are absolute; `inline` holds the code given to an
// interpreter or a shell, with a rough language name.
export interface RunTargets {
  scripts: string[];
  inline: { code: string; lang: string }[];
}

const RUN_INTERPRETERS: Record<string, string> = {
  node: "js", nodejs: "js", tsx: "ts", "ts-node": "ts", "ts-node-esm": "ts", "ts-node-script": "ts", esno: "ts", jiti: "ts",
  python: "python", python3: "python", perl: "perl", ruby: "ruby", php: "php", lua: "lua",
  deno: "js", bun: "js",
};
const RUN_PROGRAMS = new Set([...Object.keys(RUN_INTERPRETERS), "bash", "sh", "zsh", "dash", "ksh", "powershell", "pwsh"]);
// Options that take the next word as a value, so it is not a script file.
const RUN_VALUE_FLAGS = new Set([
  "-W", "-X", "-Q", "-c", "--config", "--import-map", "--cert", "--location", "-L", "--log-level", "--seed", "--v8-flags",
  "--ext", "--cwd", "--input-type", "--conditions", "--env-file", "--tsconfig", "--title", "--inspect-port",
]);

/** Every script file and inline program a shell command runs. It resolves scripts against the
 * tracked working directory, also behind `cd`, `timeout`, `bash -c`, pipes and `$(...)`. */
export function runTargets(command: string, scope: Scope): RunTargets {
  const out: RunTargets = { scripts: [], inline: [] };
  const seen = new Set<string>();
  const add = (p: string | undefined) => {
    if (p && !seen.has(p)) {
      seen.add(p);
      out.scripts.push(p);
    }
  };
  walkRuns(parse(command), scope, out, add, 0);
  return out;
}

function walkRuns(parsed: Parsed, scope: Scope, out: RunTargets, add: (p?: string) => void, depth: number) {
  if (depth > 5) return;
  const local: Scope = { ...scope };
  // A `cd` inside a command substitution only moves that subshell; the commands after it in the
  // substitution resolve against it, those after the substitution resolve against the outer cwd.
  let subCwd: string | undefined;
  for (const cmd of parsed.cmds) {
    const first = path.basename(cmd.argv[0] ?? "");
    const at = cmd.subshell ? subCwd ?? local.cwd : local.cwd;
    if (first === "cd" || first === "pushd" || first === "popd") {
      if (cmd.subshell) {
        subCwd = first === "cd" && cmd.argv.length === 2 ? resolveWord(cmd.argv[1], { ...local, cwd: at }) : undefined;
      } else if (first === "cd") {
        local.cwd = cmd.argv.length === 2 ? resolveWord(cmd.argv[1], local) : cmd.argv.length === 1 ? HOME : undefined;
        subCwd = undefined;
      } else {
        local.cwd = undefined;
        subCwd = undefined;
      }
      continue;
    }
    if (!cmd.subshell) subCwd = undefined;
    collectRuns(cmd.argv, { ...local, cwd: at }, cmd, out, add, depth);
  }
}

function collectRuns(argv: string[], scope: Scope, cmd: Simple, out: RunTargets, add: (p?: string) => void, depth: number) {
  if (depth > 5) return;
  let words = unwrap(argv);
  // sudo runs the rest of the line as root; its own options come first.
  while (words.length && /^(sudo|doas)$/i.test(path.basename(words[0]))) words = afterFlags(words.slice(1), /^-[ugCDhpRrTU]$/);
  if (!words.length) return;
  const program = words[0];
  const args = words.slice(1);
  const base = path.basename(program).toLowerCase();
  const name = base.replace(/\.(exe|cmd|bat)$/i, "");
  if (program === "." || name === "source") {
    const file = args.find((a) => !a.startsWith("-"));
    if (file) add(resolveWord(file, scope));
    return;
  }
  if (["bash", "sh", "zsh", "dash", "ksh"].includes(name)) return shellRuns(args, cmd, scope, out, add, depth);
  if (name === "powershell" || name === "pwsh") return powershellRuns(args, scope, out, add);
  if (name === "cmd") {
    const at = args.findIndex((a) => /^\/[ck]$/i.test(a));
    if (at >= 0) out.inline.push({ code: args.slice(at + 1).join(" "), lang: "cmd" });
    return;
  }
  if (["npx", "pnpx", "bunx"].includes(name)) return runnerRuns(args, scope, out, add, depth);
  if (name === "npm" && /^exec$/i.test(args[0] ?? "")) return runnerRuns(args.slice(1).filter((a) => a !== "--"), scope, out, add, depth);
  if (RUNNERS[name] && args[0] === RUNNERS[name]) {
    const inner = afterFlags(args.slice(1), /^(--with|--python|-p|--project|--group|--extra|--env-file|--directory)$/);
    if (inner.length) collectRuns(inner, scope, { argv: inner, out: [] }, out, add, depth + 1);
    return;
  }
  if (RUN_INTERPRETERS[name] || /^python\d+(\.\d+)?$/.test(name)) {
    return interpreterRuns(name, RUN_INTERPRETERS[name] ?? "python", args, cmd, scope, out, add);
  }
  // A program named by its path runs that file.
  if (/[\\/]/.test(program)) add(resolveWord(program, scope));
}

function shellRuns(args: string[], cmd: Simple, scope: Scope, out: RunTargets, add: (p?: string) => void, depth: number) {
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    // -c carries the program as text; the same parser reads what it runs.
    if (/^-[a-zA-Z]*c$/.test(arg)) {
      const code = args[i + 1] ?? "";
      out.inline.push({ code, lang: "bash" });
      if (code && depth < 5) walkRuns(parse(code), scope, out, add, depth + 1);
      return;
    }
    // -n only checks the syntax and runs nothing.
    if (arg === "-n") return;
    if (/^[-+]o$/.test(arg)) { i++; continue; }
    if (arg.startsWith("-")) continue;
    if (arg === "-") break;
    add(resolveWord(arg, scope));
    return;
  }
  // No script file: a heredoc gives the shell its program.
  if (cmd.heredoc) for (const body of cmd.heredocBodies ?? []) out.inline.push({ code: body, lang: "bash" });
}

function interpreterRuns(name: string, lang: string, args: string[], cmd: Simple, scope: Scope, out: RunTargets, add: (p?: string) => void) {
  let i = 0;
  if ((name === "deno" || name === "bun") && /^(run|x)$/i.test(args[0] ?? "")) i = 1;
  if (name === "deno" && /^eval$/i.test(args[0] ?? "")) {
    out.inline.push({ code: args[1] ?? "", lang: "js" });
    return;
  }
  for (; i < args.length; i++) {
    const arg = args[i];
    // -e is the eval flag of every interpreter; python and the shell-like ones use -c, php -r.
    const evalFlag = arg === "-e" || arg === "--eval" || arg === "-p" || arg === "--print" || (arg === "-c" && lang !== "js") || (arg === "-r" && lang === "php");
    if (evalFlag || /^--eval=/.test(arg)) {
      const text = arg.includes("=") ? arg.slice(arg.indexOf("=") + 1) : args[++i] ?? "";
      out.inline.push({ code: text, lang });
      continue;
    }
    // Node loads a required or imported module before the script: that file runs too.
    if ((name === "node" || name === "nodejs") && ["-r", "--require", "--import", "--loader", "--experimental-loader"].includes(arg)) {
      add(resolveWord(args[++i] ?? "", scope));
      continue;
    }
    // python -m names a module, not a file.
    if (arg === "-m" && lang === "python") return;
    if (arg === "-") break;
    if (arg.startsWith("-")) {
      if (RUN_VALUE_FLAGS.has(arg)) i++;
      continue;
    }
    add(resolveWord(arg, scope));
    return;
  }
  if (cmd.heredoc) for (const body of cmd.heredocBodies ?? []) out.inline.push({ code: body, lang });
}

function powershellRuns(args: string[], scope: Scope, out: RunTargets, add: (p?: string) => void) {
  const at = args.findIndex((a) => /^-(command|c)$/i.test(a));
  if (at >= 0) {
    out.inline.push({ code: args.slice(at + 1).join(" "), lang: "powershell" });
    return;
  }
  const encoded = args.findIndex((a) => /^-(e|ec|encodedcommand)$/i.test(a));
  if (encoded >= 0) {
    let code = "";
    try { code = Buffer.from(args[encoded + 1] ?? "", "base64").toString("utf16le").replace(/\0+$/, ""); } catch { code = ""; }
    if (code.trim()) out.inline.push({ code, lang: "powershell" });
    return;
  }
  const file = args.findIndex((a) => /^-(file|f)$/i.test(a));
  const script = file >= 0 ? args[file + 1] : args.find((a) => !a.startsWith("-") && /\.(ps1|psm1)$/i.test(a));
  if (script) add(resolveWord(script, scope));
}

// npx, pnpx and bunx run the package named after their own options.
function runnerRuns(args: string[], scope: Scope, out: RunTargets, add: (p?: string) => void, depth: number) {
  let i = 0;
  for (; i < args.length; i++) {
    const arg = args[i];
    if (arg === "-c" || arg === "--call") {
      const code = args[i + 1] ?? "";
      out.inline.push({ code, lang: "bash" });
      if (code && depth < 5) walkRuns(parse(code), scope, out, add, depth + 1);
      return;
    }
    if (arg === "-p" || arg === "--package" || arg === "--node-options" || /^--node-options=/.test(arg)) { i++; continue; }
    if (arg.startsWith("-")) continue;
    break;
  }
  // `tsx@4` names the same package as `tsx`.
  const pkg = (args[i] ?? "").replace(/@[^/]*$/, "");
  if (!pkg || !(RUN_PROGRAMS.has(pkg.toLowerCase()) || /^python\d+(\.\d+)?$/i.test(pkg))) return;
  collectRuns([pkg, ...args.slice(i + 1)], scope, { argv: [pkg, ...args.slice(i + 1)], out: [] }, out, add, depth + 1);
}

// write and edit tools.
export function fileVerdict(tool: string, target: string, scope: Scope): Verdict {
  const p = resolveWord(target.startsWith("@") ? target.slice(1) : target, scope);
  if (isGuarded(p, scope)) return guardAsk(`${tool} changes the auto-mode guard's own files`);
  if (isPiFile(p, scope)) return piAsk(`${tool} changes Pi's own files: ${target}`);
  // The write tool replaces the whole file with the agent's text; an edit keeps the file's origin.
  // For the chat decider an edit makes a file of no known origin one the session wrote, so a
  // project script the agent changed goes to it when run.
  if (tool === "write" || (scope.chatDecider && p && originOf(p, scope) === undefined)) note(p, "authored", scope);
  // Git runs what its own directory says: a hook, or config that names a command. The write tool
  // reaches these as easily as a shell does.
  if (p && /(^|[\\/])\.git[\\/]/.test(p)) return outwardClassify(`${tool} changes git's own files, which git acts on later: ${target}`);
  return isLocal(p, scope) ? ALLOW : forDecider(outside(`${tool} outside the working directory: ${target}`, p), scope);
}

// read and grep tools: an ask for a credential file, undefined for every other path.
export function readVerdict(tool: string, target: string, scope: Scope): Verdict | undefined {
  const secret = secretIn(target.startsWith("@") ? target.slice(1) : target, scope, true);
  return secret ? criticalAsk(`${tool} of a credential file: ${target}`) : undefined;
}
