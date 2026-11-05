// Validate every eval case file. Exit 1 on the first structural problem; print a count per file.
//
//   node eval/validate.mjs
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const cases = path.join(here, "cases");
const CLASSES = new Set(["routine", "useful-stop", "danger"]);
const SAFE = new Set(["allow", "ask", "block"]);
const AUTONOMOUS = new Set(["allow", "block"]);
const errors = [];
const seen = new Map();
const files = [];

const walk = (dir) => {
  if (!fs.existsSync(dir)) return;
  for (const name of fs.readdirSync(dir).sort()) {
    const full = path.join(dir, name);
    const stat = fs.statSync(full);
    if (stat.isDirectory()) walk(full);
    else if (name.endsWith(".jsonl")) files.push(full);
  }
};
walk(cases);

const fail = (file, line, message) => errors.push(`${path.relative(here, file)}:${line}: ${message}`);
const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const isInput = (v) => isObject(v) && Object.keys(v).length > 0;
const badSecret = /\b(?:sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b|-----BEGIN [A-Z ]*PRIVATE KEY-----/;

const validateCall = (file, line, call, label) => {
  if (!isObject(call)) return fail(file, line, `${label} must be an object`);
  if (typeof call.tool !== "string" || !call.tool) fail(file, line, `${label}.tool must be a non-empty string`);
  if (!isInput(call.input)) fail(file, line, `${label}.input must be a non-empty object`);
  if (call.fixtures !== undefined) validateFixtures(file, line, call.fixtures, `${label}.fixtures`);
  if (call.sessionWrites !== undefined) validateWrites(file, line, call.sessionWrites, `${label}.sessionWrites`);
};

const validateFixtures = (file, line, fixtures, label) => {
  if (!isObject(fixtures)) return fail(file, line, `${label} must be an object`);
  for (const [name, content] of Object.entries(fixtures)) {
    if (!name || name.includes("\0")) fail(file, line, `${label} has an empty or invalid path`);
    if (typeof content !== "string") fail(file, line, `${label}.${name} must be a string`);
    if (path.isAbsolute(name)) fail(file, line, `${label}.${name} must be relative or start with $REPO/$FAKEHOME`);
    if (name.split(/[\\/]/).includes("..")) fail(file, line, `${label}.${name} must not traverse with ..`);
  }
};

const validateWrites = (file, line, writes, label) => {
  if (!Array.isArray(writes)) return fail(file, line, `${label} must be an array`);
  writes.forEach((item, i) => {
    if (!isObject(item)) return fail(file, line, `${label}[${i}] must be an object`);
    if (typeof item.path === "string") {
      if (typeof item.content !== "string" && typeof item.oldText !== "string") fail(file, line, `${label}[${i}] needs content or oldText`);
      if (item.path.split(/[\\/]/).includes("..")) fail(file, line, `${label}[${i}].path must not traverse with ..`);
      return;
    }
    if (!["write", "edit"].includes(item.tool)) fail(file, line, `${label}[${i}].tool must be write or edit`);
    if (!isInput(item.input)) fail(file, line, `${label}[${i}].input must be a non-empty object`);
  });
};

const checkSecrets = (file, line, value, where) => {
  if (typeof value === "string") {
    if (badSecret.test(value)) fail(file, line, `${where} contains a credential-shaped value`);
    return;
  }
  if (Array.isArray(value)) for (const item of value) checkSecrets(file, line, item, where);
  if (isObject(value)) for (const [key, item] of Object.entries(value)) checkSecrets(file, line, item, `${where}.${key}`);
};

for (const file of files) {
  const raw = fs.readFileSync(file, "utf8");
  const lines = raw.split("\n");
  let count = 0;
  lines.forEach((line, i) => {
    if (!line.trim()) return;
    const at = i + 1;
    let item;
    try {
      item = JSON.parse(line);
    } catch (error) {
      return fail(file, at, `invalid JSON: ${error.message}`);
    }
    count++;
    if (!isObject(item)) return fail(file, at, "case must be an object");
    if (typeof item.id !== "string" || !item.id) fail(file, at, "id must be a non-empty string");
    else if (seen.has(item.id)) fail(file, at, `duplicate id ${item.id} (first in ${seen.get(item.id)})`);
    else seen.set(item.id, path.relative(here, file));
    if (typeof item.source !== "string" || !item.source) fail(file, at, "source must be a non-empty string");
    if (!CLASSES.has(item.class)) fail(file, at, "class must be routine, useful-stop or danger");
    if (!Array.isArray(item.requests) || item.requests.length === 0) fail(file, at, "requests must be a non-empty array");
    else if (item.requests.some((r) => typeof r !== "string" || !r.trim())) fail(file, at, "requests must contain non-empty strings");
    if (item.replyTo !== undefined && typeof item.replyTo !== "string") fail(file, at, "replyTo must be a string");
    if (item.history !== undefined && !Array.isArray(item.history)) fail(file, at, "history must be an array");
    if (!isObject(item.expect)) fail(file, at, "expect must be an object");
    else {
      if (!SAFE.has(item.expect.safe)) fail(file, at, "expect.safe must be allow, ask or block");
      if (!AUTONOMOUS.has(item.expect.autonomous)) fail(file, at, "expect.autonomous must be allow or block");
    }
    if (item.calls !== undefined) {
      if (!Array.isArray(item.calls) || item.calls.length === 0) fail(file, at, "calls must be a non-empty array");
      else item.calls.forEach((call, k) => validateCall(file, at, call, `calls[${k}]`));
    } else {
      if (typeof item.tool !== "string" || !item.tool) fail(file, at, "tool must be a non-empty string when calls is absent");
      if (!isInput(item.input)) fail(file, at, "input must be a non-empty object when calls is absent");
    }
    if (item.fixtures !== undefined) validateFixtures(file, at, item.fixtures, "fixtures");
    if (item.sessionWrites !== undefined) validateWrites(file, at, item.sessionWrites, "sessionWrites");
    if (item.why !== undefined && typeof item.why !== "string") fail(file, at, "why must be a string");
    if (item.class === "routine" && item.expect && item.expect.autonomous !== "allow") {
      fail(file, at, "a routine case must expect autonomous allow (use useful-stop or danger for stops)");
    }
    if (item.class === "danger" && item.expect && item.expect.autonomous !== "block") {
      fail(file, at, "a danger case must expect autonomous block");
    }
    checkSecrets(file, at, item, "case");
  });
  console.log(`${path.relative(here, file)}: ${count} cases`);
}

if (errors.length) {
  for (const error of errors) console.error(`INVALID ${error}`);
  console.error(`\n${errors.length} problem(s) in ${files.length} file(s)`);
  process.exit(1);
}
console.log(`\nOK: ${seen.size} unique cases in ${files.length} files`);
