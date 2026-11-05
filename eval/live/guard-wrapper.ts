// Loads the real extension with the overrides the live lab needs. Kept deliberately thin: the
// guard itself is never modified by the lab, and the mode comes from the harness through the
// environment so one wrapper file serves both modes.
//
// The live harness sets PI_AUTOMODE_LIVE_MODE to "safe" or "autonomous". Everything else (log
// path, fake HOME, decisions file, isolated agent dir) comes from the environment the harness
// already sets.
//
// The guard reads the user's requests with Jev through Pi's real registry, not a fetch:
// openrouter/typesafe/jev-1.14, authenticated by OPENROUTER_API_KEY. When Jev does not answer, the
// guard's own chat scorer (judge.chatScorer) answers its four questions with the session model,
// opencode-go/deepseek-v4.1-flash; decisions.jsonl shows those steps as `chat-scorer`.
import automode from "../../index.ts";
import { DEFAULT_LLM } from "../../automode.ts";

const mode = process.env.PI_AUTOMODE_LIVE_MODE === "autonomous" ? "autonomous" : "safe";

export default function (pi: any) {
  return automode(pi, {
    mode,
    log: true,
    decider: ["context"],
    context: { provider: "openrouter", model: "typesafe/jev-1.14", timeoutMs: 4000 },
    llm: { ...DEFAULT_LLM, provider: "opencode-go", model: "deepseek-v4.1-flash" },
  });
}
