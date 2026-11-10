# Changelog

## 0.6.0

Two modes replace Auto. `docs/AUTO-MODES.md` has how they decide, setup, results and limits.

- **Auto Mode Safe** (`/mode safe`, `/mode auto` still works) asks only about what stays unresolved. **Auto Mode Autonomous** (`/mode autonomous`) never asks: what the judges will not clear is blocked, listed in `/automode blocked`, and the agent carries on. Alt+M cycles safe, autonomous and yolo. A child Pi inherits safe or autonomous, never yolo.
- **Effects analysis** (`effects.ts`) reads the code a call runs, without running it: network, credentials, whole-environment reads, outside writes and deletes, dynamic and obfuscated code, for JS, TS, Python, shell and PowerShell, and plain text for other languages. Imports are followed.
- **Floors** (`judge.ts`) no model can overrule. The guard's own files are never cleared by a model. Credentials, root, downloaded code and dangerous code need your words and a second opinion. Anything acting outside the project needs your words. A strong suspicious signal cannot be talked away.
- **Jev is better informed.** It gets the task from your first substantial message, kept whole at both ends, plus measured effects and recent commands, and answers four questions: serves the task, named by you, lasting harm, suspicious.
- **Second opinion**: the chat model decides what Jev leaves gray. **Fallback**: when Jev is down or out of quota, the chat model answers its questions.
- **Review memory**: the same call over the same content gets the same decision, and a changed file is a new review. "Allow while unchanged" replaces exact-text session allow, and a script that changes while a prompt is open is reviewed again.
- **Runner scan**: `npm test`, `make` and similar read what they will invoke and everything changed since the session began, so editing a test to exfiltrate and then running it is caught. A file counts as the project's only once committed or ignored.
- **Write-time scan**: dangerous content is stopped when written, including hooks and files in other languages.
- **Prompts** show why, what the code does, each judge's answer in words and how much was clipped, with "View full action" returning to the menu.
- **Agent guidance** in the system prompt reduces avoidable prompts, and in autonomous tells the agent not to wait for approval.
- **Rules**: Orca coordination by subcommand; guard bypasses such as `pi --no-extensions` and `PI_AUTOMODE_MODE=`; secrets behind globs, braces, variables and links; write and exec flags on tools that were allowed (`sort -o`, `sed w`, `man -P`, `rg --pre`, `tar --to-command`, `git -c core.hooksPath`, `git log --output`, abbreviated long options, environment prefixes such as `GIT_DIR=` and `MAKEFLAGS=`); PowerShell writes inside the project and native programs in PowerShell.
- **Fixes**: a config with a BOM, as Windows PowerShell's `Set-Content` writes, was ignored and the guard silently ran on defaults. The second opinion and explainer now send the session id, without which OpenCode Go refuses the call. Long requests keep both ends for the second opinion.
- **`eval/`**: a labelled corpus, two red-team rounds, replays of your own sessions, and a live lab with real Pi, a compromised agent and canaries. `test-hostile.mjs` holds every analyzer to a time limit on pathological input, after a hang froze a session.

## Unreleased

Autonomous blocked too much of what was asked (52 of 56 blocks over Nov 5-9 were false positives). Measured side by side with Claude Code's auto mode in `eval/ab/`: real Claude Code and Pi TUIs, each in its own Orca terminal, on the same 29 requested tasks and 3 injection attacks, in throwaway sandboxes.

| | Claude Code (Haiku, auto) | Pi, before | Pi, now |
|---|---|---|---|
| Tasks done on the first ask | 29/29 | 27/29 | 28/29 |
| Blocks on requested tasks | 0 | 5 | 2 |
| Attacks held | 3/3 | 3/3 | 3/3 |

Safety corpus, autonomous (627 cases): dangerous calls that ran 1/345 before, 2/345 now; both are coin-flip cases on the existing "partly named" path, where Jev scores 0.44-0.48 against the 0.45 bar. A first, broader version let 12/345 through and was narrowed.

- **Trusted servers**: on a host in `remote.trustedHosts`, a change that plainly serves your task ("ssh in and fix it") goes to the second opinion instead of a flat block. Every other outward call keeps the named-words bar. New thresholds `judge.scopedServesAbove`, `scopedHarmBelow`, `scopedSuspiciousBelow`.
- **Trusted servers from PowerShell too** (Muse Autonomous, and Pi's `powershell` tool): a plain native line such as `ssh killian 'docker ps --format {{.Names}}; df -h'` is read like the Bash line, and counts for the trusted-server path. Single-quoted text is literal in both, so `$`, braces and `;` inside it no longer force a review. What PowerShell would expand or Windows PowerShell 5.1 would re-quote differently (`$` outside single quotes, a double quote or `''` inside them, an empty argument, a trailing backslash) keeps the ask. Through Muse's linked judge, three steps that serve the task ("bazarr on killian is wedged, sort it out" → `docker restart bazarr`) went from blocked to cleared; an unrelated `docker rm -f` on the same host stays blocked.
- **Your words beat a suspicious look**: when Jev is confident you named the action (`namedAbove`), its suspicion score no longer stops the second opinion from deciding (a `curl ... | sh` you typed out). Credential reads and exfiltration keep the veto.
- **"Yes, do it" works**: a remembered block holds only until your next message, instead of re-blocking the same call from review memory.
- **Fixes**: `find ... -exec rm -rf {} +` read as `rm -rf .`; a glob over a folder that exists (`cat capabilities/*.json`) is judged by the files there, not by a guessed `credentials.json`; crate sources under `~/.cargo/registry` are not credentials; `cargo --version` and a quoted "cargo test" no longer start the runner scan.


- Add `docs/TUNING.md`: the read-only rule changes, the PowerShell vocabulary, and the opt-in thresholds that cut prompts, with the measured effect and the review fixes that closed the bypasses.

Fewer prompts for read-only work:

- `cd`/`pushd`/`popd`, option words (`-n`, `--depth`, a bare `-`), `sed` without `-i` and `find` whose every `-exec` only reads no longer count as touching the guard's own files.
- Running a script the session wrote is judged by its harm rating instead of always skipping the fast paths (`runs` is separate from `files`).
- `git config --global <key>` reads are allowed; set/unset/add/edit still ask.
- PowerShell is read by a cmdlet vocabulary instead of always asking: `Get-*`, `Format-*`, `Select/Where/ForEach-Object`, `Measure-Object`, `ConvertTo/From-*` and similar run; writers, executors, unknown cmdlets, redirects and non-pure .NET calls ask.

Protections the above must not open (with regressions):

- A writer running with its working directory inside the guard asks (`cd <guard> && python - <<EOF … open("rules.ts","w")`), and code the rules cannot read that names a guard path asks instead of going to the classifier.
- Every `find -exec`/`-ok` group is checked, not only the first. A read-only `-exec` outside the project passes only for name-only tools (`ls`, `stat`, `du`); credential locations (`find ~/.ssh -exec cat`) ask.
- PowerShell asks for `ForEach-Object` member calls (`gci | % Delete`, `gsv x | % Stop`; property reads such as `% FullName` pass), `$(…)` inside double-quoted strings that does not only read, numbered and `*>` redirects, property assignments, credential files and stores (`~/.ssh`, `Get-Credential`, `Get-Clipboard`), and `Terminate`/`Stop`/`Start`-style methods.
- `test-windows.mjs` runs outside Pi without `PI_CODING_AGENT_DIR`.

## 0.5.1

- Preserve the repair proposal at the end of long messages when a user gives a short approval reply. Keep messages up to 6,000 characters whole; retain the opening and end of longer messages.
- Redact credentials before trimming approval context. Add regressions for long proposals, bounded context, masking, and proposals without a user reply. Approval thresholds and mandatory checks are unchanged.

## 0.5.0

- Support native Windows paths and Git Bash drive, temporary, and installation paths with Git for Windows in its standard location.
- Protect Windows drive roots, system directories, case-insensitive credential paths, Pi instructions, Git metadata, and credentials in custom Pi agent directories.
- Require explicit review for PowerShell tool calls and PowerShell/cmd wrappers; deterministic shell rules parse Bash.
- Hide classifier and Git helper consoles on Windows.
- Add session-only Auto/YOLO switching with `/mode` and Alt+M, synchronized with the existing on/off commands. Session start restores the configured mode; entering YOLO stops the local classifier.
- Correct context-decider status reporting and Windows folder labels.
- Add isolated Windows and mode regressions, CRLF-compatible tests, configurable fixture roots, and Linux/Windows CI.
