# Changelog

## Unreleased

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
