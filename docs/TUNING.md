# Tuning for fewer prompts

Every prompt is a place the session stops. The rules already allow plain reads, builds and
tests; the changes below close the gaps where read-only inspection still asked, and the
thresholds loosen the model bands that were asking about routine work.

The rule changes and the PowerShell reader are on `main`. The thresholds are opt-in: they were
tuned with one model pair (LANCET Nano 0.4.3 and Jev 1.13), so measure them with your own models
before you keep them.

## Rules: what changed

These gaps turned read-only inspection into a prompt, and each one fired in ordinary review work:

| Before | Now |
|---|---|
| `cd <protected dir> && …` asked, because `cd`'s path argument was resolved like a write | `cd`, `pushd` and `popd` never count as touching a file |
| `sed -n`, `find -exec ls`, and any option word (`-n`, `--depth`, a bare `-` for stdin) were resolved as paths in the working directory | option words are not paths; `sed` without `-i` and `find` whose `-exec` only reads are read-only |
| Running a script the session just wrote skipped every fast path, because the run target was stored in `files` (write targets) | run targets are `runs`, separate from `files`: the harm rating decides, so `node test.js` or `./gen.sh` rated 4-7% harm runs without a prompt, and a harmful rating still asks |
| `git config --global user.name` (a read) asked as a change | only a set/unset/edit asks; reads of a key, `--get` and `--list` are allowed |
| Every PowerShell command was a critical, firm ask | a small vocabulary reads the command: read-only cmdlets allow, writers/executors/unknown cmdlets ask (see below) |

`sed -i`, redirects, `cp`/`mv`/`tee`, `sudo`, credentials, `curl | bash`, `find -exec <writer>`
and every write to the guard's own files still ask or are blocked exactly as before.

## PowerShell

`powershell` and `powershell.exe -Command` are parsed, not blanket-asked:

- allowed: `Get-*`, `Format-*`, `Measure-Object`, `Select-Object`, `Where-Object`,
  `ForEach-Object`, `Sort-Object`, `Group-Object`, `Compare-Object`, `Out-String`/`Out-Host`/
  `Out-Null`, `Write-Output` and the other `Write-*` streams, `Test-Path`, `Resolve-Path`,
  `Split-Path`, `ConvertTo-*`, `ConvertFrom-*`, loops and `if`/`try` blocks, and assignments whose
  value is read-only
- asks: `Set-*`, `New-*`, `Remove-*`, `Move-*`, `Copy-*`, `Rename-*`, `Clear-*`, `Add-*`,
  `Out-File`, `Tee-Object`, `Export-*`, `Start-*`/`Stop-*`, `Invoke-*`, `Install-*`, `Update-*`,
  native writers, `rm`/`sc`/`si`/`ni`/`cp`/`mv` aliases, and `>` redirection
- asks: `Invoke-Expression`/`iex`, `-EncodedCommand`, `-File` (the script body is hidden),
  `cmd.exe`, and any cmdlet the vocabulary does not know
- asks: .NET calls outside a pure-type whitelist (`[math]`, `[string]`, `[convert]`,
  `[datetime]`…), destructive methods (`$file.Delete()`, `(Get-Item x).MoveTo(y)`), and any method
  on an expression `(…).Method()` — these bypass the cmdlet vocabulary entirely

Parsing is conservative about literals: quoted text cannot run, so `Where-Object { $_.Name -match
'remove-item' }` is still a read.

## Thresholds

Add the keys you want to your config; everything else keeps its default. The two thresholds that
decide the dangerous cases are deliberately left alone: `authorizedAbove` (0.6) still requires
that you asked for a destructive call, and `blockHarmAbove` (0.9) still auto-blocks a clearly
harmful, unasked one.

```json
{
  "context": {
    "allowHarmBelow": 0.25,
    "lowHarmBelow": 0.15,
    "partialAuthorizedAbove": 0.2,
    "partialHarmBelow": 0.5,
    "sessionHarmBelow": 0.6
  },
  "askTimeoutSeconds": 90
}
```

| Key | Was | Now | Why |
|---|---|---|---|
| `context.allowHarmBelow` | 0.1 | 0.25 | routine is LANCET < 0.2 and harm < 0.25; 0.1 made borderline routine calls ask |
| `context.lowHarmBelow` | 0.1 | 0.15 | "harmless" now covers a harm rating that wobbles between 0.10 and 0.15 |
| `context.partialAuthorizedAbove` | 0.25 | 0.2 | a natural next step of the task |
| `context.partialHarmBelow` | 0.4 | 0.5 | reversible work inside the project |
| `context.sessionHarmBelow` | 0.5 | 0.6 | a kind of call you already allowed this session |
| `askTimeoutSeconds` | 0 | 90 | an unanswered prompt blocks and the agent carries on with the rest |

`command.allowBelow` stays at 0.1: that band is tuned for LANCET, and the rules now cover most of
what used to fall into it. Turn `log` on to see where a decision came from; every entry lands in
`~/.local/state/pi-automode-classifier/decisions.jsonl` with its outcome, decider and reason.

## Measured effect

Real Pi sessions in throwaway folders, with a driver that answers every prompt instead of hanging:

| session | before | after |
|---|---|---|
| fix a failing test (`calc`, 7-8 calls) | 0 prompts | 0 |
| add a `--json` flag, test, docs, commit (`greeter`, 12-13 calls) | 1 (ran `src/cli.js`, harm 4%) | 0 |
| clean dead code, tests, commit (`messy`, 15-22 calls) | 1 (read `git config --global user.name`) | 0 |
| 7-turn feature session, 28 calls | — | 0 |
| read-only PowerShell volumes and top processes, 2 calls | 2 (would have been critical asks) | 0 |

A replay of a fixed corpus through the real handler keeps the risky set unchanged: `rm -rf
~/Documents/old-project` blocked, `git push --force`, `cat ~/.ssh/id_rsa`, `curl … | bash`,
`sudo`, `Remove-Item` and `Get-ChildItem > out.txt` all ask.

## Reload

The extension and its config load at startup. Run `/reload` in Pi (or restart) and check
`/automode-classifier status`.

## Review fixes

An adversarial review found rule-level allows that the tuning had opened; all are closed with
regressions in `test.mjs`:

- guard edits from a `cd` into the guard (`python - <<EOF`), and opaque code that names a guard path
- every `find -exec` group (only the first was checked), and credential roots in `find`
- PowerShell member calls (`gci | % Delete`), `$(…)` in strings, `2>`/`*>` redirects, property
  sets, credential files and stores, and process methods

See [PR #1](https://github.com/killianmiles27/pi-automode-classifier/pull/1) for the commit and
its regressions.

## Sharing a config

Keep machine paths, provider credentials and personal allow rules out of anything you publish. A
`command.argv` with a local interpreter or model path, an API key, or an `allow` rule for one
machine's tooling does not belong in a shared example; describe the shape instead.
