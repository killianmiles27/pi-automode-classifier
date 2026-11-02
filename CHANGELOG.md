# Changelog

## 0.5.0

- Support native Windows paths and Git Bash drive, temporary, and installation paths with Git for Windows in its standard location.
- Protect Windows drive roots, system directories, case-insensitive credential paths, Pi instructions, Git metadata, and credentials in custom Pi agent directories.
- Require explicit review for PowerShell tool calls and PowerShell/cmd wrappers; deterministic shell rules parse Bash.
- Hide classifier and Git helper consoles on Windows.
- Add session-only Auto/YOLO switching with `/mode` and Alt+M, synchronized with the existing on/off commands. Session start restores the configured mode; entering YOLO stops the local classifier.
- Correct context-decider status reporting and Windows folder labels.
- Add isolated Windows and mode regressions, CRLF-compatible tests, configurable fixture roots, and Linux/Windows CI.
