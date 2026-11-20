# bash-crlf

`shellwise lint` only. A `.sh` or `.bash` file with CRLF line ends, linted in the Git Bash profile
(a Windows host): Git Bash reads such a script as if it had LF line ends and runs it, while Linux
bash stops at each CR (`$'\r': command not found`). The file gets this one `warn`; the shellwise
rules and ShellCheck then read its LF twin, so a CR is never reported as a syntax error.

In the POSIX profile the CRs stay in the text, as Linux bash reads it.

| Case | Level | Why |
|---|---|---|
| A CRLF `.sh` in the Git Bash profile | `warn` | It runs here and fails on Linux. |
| An LF `.sh`, or any `.ps1` | `ok` | PowerShell reads CRLF as a line end. |

## Deny

A `build.sh` saved with CRLF line ends:

`warn`: `Fix: save the file with LF line ends`

## Allow

The same file saved with LF line ends: `ok`.
