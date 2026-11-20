# Security

## What shellwise protects against

shellwise guards against the careless mistakes of an agent that means well. It is not a security
boundary: a command written to hide what it does can get past it, and that is not treated as a
vulnerability. Do not rely on it to contain untrusted code or an untrusted agent.

A good command that is blocked, or a careless destructive command that passes, is an ordinary bug:
open a public issue.

## What to report privately

- shellwise itself doing harm: writing or deleting files, running the command it is checking,
  sending data anywhere;
- a crash or hang of the hook that lets every later command through unchecked;
- a problem in a release binary or in the build and release workflow.

Report these through GitHub's private vulnerability reporting on this repository (Security →
Report a vulnerability). Please include the version (`shellwise --version`), the operating system
and the steps to reproduce.
