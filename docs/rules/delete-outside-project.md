# delete-outside-project

A delete whose target is outside the project and outside every allowed root
(`allowed_roots`: by default the OS temp folder). The project is the root of the repo holding
the cwd, or the cwd itself when it is in no repo. Deleting the cwd itself outside any repo is
this rule too.

Level `danger`: a signal, not a ban. When the delete is meant, the agent confirms it with the
trailing marker.

`Fix: if this is intended, run the same command again with ` # shellwise: allow` at its end`

## Deny

```bash
rm -rf ../outside/data
```

## Allow

```bash
rm -rf build
rm -rf ../outside/data # shellwise: allow
```
