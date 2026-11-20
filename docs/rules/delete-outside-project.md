# delete-outside-project

A delete whose target is outside the project and outside every allowed root (`allowed_roots`:
by default the OS temp folder). The project is the root of the repo holding the cwd, or the cwd
itself when it is in no repo. Deleting the cwd itself outside any repo is this rule too.

Level `warn` (Ruling 122): the message names what will be deleted; nothing is blocked.

## Warns

```bash
rm -rf ../outside/data
```

## Allow

```bash
rm -rf build
```
