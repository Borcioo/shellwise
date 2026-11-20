# bash-versioned-php

Herd's versioned PHP names (`php74`, `php80` … `php85`) are Windows `.bat` launchers. Git Bash does
not run a `.bat` file by its bare name, so `php83 -l a.php` fails there unless a shell profile
defines a `php83` function that calls the `.bat` (some machines do, which is why the rule warns).
The names are the `launcher` rows of `data/programs.toml`.

| Case | Level |
|---|---|
| a `launcher` row as the command, behind wrappers too, any case, with or without `.exe` | `warn` by default |
| `php`, or a `php.exe` by its full path | no finding |

The Fix line names the full path only when the config holds one (`tool_paths.<name>`); the rule
never guesses a path. The level follows the landing rule: the corpus replay counts 33 `ok` rows
that ran a versioned name, so it starts as `warn` (`VERSIONED_PHP_LEVEL`). Git Bash only.

## Deny

```bash
cd D:/x && php83 -l a.php
```

`warn`: `Fix: call the php.exe of that version by its full path`, followed by
`: "<path>"` when `tool_paths.php83` is set.

## Allow

```bash
php -v
```

`ok`.
