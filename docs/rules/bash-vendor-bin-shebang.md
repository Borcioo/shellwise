# bash-vendor-bin-shebang

A Composer script run by path (`vendor/bin/pint`, `./vendor/bin/phpunit`) starts with
`#!/usr/bin/env php`. Git Bash has no `php` on its PATH, so the script does not start.

| Case | Level |
|---|---|
| `vendor/bin/<tool>` or `./vendor/bin/<tool>` as the command, behind wrappers too | `warn` by default |
| the `.bat` launcher (`vendor/bin/phpunit.bat`), or the script passed to `php` | no finding |

The level follows the landing rule: the corpus replay counts 31 `ok` rows, so it starts as `warn`
(`VENDOR_BIN_LEVEL`). Git Bash only.

## Deny

```bash
vendor/bin/pint --dirty
```

`warn`: `Fix: php vendor/bin/pint`

## Allow

```bash
php vendor/bin/phpunit
```

`ok`.
