# bash-msys-path-mangle

Git Bash rewrites an argument that looks like a POSIX path (`/var/www`, `--config=/etc/x`,
`/data:/data`) into a path under Git's install folder before a native Windows program sees it.
Programs that take Linux paths (`docker`, `docker-compose`, `wsl`, `kubectl`, `podman`; the
`native-msys` rows of `data/programs.toml`) then get a Windows path.

| Case | Level |
|---|---|
| a `native-msys` program with a `/<root>` argument (roots: `[msys].roots`), behind wrappers too | `warn` |
| the command, or the text before it, sets `MSYS_NO_PATHCONV` or `MSYS2_ARG_CONV_EXCL` | no finding |
| the path is written `//var/www` | no finding |

`warn`, because 173 `ok` corpus rows match: many of these commands still work. Git Bash only.

## Deny

```bash
docker exec web php /var/www/html/x.php
```

`warn`: `Fix: prefix MSYS_NO_PATHCONV=1, or write the leading slash as //`

## Allow

```bash
MSYS_NO_PATHCONV=1 docker exec web php /var/www/html/x.php
```

`ok`. So are `docker exec web ls //var/www` and `ls /var/log` (an msys program reads the path
itself).
