#!/bin/sh
# Installs or updates shellwise on Linux and macOS (POSIX sh):
#
#   curl -fsSL https://raw.githubusercontent.com/Borcioo/shellwise/main/install.sh | sh
#
# It downloads the release archive and SHA256SUMS, refuses unless the archive's SHA-256 matches its
# line, and moves the binary in with one rename. Running it again is the update. It never edits a
# shell profile. Settings come only from the environment:
#
#   SHELLWISE_VERSION      1.2.3 or v1.2.3; unset installs the latest release
#   SHELLWISE_INSTALL_DIR  the install folder; default ~/.local/bin
#   SHELLWISE_BASE_URL     the release URL, or a local folder with the same layout
#   SHELLWISE_MODE         install (default), or check: print the latest version and install nothing
#   SHELLWISE_NO_PATH      1 skips the PATH hint
#   SHELLWISE_TARGET       overrides the detected target (tests and troubleshooting)

set -eu

supported='x86_64-unknown-linux-musl, x86_64-unknown-linux-gnu, aarch64-unknown-linux-musl, x86_64-apple-darwin, aarch64-apple-darwin'
version_re='[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?'

say() {
    printf '%s\n' "$*"
}

refuse() {
    printf 'shellwise install: %s\n' "$*" >&2
    exit 1
}

base=${SHELLWISE_BASE_URL:-https://github.com/Borcioo/shellwise/releases}
base=${base%/}
case $base in
    http://* | https://*) remote=1 ;;
    *) remote=0 ;;
esac
connect_timeout=10
max_time=120

tmp=''
trap 'if [ -n "$tmp" ]; then rm -rf "$tmp"; fi' EXIT
trap 'exit 1' HUP INT TERM
tmp=$(mktemp -d "${TMPDIR:-/tmp}/shellwise-install.XXXXXX") || refuse 'could not make a temp folder'

# fetch <path under the base> <destination file>
fetch() {
    if [ "$remote" = 1 ]; then
        url="$base/$1"
        if command -v curl >/dev/null 2>&1; then
            # curl's own error joins the one refusal line.
            if ! why=$(curl -fsSL --connect-timeout "$connect_timeout" --max-time "$max_time" -o "$2" "$url" 2>&1); then
                refuse "could not download $url: $(printf '%s' "$why" | tr '\n' ' ')"
            fi
        elif command -v wget >/dev/null 2>&1; then
            wget -q -T "$max_time" -O "$2" "$url" || refuse "could not download $url"
        else
            refuse 'neither curl nor wget is installed'
        fi
    else
        [ -f "$base/$1" ] || refuse "could not read $base/$1"
        cp "$base/$1" "$2" || refuse "could not copy $base/$1"
    fi
}

# Sets $version to the latest release named in <base>/latest/download/SHA256SUMS.
read_latest_version() {
    fetch latest/download/SHA256SUMS "$tmp/latest-SHA256SUMS"
    version=$(tr -d '\r' <"$tmp/latest-SHA256SUMS" |
        sed -n -E "s/^[0-9a-fA-F]{64} [ *]shellwise-v($version_re)-(x86_64|aarch64)-.*/\\1/p" |
        head -n 1)
    [ -n "$version" ] || refuse "could not read the latest version from $base/latest/download/SHA256SUMS"
}

# Prints the lowercase digest on the one line for <file> in <sums>, "many" for more than one line,
# nothing for none.
sums_line() {
    tr -d '\r' <"$2" | awk -v f="$1" '
        length($0) > 66 && substr($0, 65, 1) == " " && (substr($0, 66, 1) == " " || substr($0, 66, 1) == "*") {
            hex = substr($0, 1, 64)
            name = substr($0, 67)
            sub(/[ \t]+$/, "", name)
            if (hex ~ /^[0-9a-fA-F]+$/ && name == f) { n++; digest = tolower(hex) }
        }
        END { if (n == 1) print digest; else if (n > 1) print "many" }'
}

mode=${SHELLWISE_MODE:-install}
if [ "$mode" = check ]; then
    connect_timeout=2
    max_time=3
    read_latest_version
    printf '%s\n' "$version"
    exit 0
fi
[ "$mode" = install ] || refuse "unknown SHELLWISE_MODE $mode; use install or check"

target=${SHELLWISE_TARGET:-}
gnu_fallback=0
if [ -z "$target" ]; then
    os=$(uname -s)
    arch=$(uname -m)
    case "$os/$arch" in
        Linux/x86_64 | Linux/amd64)
            target=x86_64-unknown-linux-musl
            gnu_fallback=1
            ;;
        Linux/aarch64 | Linux/arm64) target=aarch64-unknown-linux-musl ;;
        Darwin/x86_64) target=x86_64-apple-darwin ;;
        Darwin/arm64 | Darwin/aarch64) target=aarch64-apple-darwin ;;
        *) refuse "no release for $os on $arch; supported targets: $supported" ;;
    esac
fi
case $target in
    x86_64-unknown-linux-musl | x86_64-unknown-linux-gnu | aarch64-unknown-linux-musl | x86_64-apple-darwin | aarch64-apple-darwin) ;;
    *) refuse "unsupported target $target; supported targets: $supported (on Windows use install.ps1)" ;;
esac

if [ -n "${SHELLWISE_VERSION:-}" ]; then
    version=${SHELLWISE_VERSION#v}
    case $version in
        *[!0-9A-Za-z.-]* | '') refuse "SHELLWISE_VERSION $SHELLWISE_VERSION is not a version like 1.2.3" ;;
    esac
    printf '%s\n' "$version" | grep -Eq "^$version_re\$" ||
        refuse "SHELLWISE_VERSION $SHELLWISE_VERSION is not a version like 1.2.3"
    sums="$tmp/SHA256SUMS"
    fetch "download/v$version/SHA256SUMS" "$sums"
else
    read_latest_version
    sums="$tmp/latest-SHA256SUMS"
fi

file="shellwise-v$version-$target.tar.gz"
expected=$(sums_line "$file" "$sums")
if [ -z "$expected" ] && [ "$gnu_fallback" = 1 ]; then
    # Releases up to v0.1.1 have no musl build.
    gnu_file="shellwise-v$version-x86_64-unknown-linux-gnu.tar.gz"
    expected=$(sums_line "$gnu_file" "$sums")
    if [ -n "$expected" ]; then
        target=x86_64-unknown-linux-gnu
        file=$gnu_file
    fi
fi
case $expected in
    '') refuse "SHA256SUMS of v$version has no line for $file; nothing was installed" ;;
    many) refuse "SHA256SUMS of v$version has more than one line for $file; nothing was installed" ;;
esac

archive="$tmp/$file"
fetch "download/v$version/$file" "$archive"
if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum <"$archive" | cut -d ' ' -f 1)
elif command -v shasum >/dev/null 2>&1; then
    actual=$(shasum -a 256 <"$archive" | cut -d ' ' -f 1)
else
    refuse 'neither sha256sum nor shasum is installed; nothing was installed'
fi
actual=$(printf '%s' "$actual" | tr 'A-F' 'a-f')
# $expected is 64 hex digits (sums_line checks it), so an empty or broken hash never matches.
[ "$actual" = "$expected" ] ||
    refuse "checksum mismatch for $file (SHA256SUMS has $expected, the download has $actual); nothing was installed"

mkdir "$tmp/unpack"
tar -xzf "$archive" -C "$tmp/unpack" || refuse "could not unpack $file"
bin="$tmp/unpack/shellwise-v$version-$target/shellwise"
[ -f "$bin" ] || refuse "$file holds no shellwise-v$version-$target/shellwise"

dir=${SHELLWISE_INSTALL_DIR:-}
if [ -z "$dir" ]; then
    [ -n "${HOME:-}" ] || refuse 'HOME is not set; set SHELLWISE_INSTALL_DIR'
    dir="$HOME/.local/bin"
fi
case $dir in
    /*) ;;
    *) dir="$(pwd)/$dir" ;;
esac
dir=${dir%/}
mkdir -p "$dir" || refuse "could not make $dir"

# The copy lands in the install folder first, so the swap is one rename on one file system.
dest="$dir/shellwise"
new="$dir/shellwise.new"
if [ -d "$dest" ]; then
    refuse "$dest is a folder; nothing was installed"
fi
if ! cp "$bin" "$new" || ! chmod 755 "$new"; then
    rm -f "$new"
    refuse "could not write $new; nothing was installed"
fi
if ! mv -f "$new" "$dest"; then
    rm -f "$new"
    refuse "could not put the new binary in place at $dest"
fi
say "Installed shellwise $version at $dest"

if [ "${SHELLWISE_NO_PATH:-}" != 1 ]; then
    case ":${PATH:-}:" in
        *":$dir:"*) ;;
        *)
            say "$dir is not on PATH; add this line to your shell profile:"
            # The line is printed for the user to paste, so $PATH stays unexpanded.
            # shellcheck disable=SC2016
            printf '  export PATH="%s:$PATH"\n' "$dir"
            ;;
    esac
fi
say 'Next: shellwise agent-setup'
