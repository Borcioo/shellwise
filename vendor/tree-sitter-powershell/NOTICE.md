# tree-sitter-powershell fork

Started from the crates.io package `tree-sitter-powershell` version 0.26.6 (MIT, upstream
repository `airbus-cert/tree-sitter-powershell`); `LICENSE` is the upstream licence text.

`src/parser.c`, `src/grammar.json`, `src/node-types.json` and `src/tree_sitter/` are generated:
only `scripts/regen-grammar.ps1` writes them, with `tree-sitter-cli` 0.27.2
(`cargo install tree-sitter-cli --version 0.27.2 --locked`, QuickJS runtime), the newest CLI
whose parser the `tree-sitter` 0.27.2 runtime loads. `GENERATED` holds the hashes a test checks.

## Packaging changes

- `Cargo.toml`: `publish = false`.
- Regenerated with the pinned CLI: the parser tables are unchanged; `parser.c` differs from
  upstream only in its GCC optimisation pragma and `tree_sitter/array.h` is the CLI's own copy.
- `bindings/rust/build.rs` defines `TREE_SITTER_HIDE_SYMBOLS`: the parser is linked into an
  executable, and an exported symbol made MSVC's linker print a warning on every binary.

## Grammar changes

Each change makes the tree agree with PowerShell's `Parser::ParseInput` on a shape the parser
spike measured (`docs/spikes.md`).

- Numbers take case-insensitive type suffixes (`l`, `d`, `n`, `u`, `ul`, `uy`, `us`, `y`, `s`),
  multipliers (`kb` … `pb`), `0x` and `e` exponents in either case.
- `generic_token` (a bare word): it may hold `<` and `>` after its first character (`a>b` is one
  word); a leading digit or `*` is not followed by `>`, so `2>$null` is a redirection; its first
  character is not `,`, `<`, `>`, a digit, `*` or a typographic quote; quoted sections and
  backtick escapes inside it belong to the word; a Unicode space (`\p{Zs}`) ends it.
- Redirection operators `1>` and `1>>`; a redirection target may be a bare word.
- `command_name`: a name that starts with digits needs a letter after them (`(1..5)` and `1#` are
  not commands); it never starts with `>` or a stream redirection (`>git`, `2>&1x`); a backtick
  escapes the next character inside it, a line end included (`` git`<LF> status ``); Unicode
  spaces and typographic quotes end it.
- `stop_parsing`: `--%` is the token only before a space, a tab or the line end (`--%x` is not).
- New rule `glued_string_argument`: a closing quote ends an argument, so a bare word or a `(`
  glued after a string starts the next argument (`"a \"b\""`, `"x \"(a|b)\""`, `'a'x`).
- `command_parameter`: a `%` may follow the first letter (`-M50%`); a Unicode space ends an
  attached value (`--name=a`).
- `generic_token` never starts with `#` (a comment starts there); `command_argument_sep`: a
  Unicode space separates arguments.
- Null-conditional member access `${a}?.Name`.
- New rule `glued_argument`: a variable or `$(…)` with text glued after it (`$env:TEMP\x`,
  `$d\sub`, `${name}:`, `$a$b`) is one argument.
- Extras: BOM, word joiner, zero-width space, Unicode spaces and NEL are whitespace; a backtick
  before CR continues the line.
- Strings: typographic quotes open and close verbatim strings, expandable strings and
  here-strings; here-strings accept CR-only line ends; `""` doubling covers the typographic
  forms.
- A parameter glued to a quoted value (`-m'msg'`, `-S"text"`) is one argument.
- A command argument is one comma list of items (`a,b`, `'a', $b`); the old alternatives for an
  array literal and a glued pair are gone. `-split x` in argument position is a parameter and a
  value, and `-1`, `-5MB` are negative number arguments.
- `switch_clause`: the statement terminator after a clause is optional (`switch ($x) { 'a' {…}
  'b' {…} }` on one line).
- `.ForEach(…)` / `.Where(…)` take an argument list as well as a script block.
- New `null_coalescing_expression` (`??`), `ternary_expression` (`? :`) and the `??=`
  assignment operator.
- `{}` is a valid script block expression.
- Scanner: the text of an expandable string or here-string is read by the external scanner
  (`_expandable_string_text`, `_expandable_here_string_text`), so a `#` inside a string is not a
  comment; a lone CR ends a statement.
