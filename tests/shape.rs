//! Rules as data: program names and option spellings belong in the tables, not in code.
//!
//! A **program literal** is a string literal outside `#[cfg(test)]` whose value, lowercased with a
//! trailing `.exe` removed, names a program in the name sources. An **option literal** matches
//! `^(-{1,2}[A-Za-z][A-Za-z0-9-]*|/[A-Za-z]{1,2})$`. Under `src/rules/`, a literal passed to
//! `Regex::new` is flagged too. Literals inside macro calls count.
//!
//! String and byte-string literals both count.
//!
//! Files that existed at acf4643 are counted against the name set frozen then
//! (`tests/shape_names_acf4643.txt`), so a table that grows cannot raise their counts, and each
//! must hold exactly the literals `tests/shape_legacy.txt` records for it, each as often: a
//! literal swapped for another is seen, not only a count that grows. Every other file is counted
//! against the live name sources and has cap 0 unless `NEW_FILES` records one.
//! `src/programs.rs`, the reader of the table, is not counted.
//!
//! The name sources include the wrapper, shell, eval and echo tables of `src/scan.rs`, so a rule
//! that names `sudo` or `bash` in code is seen. `cargo test --test shape -- --ignored
//! --nocapture recount_legacy_literals` prints the current legacy literals in the record's format.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use syn::visit::{self, Visit};

/// Every file under `src/` at acf4643. Its literals are recorded in `tests/shape_legacy.txt`; a
/// record only shrinks, with the commit that removes the literals.
const LEGACY: &[&str] = &[
    "src/adapter/check_json.rs",
    "src/adapter/mod.rs",
    "src/config.rs",
    "src/fs/cmdlet_table.rs",
    "src/fs/mod.rs",
    "src/fs/resolve.rs",
    "src/fs/walk.rs",
    "src/fs/windows.rs",
    "src/ir.rs",
    "src/level.rs",
    "src/lib.rs",
    "src/main.rs",
    "src/parse/bash.rs",
    "src/parse/mod.rs",
    "src/parse/pwsh.rs",
    "src/rules/mod.rs",
    "src/scan.rs",
];

/// The `src/scan.rs` constants whose names seed the name sources: the shells of the table, the
/// wrappers, the code-running commands, the bash and other shells and the echo commands.
const SCAN_TABLES: &[&str] = &[
    "SHELLS",
    "WRAPPERS",
    "EVAL_NAMES",
    "BASH_SHELLS",
    "OTHER_SHELLS",
    "ECHO_NAMES",
];

/// New files allowed host tool names that are not program names, with the reason. Their caps
/// are otherwise 0.
const NEW_FILES: &[(&str, &[&str], &str)] = &[
    (
        "src/adapter/claude_code.rs",
        &["Bash", "PowerShell"],
        "the hook event's tool names, compared to pick the shell",
    ),
    (
        "src/bench.rs",
        &["Bash", "PowerShell"],
        "the corpus rows' tool names, compared to pick the shell",
    ),
    (
        "src/fs/assigned.rs",
        &["foreach"],
        "the PowerShell loop keyword a loop header starts with, not a command",
    ),
];

/// The file that reads `data/programs.toml`: its literals are the table's own keys.
const TABLE_READER: &str = "src/programs.rs";

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Count {
    programs: usize,
    options: usize,
    regexes: usize,
}

/// One flagged literal: its kind (`program`, `option` or `regex`) and its value.
type Flagged = (&'static str, String);

/// Each flagged literal of a file, with how often it occurs.
type Literals = BTreeMap<Flagged, usize>;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every lowercased name the sources hold: `data/destructive.toml` names (a name with spaces
/// also gives its first word), `src/parse/pwsh_names.txt` aliases, targets and commands, the
/// `SCAN_TABLES` of `src/scan.rs`, and the `name`/`aliases` strings of `data/programs.toml` when
/// it exists.
fn live_names() -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let destructive = std::fs::read_to_string(root().join("data/destructive.toml")).unwrap();
    let table: toml::Table = toml::from_str(&destructive).unwrap();
    let commands = table["command"].as_array().unwrap();
    assert!(!commands.is_empty(), "destructive.toml: no commands");
    for c in commands {
        for n in c["names"].as_array().unwrap() {
            let n = n.as_str().unwrap().to_lowercase();
            if let Some((first, _)) = n.split_once(' ') {
                out.insert(first.to_string());
            }
            out.insert(n);
        }
    }
    let pwsh = std::fs::read_to_string(root().join("src/parse/pwsh_names.txt")).unwrap();
    let before = out.len();
    for line in pwsh.lines() {
        if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
            continue;
        }
        for part in line.split('=') {
            out.insert(part.to_lowercase());
        }
    }
    assert!(out.len() > before + 500, "pwsh_names.txt: too few names");
    let scan = std::fs::read_to_string(root().join("src/scan.rs")).unwrap();
    out.extend(scan_table_names(&scan));
    let programs = root().join("data/programs.toml");
    if programs.exists() {
        let text = std::fs::read_to_string(&programs).unwrap();
        let table: toml::Table = toml::from_str(&text).unwrap();
        collect_program_names(&toml::Value::Table(table), &mut out);
    }
    out
}

/// The lowercased names in the `SCAN_TABLES` constants of `source` (`src/scan.rs`); option
/// spellings in them (a wrapper's value options) are left out. Fails when a table is missing or
/// names nothing.
fn scan_table_names(source: &str) -> BTreeSet<String> {
    struct Strings(Vec<String>);
    impl<'ast> Visit<'ast> for Strings {
        fn visit_lit_str(&mut self, s: &'ast syn::LitStr) {
            self.0.push(s.value());
        }
    }
    let file = syn::parse_file(source).expect("src/scan.rs parses");
    let mut out = BTreeSet::new();
    for table in SCAN_TABLES {
        let item = file.items.iter().find_map(|i| match i {
            syn::Item::Const(c) if c.ident == table => Some(c),
            _ => None,
        });
        let item = item.unwrap_or_else(|| panic!("src/scan.rs: no const {table}"));
        let mut strings = Strings(Vec::new());
        strings.visit_expr(&item.expr);
        let names: Vec<String> = strings
            .0
            .into_iter()
            .filter(|s| !s.starts_with('-'))
            .map(|s| s.to_lowercase())
            .collect();
        assert!(!names.is_empty(), "src/scan.rs: {table} names nothing");
        out.extend(names);
    }
    out
}

fn collect_program_names(v: &toml::Value, out: &mut BTreeSet<String>) {
    match v {
        toml::Value::Table(t) => {
            for (k, v) in t {
                match (k.as_str(), v) {
                    ("name", toml::Value::String(s)) => {
                        out.insert(s.to_lowercase());
                    }
                    ("aliases", toml::Value::Array(a)) => {
                        out.extend(a.iter().filter_map(|x| x.as_str()).map(str::to_lowercase));
                    }
                    // `aliases = { bash = [...], pwsh_windows = [...] }`: one list per shell.
                    ("aliases", toml::Value::Table(t)) => {
                        for a in t.values().filter_map(|v| v.as_array()) {
                            out.extend(a.iter().filter_map(|x| x.as_str()).map(str::to_lowercase));
                        }
                    }
                    _ => collect_program_names(v, out),
                }
            }
        }
        toml::Value::Array(a) => a.iter().for_each(|x| collect_program_names(x, out)),
        _ => {}
    }
}

fn frozen_names() -> BTreeSet<String> {
    let text = std::fs::read_to_string(root().join("tests/shape_names_acf4643.txt")).unwrap();
    let names: BTreeSet<String> = text
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect();
    assert!(names.len() > 500, "the frozen name set is too small");
    names
}

fn is_option(s: &str) -> bool {
    let b = s.as_bytes();
    if let Some(rest) = s.strip_prefix('/') {
        return (1..=2).contains(&rest.len()) && rest.bytes().all(|c| c.is_ascii_alphabetic());
    }
    let dashes = b.iter().take_while(|&&c| c == b'-').count();
    if !(1..=2).contains(&dashes) {
        return false;
    }
    let rest = &b[dashes..];
    rest.first().is_some_and(|c| c.is_ascii_alphabetic())
        && rest.iter().all(|&c| c.is_ascii_alphanumeric() || c == b'-')
}

struct Counter<'n> {
    names: &'n BTreeSet<String>,
    allowed: &'n [&'n str],
    in_rules: bool,
    found: Literals,
}

impl Counter<'_> {
    fn flag(&mut self, kind: &'static str, value: &str) {
        *self.found.entry((kind, value.to_string())).or_insert(0) += 1;
    }

    fn literal(&mut self, value: &str) {
        if self.allowed.contains(&value) {
            return;
        }
        let lower = value.to_lowercase();
        let name = lower.strip_suffix(".exe").unwrap_or(&lower);
        if self.names.contains(name) {
            self.flag("program", value);
        }
        if is_option(value) {
            self.flag("option", value);
        }
    }

    /// A byte-string literal counts as its text.
    fn byte_literal(&mut self, value: &[u8]) {
        self.literal(&String::from_utf8_lossy(value));
    }

    /// Every string and byte-string literal in a macro's tokens, nested groups included.
    fn tokens(&mut self, mut cursor: syn::buffer::Cursor) {
        while !cursor.eof() {
            if let Some((inside, _, _, next)) = cursor.any_group() {
                self.tokens(inside);
                cursor = next;
            } else if let Some((lit, next)) = cursor.literal() {
                match syn::Lit::new(lit) {
                    syn::Lit::Str(s) => self.literal(&s.value()),
                    syn::Lit::ByteStr(s) => self.byte_literal(&s.value()),
                    _ => {}
                }
                cursor = next;
            } else if let Some((_, next)) = cursor.token_tree() {
                cursor = next;
            } else {
                break;
            }
        }
    }
}

fn is_cfg_test(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| match &a.meta {
        syn::Meta::List(l) => l.path.is_ident("cfg") && l.tokens.to_string() == "test",
        _ => false,
    })
}

impl<'ast> Visit<'ast> for Counter<'_> {
    fn visit_item(&mut self, i: &'ast syn::Item) {
        let attrs = match i {
            syn::Item::Mod(x) => &x.attrs,
            syn::Item::Fn(x) => &x.attrs,
            syn::Item::Impl(x) => &x.attrs,
            syn::Item::Const(x) => &x.attrs,
            syn::Item::Static(x) => &x.attrs,
            syn::Item::Use(x) => &x.attrs,
            syn::Item::Struct(x) => &x.attrs,
            syn::Item::Enum(x) => &x.attrs,
            _ => return visit::visit_item(self, i),
        };
        if !is_cfg_test(attrs) {
            visit::visit_item(self, i);
        }
    }

    fn visit_impl_item(&mut self, i: &'ast syn::ImplItem) {
        if let syn::ImplItem::Fn(f) = i
            && is_cfg_test(&f.attrs)
        {
            return;
        }
        visit::visit_impl_item(self, i);
    }

    fn visit_lit_str(&mut self, s: &'ast syn::LitStr) {
        self.literal(&s.value());
    }

    fn visit_lit_byte_str(&mut self, s: &'ast syn::LitByteStr) {
        self.byte_literal(&s.value());
    }

    fn visit_macro(&mut self, m: &'ast syn::Macro) {
        let buffer = syn::buffer::TokenBuffer::new2(m.tokens.clone());
        self.tokens(buffer.begin());
    }

    fn visit_expr_call(&mut self, c: &'ast syn::ExprCall) {
        if self.in_rules
            && let syn::Expr::Path(p) = &*c.func
        {
            let segs: Vec<String> = p
                .path
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect();
            if segs.ends_with(&["Regex".to_string(), "new".to_string()])
                && let Some(syn::Expr::Lit(l)) = c.args.first()
                && let syn::Lit::Str(s) = &l.lit
            {
                self.flag("regex", &s.value());
            }
        }
        visit::visit_expr_call(self, c);
    }
}

fn literals(source: &str, rel: &str, names: &BTreeSet<String>, allowed: &[&str]) -> Literals {
    let file = syn::parse_file(source).unwrap_or_else(|e| panic!("{rel}: {e}"));
    let mut c = Counter {
        names,
        allowed,
        in_rules: rel.starts_with("src/rules/"),
        found: Literals::new(),
    };
    c.visit_file(&file);
    c.found
}

fn count(source: &str, rel: &str, names: &BTreeSet<String>, allowed: &[&str]) -> Count {
    let mut c = Count::default();
    for ((kind, _), n) in literals(source, rel, names, allowed) {
        match kind {
            "program" => c.programs += n,
            "option" => c.options += n,
            _ => c.regexes += n,
        }
    }
    c
}

/// `tests/shape_legacy.txt`: per legacy file, each recorded literal and how often it occurs. A
/// line is `<file>\t<kind>\t<n>\t<literal>`; `#` lines are comments.
fn legacy_record() -> BTreeMap<String, Literals> {
    let text = std::fs::read_to_string(root().join("tests/shape_legacy.txt")).unwrap();
    let mut out: BTreeMap<String, Literals> = BTreeMap::new();
    for line in text
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let parts: Vec<&str> = line.splitn(4, '\t').collect();
        let [file, kind, n, literal] = parts[..] else {
            panic!("shape_legacy.txt: not 4 fields: {line:?}");
        };
        let kind = ["program", "option", "regex"]
            .into_iter()
            .find(|k| *k == kind)
            .unwrap_or_else(|| panic!("shape_legacy.txt: unknown kind {kind:?}"));
        assert!(
            LEGACY.contains(&file),
            "shape_legacy.txt: {file} is not a legacy file"
        );
        let n: usize = n.parse().unwrap_or_else(|_| panic!("bad count: {line:?}"));
        let previous = out
            .entry(file.to_string())
            .or_default()
            .insert((kind, literal.to_string()), n);
        assert!(previous.is_none(), "shape_legacy.txt: twice: {line:?}");
    }
    assert!(!out.is_empty(), "shape_legacy.txt records no literal");
    out
}

/// The record's lines for `rel`'s literals.
fn record_lines(rel: &str, found: &Literals) -> Vec<String> {
    found
        .iter()
        .map(|((kind, literal), n)| {
            assert!(
                !literal.contains(['\t', '\n', '\r']),
                "{rel}: a literal the record cannot hold: {literal:?}"
            );
            format!("{rel}\t{kind}\t{n}\t{literal}")
        })
        .collect()
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

fn rel(p: &Path) -> String {
    p.strip_prefix(root())
        .unwrap()
        .to_string_lossy()
        .replace('\\', "/")
}

#[test]
fn the_fixture_is_caught() {
    let src = std::fs::read_to_string(root().join("tests/shape_fixture/rules_bad.rs.txt")).unwrap();
    let got = count(&src, "src/rules/bad.rs", &live_names(), &[]);
    assert_eq!(
        got,
        Count {
            programs: 1,
            options: 1,
            regexes: 1
        }
    );
}

/// What is wrong with one file's literals, or `None` when they match: a legacy file against its
/// record, any other file against cap 0.
fn file_mismatch(
    rel: &str,
    source: &str,
    frozen: &BTreeSet<String>,
    live: &BTreeSet<String>,
    record: &BTreeMap<String, Literals>,
) -> Option<String> {
    if LEGACY.contains(&rel) {
        let got = literals(source, rel, frozen, &[]);
        let want = record.get(rel).cloned().unwrap_or_default();
        if got == want {
            return None;
        }
        let mut diff = Vec::new();
        for key in got.keys().chain(want.keys()).collect::<BTreeSet<_>>() {
            let (g, w) = (
                got.get(key).copied().unwrap_or(0),
                want.get(key).copied().unwrap_or(0),
            );
            if g != w {
                diff.push(format!("  {} {:?}: {g} (recorded {w})", key.0, key.1));
            }
        }
        return Some(format!("{rel}:\n{}", diff.join("\n")));
    }
    let allowed = NEW_FILES
        .iter()
        .find(|(f, ..)| *f == rel)
        .map_or(&[][..], |(_, a, _)| *a);
    let got = literals(source, rel, live, allowed);
    (!got.is_empty()).then(|| format!("{rel}: cap 0, holds {got:?}"))
}

/// Every file under `src/` that the test reads, with its path relative to the root.
fn source_files() -> Vec<(String, String)> {
    let mut files = Vec::new();
    rust_files(&root().join("src"), &mut files);
    assert!(!files.is_empty(), "read 0 files under src/");
    let mut out: Vec<(String, String)> = files
        .iter()
        .map(|p| (rel(p), std::fs::read_to_string(p).unwrap()))
        .filter(|(rel, _)| rel != TABLE_READER)
        .collect();
    out.sort();
    out
}

#[test]
fn every_file_holds_exactly_its_cap_of_literals() {
    let (frozen, live, record) = (frozen_names(), live_names(), legacy_record());
    let mut wrong = Vec::new();
    for (rel, source) in source_files() {
        wrong.extend(file_mismatch(&rel, &source, &frozen, &live, &record));
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// Prints the record of the legacy files' literals as they are now, with the totals per kind.
#[test]
#[ignore = "a recount command, run by hand"]
fn recount_legacy_literals() {
    let frozen = frozen_names();
    let mut totals: BTreeMap<&str, usize> = BTreeMap::new();
    let mut lines = Vec::new();
    for (rel, source) in source_files() {
        if !LEGACY.contains(&rel.as_str()) {
            continue;
        }
        let found = literals(&source, &rel, &frozen, &[]);
        for ((kind, _), n) in &found {
            *totals.entry(kind).or_insert(0) += n;
        }
        let c = count(&source, &rel, &frozen, &[]);
        eprintln!(
            "{rel}: programs {}, options {}, regexes {}",
            c.programs, c.options, c.regexes
        );
        lines.extend(record_lines(&rel, &found));
    }
    eprintln!("totals {totals:?}, {} record lines", lines.len());
    println!("{}", lines.join("\n"));
}

/// A new rules file naming one entry of each `SCAN_TABLES` table that no other table or name
/// source holds, a wrapper's value option, and programs in byte strings, in code and in a macro.
const NEW_RULE_FILE: &str = r#"
fn wrapped(name: &str, word: &[u8]) -> bool {
    assert_ne!(word, b"del");
    name == "cmd" || name == "sudo" || name == "eval" || name == "zsh" || name == "printf"
        || name == "-u" || word == b"rm" || name == "powershell"
}
"#;

#[test]
fn a_per_shell_alias_of_the_program_table_is_a_name() {
    let text =
        "[[program]]\nname = \"tool\"\naliases = { bash = [\"Tb\"], pwsh_windows = [\"tw\"] }\n";
    let table: toml::Table = toml::from_str(text).unwrap();
    let mut out = BTreeSet::new();
    collect_program_names(&toml::Value::Table(table), &mut out);
    let want: BTreeSet<String> = ["tool", "tb", "tw"].map(String::from).into();
    assert_eq!(out, want);
}

#[test]
fn a_new_file_naming_a_wrapper_shell_echo_or_byte_string_program_is_caught() {
    let got = count(NEW_RULE_FILE, "src/rules/new.rs", &live_names(), &[]);
    assert_eq!((got.programs, got.options), (8, 1), "{got:?}");
}

#[test]
fn a_swapped_name_in_a_legacy_file_is_caught() {
    let rel = "src/scan.rs";
    let source = std::fs::read_to_string(root().join(rel)).unwrap();
    let (frozen, live, record) = (frozen_names(), live_names(), legacy_record());
    assert_eq!(file_mismatch(rel, &source, &frozen, &live, &record), None);
    // `find` and `del` are both program names: the count stays, the literals do not.
    let from = format!("{0}find{0}", '"');
    let to = format!("{0}del{0}", '"');
    assert!(source.contains(&from), "src/scan.rs holds no {from}");
    let swapped = source.replacen(&from, &to, 1);
    assert!(
        file_mismatch(rel, &swapped, &frozen, &live, &record).is_some(),
        "the swap {from} -> {to} went unseen"
    );
}
