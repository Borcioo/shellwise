//! Rules as data: program names and option spellings belong in the tables, not in code.
//!
//! A **program literal** is a string literal outside `#[cfg(test)]` whose value, lowercased with a
//! trailing `.exe` removed, names a program in the name sources. An **option literal** matches
//! `^(-{1,2}[A-Za-z][A-Za-z0-9-]*|/[A-Za-z]{1,2})$`. Under `src/rules/`, a literal passed to
//! `Regex::new` is flagged too. Literals inside macro calls count.
//!
//! Each file's count must equal its cap. Files that existed at acf4643 are counted against the
//! name set frozen then (`tests/shape_names_acf4643.txt`), so a table that grows cannot raise
//! their counts; every other file is counted against the live name sources and has cap 0 unless
//! `NEW_FILES` records one. `src/programs.rs`, the reader of the table, is not counted.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use syn::visit::{self, Visit};

/// (file, program literals, option literals, `Regex::new` literals) for every file under `src/`
/// at acf4643, from the counter's first run there. A cap only goes down, with the commit that
/// removes the literals.
const LEGACY: &[(&str, usize, usize, usize)] = &[
    ("src/adapter/check_json.rs", 0, 0, 0),
    ("src/adapter/mod.rs", 0, 0, 0),
    ("src/config.rs", 0, 0, 0),
    ("src/fs/cmdlet_table.rs", 1232, 0, 0),
    ("src/fs/mod.rs", 0, 0, 0),
    ("src/fs/resolve.rs", 161, 28, 0),
    ("src/fs/walk.rs", 0, 0, 0),
    ("src/fs/windows.rs", 0, 0, 0),
    ("src/ir.rs", 0, 0, 0),
    ("src/level.rs", 0, 0, 0),
    ("src/lib.rs", 0, 0, 0),
    ("src/main.rs", 0, 0, 0),
    ("src/parse/bash.rs", 4, 10, 0),
    ("src/parse/mod.rs", 0, 0, 0),
    ("src/parse/pwsh.rs", 1, 0, 0),
    ("src/rules/mod.rs", 1, 0, 0),
    ("src/scan.rs", 16, 29, 0),
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
];

/// The file that reads `data/programs.toml`: its literals are the table's own keys.
const TABLE_READER: &str = "src/programs.rs";

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Count {
    programs: usize,
    options: usize,
    regexes: usize,
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every lowercased name the three sources hold: `data/destructive.toml` names (a name with
/// spaces also gives its first word), `src/parse/pwsh_names.txt` aliases, targets and commands,
/// and the `name`/`aliases` strings of `data/programs.toml` when it exists.
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
    let programs = root().join("data/programs.toml");
    if programs.exists() {
        let text = std::fs::read_to_string(&programs).unwrap();
        let table: toml::Table = toml::from_str(&text).unwrap();
        collect_program_names(&toml::Value::Table(table), &mut out);
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
    count: Count,
}

impl Counter<'_> {
    fn literal(&mut self, value: &str) {
        if self.allowed.contains(&value) {
            return;
        }
        let lower = value.to_lowercase();
        let name = lower.strip_suffix(".exe").unwrap_or(&lower);
        if self.names.contains(name) {
            self.count.programs += 1;
        }
        if is_option(value) {
            self.count.options += 1;
        }
    }

    /// Every string literal in a macro's tokens, nested groups included.
    fn tokens(&mut self, mut cursor: syn::buffer::Cursor) {
        while !cursor.eof() {
            if let Some((inside, _, _, next)) = cursor.any_group() {
                self.tokens(inside);
                cursor = next;
            } else if let Some((lit, next)) = cursor.literal() {
                if let syn::Lit::Str(s) = syn::Lit::new(lit) {
                    self.literal(&s.value());
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
                && matches!(c.args.first(), Some(syn::Expr::Lit(l)) if matches!(l.lit, syn::Lit::Str(_)))
            {
                self.count.regexes += 1;
            }
        }
        visit::visit_expr_call(self, c);
    }
}

fn count(source: &str, rel: &str, names: &BTreeSet<String>, allowed: &[&str]) -> Count {
    let file = syn::parse_file(source).unwrap_or_else(|e| panic!("{rel}: {e}"));
    let mut c = Counter {
        names,
        allowed,
        in_rules: rel.starts_with("src/rules/"),
        count: Count::default(),
    };
    c.visit_file(&file);
    c.count
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

#[test]
fn every_file_holds_exactly_its_cap_of_literals() {
    let frozen = frozen_names();
    let live = live_names();
    let mut files = Vec::new();
    rust_files(&root().join("src"), &mut files);
    assert!(!files.is_empty(), "read 0 files under src/");
    let mut wrong = Vec::new();
    let mut table = Vec::new();
    for path in &files {
        let rel = rel(path);
        if rel == TABLE_READER {
            continue;
        }
        let source = std::fs::read_to_string(path).unwrap();
        let legacy = LEGACY.iter().find(|(f, ..)| *f == rel);
        let (got, cap) = match legacy {
            Some(&(_, p, o, r)) => (
                count(&source, &rel, &frozen, &[]),
                Count {
                    programs: p,
                    options: o,
                    regexes: r,
                },
            ),
            None => {
                let allowed = NEW_FILES
                    .iter()
                    .find(|(f, ..)| *f == rel)
                    .map_or(&[][..], |(_, a, _)| *a);
                (count(&source, &rel, &live, allowed), Count::default())
            }
        };
        table.push(format!(
            "    (\"{rel}\", {}, {}, {}),",
            got.programs, got.options, got.regexes
        ));
        if got != cap {
            wrong.push(format!("{rel}: count {got:?}, cap {cap:?}"));
        }
    }
    table.sort();
    assert!(
        wrong.is_empty(),
        "{}\ncounts:\n{}",
        wrong.join("\n"),
        table.join("\n")
    );
}
