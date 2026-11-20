//! Turns `data/programs.toml` into Rust code that builds the program table, so the hook never
//! parses the table text. `src/programs.rs` includes the output; its test
//! `the_generated_table_equals_the_loaded_text` pins it to `programs::load`, which stays the
//! validator. A value kind this script does not know fails the build.

use std::fmt::Write as _;

/// The `[[program]]` keys that are `Program` fields; every other key goes into `extra`.
const FIELDS: &[&str] = &[
    "name",
    "shells",
    "aliases",
    "kind",
    "value_options",
    "fix",
    "operands",
    "assignments",
    "no_run_options",
    "flag_options",
    "escapes",
    "escape_options",
    "cmd_options",
];

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-changed=data/programs.toml");
    let text = std::fs::read_to_string("data/programs.toml").expect("read data/programs.toml");
    let table: toml::Table = text.parse().expect("data/programs.toml is TOML");
    for key in table.keys() {
        assert!(
            key == "program" || key == "msys" || key == "loops",
            "data/programs.toml: unknown top-level key {key:?}"
        );
    }
    let rows = table["program"].as_array().expect("[[program]] rows");
    let mut out = String::new();
    out.push_str("#[allow(clippy::all, unused_mut)]\nfn generated() -> Table {\n    Table {\n        programs: vec![\n");
    for row in rows {
        let row = row.as_table().expect("a [[program]] row is a table");
        out.push_str(&program(row));
    }
    out.push_str("        ],\n");
    let msys = table
        .get("msys")
        .map(|m| m.as_table().expect("[msys] is a table"));
    let msys_list = |key: &str| msys.and_then(|m| m.get(key)).map_or_else(Vec::new, strings);
    if let Some(m) = msys {
        for key in m.keys() {
            assert!(
                key == "roots" || key == "opt_out",
                "[msys]: unknown key {key:?}"
            );
        }
    }
    writeln!(
        out,
        "        msys: Msys {{ roots: {}, opt_out: {} }},",
        vec_of(&msys_list("roots")),
        vec_of(&msys_list("opt_out"))
    )
    .unwrap();
    let loops = table
        .get("loops")
        .map(|m| m.as_table().expect("[loops] is a table"));
    let loops_list = |key: &str| {
        loops
            .and_then(|m| m.get(key))
            .map_or_else(Vec::new, strings)
    };
    if let Some(m) = loops {
        for key in m.keys() {
            assert!(
                [
                    "exits",
                    "always",
                    "clocks",
                    "compares",
                    "hint_bash",
                    "hint_pwsh"
                ]
                .contains(&key.as_str()),
                "[loops]: unknown key {key:?}"
            );
        }
    }
    let loops_text = |key: &str| {
        loops
            .and_then(|m| m.get(key))
            .map_or("", |v| v.as_str().expect("a [loops] hint is a string"))
            .to_string()
    };
    writeln!(
        out,
        "        loops: Loops {{ exits: {}, always: {}, clocks: {}, compares: {}, hint_bash: {}, hint_pwsh: {} }},",
        vec_of(&loops_list("exits")),
        vec_of(&loops_list("always")),
        vec_of(&loops_list("clocks")),
        vec_of(&loops_list("compares")),
        string_expr(&loops_text("hint_bash")),
        string_expr(&loops_text("hint_pwsh"))
    )
    .unwrap();
    out.push_str("    }\n}\n");
    let path = std::path::Path::new(&std::env::var("OUT_DIR").unwrap()).join("programs_table.rs");
    std::fs::write(path, out).expect("write the generated table");
    pwsh_table::generate(std::path::Path::new(&std::env::var("OUT_DIR").unwrap()));
    rule_docs::generate(std::path::Path::new(&std::env::var("OUT_DIR").unwrap()));
}

#[path = "build/pwsh_table.rs"]
mod pwsh_table;

#[path = "build/rule_docs.rs"]
mod rule_docs;

fn program(row: &toml::Table) -> String {
    let list = |key: &str| row.get(key).map_or_else(Vec::new, strings);
    let name = row
        .get("name")
        .and_then(|v| v.as_str())
        .expect("a row has a name");
    let fix = row.get("fix").map(|v| v.as_str().expect("fix is a string"));
    let operands = row.get("operands").map_or(0, |v| {
        let n = v.as_integer().expect("operands is an integer");
        usize::try_from(n).expect("operands is not negative")
    });
    let assignments = row
        .get("assignments")
        .is_some_and(|v| v.as_bool().expect("assignments is a bool"));
    let kinds: Vec<String> = list("kind")
        .iter()
        .map(|k| format!("Kind::{}", variant(k)))
        .collect();
    let escapes = row.get("escapes").map(|v| {
        format!(
            "Escapes::{}",
            variant(v.as_str().expect("escapes is a string"))
        )
    });
    let aliases = row
        .get("aliases")
        .map(|v| v.as_table().expect("aliases is a table"));
    if let Some(a) = aliases {
        for key in a.keys() {
            assert!(
                ["bash", "pwsh_windows", "pwsh_posix"].contains(&key.as_str()),
                "{name}: unknown alias key {key:?}"
            );
        }
    }
    let alias = |key: &str| {
        aliases
            .and_then(|a| a.get(key))
            .map_or_else(Vec::new, strings)
    };
    let mut extra = String::from("{ let mut t = toml::Table::new(); ");
    for (key, value) in row.iter().filter(|(k, _)| !FIELDS.contains(&k.as_str())) {
        write!(
            extra,
            "t.insert({key:?}.to_string(), {}); ",
            value_expr(value)
        )
        .unwrap();
    }
    extra.push_str("t }");
    format!(
        "            Program {{ name: {}, shells: {}, aliases: Aliases {{ bash: {}, pwsh_windows: {}, pwsh_posix: {} }}, kind: vec![{}], value_options: {}, fix: {}, operands: {operands}, assignments: {assignments}, no_run_options: {}, flag_options: {}, escapes: {}, escape_options: {}, cmd_options: {}, extra: {extra} }},\n",
        string_expr(name),
        vec_of(&list("shells")),
        vec_of(&alias("bash")),
        vec_of(&alias("pwsh_windows")),
        vec_of(&alias("pwsh_posix")),
        kinds.join(", "),
        vec_of(&list("value_options")),
        fix.map_or("None".to_string(), |f| format!("Some({})", string_expr(f))),
        vec_of(&list("no_run_options")),
        vec_of(&list("flag_options")),
        escapes.map_or("None".to_string(), |e| format!("Some({e})")),
        vec_of(&list("escape_options")),
        vec_of(&list("cmd_options")),
    )
}

/// `native-msys` -> `NativeMsys`: the serde kebab-case spelling as a Rust variant. An unknown
/// spelling names no variant and fails the compile.
fn variant(spelling: &str) -> String {
    spelling
        .split('-')
        .map(|part| {
            let mut c = part.chars();
            c.next()
                .map_or_else(String::new, |f| f.to_uppercase().chain(c).collect())
        })
        .collect()
}

fn strings(v: &toml::Value) -> Vec<String> {
    v.as_array()
        .expect("a list")
        .iter()
        .map(|x| x.as_str().expect("a list of strings").to_string())
        .collect()
}

fn string_expr(s: &str) -> String {
    format!("{s:?}.to_string()")
}

fn vec_of(items: &[String]) -> String {
    let items: Vec<String> = items.iter().map(|s| string_expr(s)).collect();
    format!("vec![{}]", items.join(", "))
}

/// A `toml::Value` built in code. Only the kinds the table uses; any other fails the build.
fn value_expr(v: &toml::Value) -> String {
    match v {
        toml::Value::String(s) => format!("toml::Value::String({})", string_expr(s)),
        toml::Value::Integer(n) => format!("toml::Value::Integer({n})"),
        toml::Value::Boolean(b) => format!("toml::Value::Boolean({b})"),
        toml::Value::Array(a) => {
            let items: Vec<String> = a.iter().map(value_expr).collect();
            format!("toml::Value::Array(vec![{}])", items.join(", "))
        }
        toml::Value::Table(t) => {
            let mut s = String::from("toml::Value::Table({ let mut t = toml::Table::new(); ");
            for (key, value) in t {
                write!(s, "t.insert({key:?}.to_string(), {}); ", value_expr(value)).unwrap();
            }
            s.push_str("t })");
            s
        }
        other => panic!(
            "data/programs.toml: a {} value, which build.rs does not emit",
            other.type_str()
        ),
    }
}
