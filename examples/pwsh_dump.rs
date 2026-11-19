//! Dump what `parse::pwsh` reads from each row, in the parser spike's format, for comparison with
//! `Parser::ParseInput`:
//!
//!     cargo run --release --example pwsh_dump -- --in <rows.jsonl> --out <dump.jsonl>
//!
//! Per row: `{"id","error","cmds":[[element…]],"comments","methods","lower_error","lost"}`.
//! `error` is the tree's error status (an ERROR or MISSING node), so it compares with the
//! spike's; `lower_error` is what the lowering refused; `lost` counts `command` nodes of the tree
//! the IR does not hold. A command is its name and argument texts as written.

use std::io::{BufRead, BufReader, BufWriter, Write};

use serde_json::{Value, json};
use shellwise::parse::pwsh;
use shellwise::{Os, Shell};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let arg = |flag: &str| {
        args.iter()
            .position(|a| a == flag)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let (Some(input), Some(output)) = (arg("--in"), arg("--out")) else {
        eprintln!("usage: pwsh_dump --in <rows.jsonl> --out <dump.jsonl>");
        std::process::exit(64);
    };
    let rd = BufReader::new(std::fs::File::open(&input).expect("open --in"));
    let mut out = BufWriter::new(std::fs::File::create(&output).expect("create --out"));
    let mut n = 0usize;
    for line in rd.lines() {
        let line = line.expect("read a row");
        if line.trim().is_empty() {
            continue;
        }
        let row: Value = serde_json::from_str(&line).expect("row json");
        let mut v = match row.get("command").and_then(Value::as_str) {
            Some(src) => dump(src),
            None => json!({"error": true, "cmds": [], "absent": true}),
        };
        v["id"] = row["id"].clone();
        writeln!(out, "{v}").expect("write a row");
        n += 1;
    }
    out.flush().expect("flush");
    eprintln!("rows {n}");
    if n == 0 {
        std::process::exit(1);
    }
}

fn dump(src: &str) -> Value {
    let lossy = pwsh::parse_lossy(src, Shell::Pwsh, Os::Windows);
    let seen = pwsh::seen(src, &lossy.script);
    json!({
        "error": lossy.tree_error.is_some(),
        "lost": lossy.tree_commands as i64 - seen.cmds.len() as i64,
        "cmds": seen.cmds,
        "comments": seen.comments,
        "methods": seen.methods,
        "message": lossy.tree_error.as_ref().map(|e| e.message.clone()),
        "error_span": lossy.tree_error.as_ref().map(|e| [e.span.start, e.span.end]),
        "lower_error": lossy.lower_error.as_ref().map(|e| e.message.clone()),
    })
}
