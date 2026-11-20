//! Turns `data/pwsh_commands.tsv` into static sorted slices (`OUT_DIR/pwsh_table.rs`), so the hook
//! never parses the table text. `src/rules/pwsh_lint/table.rs` includes the output and its test
//! `the_generated_table_equals_the_tsv` pins it to the file. A malformed row fails the build.

use std::collections::BTreeMap;
use std::fmt::Write as _;

const SOURCE: &str = "data/pwsh_commands.tsv";

pub fn generate(out_dir: &std::path::Path) {
    println!("cargo::rerun-if-changed={SOURCE}");
    let text = std::fs::read_to_string(SOURCE).expect("read data/pwsh_commands.tsv");
    let mut platform = None;
    // name -> (flags, param rows in file order)
    let mut cmdlets: BTreeMap<String, (String, Vec<String>)> = BTreeMap::new();
    let mut params: Vec<(String, String)> = Vec::new();
    let mut common: Vec<String> = Vec::new();
    let mut aliases: BTreeMap<String, String> = BTreeMap::new();
    let mut variables: BTreeMap<String, String> = BTreeMap::new();
    let mut verbs: Vec<String> = Vec::new();
    let mut dotnet: BTreeMap<(String, String), String> = BTreeMap::new();
    for (n, line) in text.lines().enumerate() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split('\t').collect();
        let at = |want: usize| {
            assert!(
                f.len() == want,
                "{SOURCE}:{}: a {} row has {} columns, not {want}",
                n + 1,
                f[0],
                f.len()
            );
        };
        match f[0] {
            "platform" => {
                at(4);
                assert!(platform.is_none(), "{SOURCE}: two platform rows");
                platform = Some(format!("{} {} {}", f[1], f[2], f[3]));
            }
            "cmdlet" => {
                at(6);
                let flags = f[5];
                assert!(
                    flags.chars().all(|c| "BPRS".contains(c)),
                    "{SOURCE}:{}: unknown flag in {flags:?}",
                    n + 1
                );
                let old = cmdlets.insert(f[1].to_string(), (flags.to_string(), Vec::new()));
                assert!(old.is_none(), "{SOURCE}:{}: {} twice", n + 1, f[1]);
            }
            "param" => {
                at(7);
                let switch = f[3] == "switch";
                let dynamic = match f[4] {
                    "0" => false,
                    "1" => true,
                    d => panic!("{SOURCE}:{}: dynamic {d:?}", n + 1),
                };
                let row = format!(
                    "Param {{ name: {:?}, switch: {switch}, dynamic: {dynamic}, aliases: &[{}], sets: &[{}] }}",
                    f[2],
                    list(f[5]),
                    members(f[6], n + 1)
                );
                params.push((f[1].to_string(), row));
            }
            "common" => {
                at(5);
                let group = match f[4] {
                    "B" => "Group::Cmdlet",
                    "P" => "Group::ShouldProcess",
                    g => panic!("{SOURCE}:{}: common group {g:?}", n + 1),
                };
                common.push(format!(
                    "Common {{ group: {group}, param: Param {{ name: {:?}, switch: {}, dynamic: false, aliases: &[{}], sets: &[] }} }}",
                    f[1],
                    f[2] == "switch",
                    list(f[3])
                ));
            }
            "aka" => {
                at(3);
                let old = aliases.insert(f[1].to_string(), f[2].to_string());
                assert!(old.is_none(), "{SOURCE}:{}: alias {} twice", n + 1, f[1]);
            }
            "variable" => {
                at(3);
                let kind = match f[2] {
                    "constant" => "VarKind::Constant",
                    "readonly" => "VarKind::Readonly",
                    "automatic" => "VarKind::Automatic",
                    "session" => "VarKind::Session",
                    k => panic!("{SOURCE}:{}: variable kind {k:?}", n + 1),
                };
                let old = variables.insert(f[1].to_string(), kind.to_string());
                assert!(old.is_none(), "{SOURCE}:{}: variable {} twice", n + 1, f[1]);
            }
            "verb" => {
                at(2);
                verbs.push(f[1].to_string());
            }
            "dotnet" => {
                at(4);
                let positions: Vec<String> = f[3]
                    .split(',')
                    .map(|p| {
                        p.parse::<usize>()
                            .unwrap_or_else(|_| panic!("{SOURCE}:{}: position {p:?}", n + 1))
                            .to_string()
                    })
                    .collect();
                let old = dotnet.insert((f[1].to_string(), f[2].to_string()), positions.join(", "));
                assert!(
                    old.is_none(),
                    "{SOURCE}:{}: {}::{} twice",
                    n + 1,
                    f[1],
                    f[2]
                );
            }
            k => panic!("{SOURCE}:{}: unknown row kind {k:?}", n + 1),
        }
    }
    for (command, row) in params {
        cmdlets
            .get_mut(&command)
            .unwrap_or_else(|| panic!("{SOURCE}: a param row for the unknown command {command}"))
            .1
            .push(row);
    }
    verbs.sort();
    verbs.dedup();
    let mut out =
        String::from("// Generated by build/pwsh_table.rs from data/pwsh_commands.tsv.\n");
    writeln!(
        out,
        "/// The shell the facts come from; read by the pin test.\n#[allow(dead_code)]\npub static PLATFORM: &str = {:?};",
        platform.expect("a platform row")
    )
    .unwrap();
    out.push_str("pub static CMDLETS: &[Cmdlet] = &[\n");
    for (name, (flags, ps)) in &cmdlets {
        writeln!(
            out,
            "    Cmdlet {{ name: {name:?}, flags: {flags:?}, params: &[{}] }},",
            ps.join(", ")
        )
        .unwrap();
    }
    out.push_str("];\npub static COMMON: &[Common] = &[\n");
    for c in &common {
        writeln!(out, "    {c},").unwrap();
    }
    out.push_str("];\npub static ALIASES: &[(&str, &str)] = &[\n");
    for (a, c) in &aliases {
        writeln!(out, "    ({a:?}, {c:?}),").unwrap();
    }
    out.push_str("];\npub static VARIABLES: &[(&str, VarKind)] = &[\n");
    for (v, k) in &variables {
        writeln!(out, "    ({v:?}, {k}),").unwrap();
    }
    out.push_str("];\npub static VERBS: &[&str] = &[\n");
    for v in &verbs {
        writeln!(out, "    {v:?},").unwrap();
    }
    out.push_str("];\npub static DOTNET: &[Dotnet] = &[\n");
    for ((ty, method), positions) in &dotnet {
        writeln!(
            out,
            "    Dotnet {{ type_name: {ty:?}, method: {method:?}, paths: &[{positions}] }},"
        )
        .unwrap();
    }
    out.push_str("];\n");
    std::fs::write(out_dir.join("pwsh_table.rs"), out).expect("write the generated pwsh table");
}

fn list(s: &str) -> String {
    s.split(',')
        .filter(|x| !x.is_empty())
        .map(|x| format!("{x:?}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// `set:position:mandatory:pipeline;...` as `Member` expressions.
fn members(s: &str, line: usize) -> String {
    s.split(';')
        .filter(|m| !m.is_empty())
        .map(|m| {
            // A set name may hold `:` itself (`PowerShellGet:PackageByInputObject`): the last three
            // fields are the numbers.
            let mut p: Vec<&str> = m.rsplitn(4, ':').collect();
            assert!(p.len() == 4, "{SOURCE}:{line}: member {m:?}");
            p.reverse();
            let position: i32 = p[1]
                .parse()
                .unwrap_or_else(|_| panic!("{SOURCE}:{line}: position {:?}", p[1]));
            let flag = |v: &str| match v {
                "0" => false,
                "1" => true,
                x => panic!("{SOURCE}:{line}: flag {x:?}"),
            };
            format!(
                "Member {{ set: {:?}, position: {position}, mandatory: {} }}",
                p[0],
                flag(p[2])
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}
