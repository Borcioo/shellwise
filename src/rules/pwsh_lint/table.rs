//! The pwsh 7 command table: `data/pwsh_commands.tsv` (`tools/pwsh_commands.ps1`), turned into
//! static sorted slices by `build.rs`, so a hook call reads it without parsing any text. Every
//! lookup is a binary search on a lowercase key.
//!
//! The table holds pwsh 7 facts only (Ruling 110: Windows PowerShell 5.1 is not a shell the
//! agent's tool runs), so it is reached through `Facts::for_shell`, which gives nothing for 5.1.

use crate::Shell;

/// The parameter set name of a parameter that is in every set.
pub const ALL_SETS: &str = "__AllParameterSets";

/// One member of a parameter set: the set, the position (`-1` for named only), mandatory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Member {
    pub set: &'static str,
    pub position: i32,
    pub mandatory: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Param {
    /// Lowercase.
    pub name: &'static str,
    pub switch: bool,
    /// A provider's dynamic parameter: bound only when no other parameter matches.
    pub dynamic: bool,
    pub aliases: &'static [&'static str],
    pub sets: &'static [Member],
}

/// Which cmdlets bind a common parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Group {
    /// Every cmdlet and advanced function (flag `B`).
    Cmdlet,
    /// Only those that support ShouldProcess (flag `P`): `-WhatIf`, `-Confirm`.
    ShouldProcess,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Common {
    pub group: Group,
    pub param: Param,
}

/// A cmdlet or function, with its own parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cmdlet {
    /// Lowercase.
    pub name: &'static str,
    /// `B` binds the common parameters, `P` also -WhatIf and -Confirm, `R` takes remaining
    /// arguments, `S` a simple function.
    pub flags: &'static str,
    pub params: &'static [Param],
}

impl Cmdlet {
    /// An unknown `-name` is bound as an argument: a parameter takes the remaining arguments, or
    /// the command is a simple function (no `CmdletBinding`), which puts it in `$args`.
    pub fn takes_remaining(&self) -> bool {
        self.flags.contains(['R', 'S'])
    }

    /// Every parameter the command binds, its own first, each with whether it is common.
    pub fn all_params(&self) -> impl Iterator<Item = (&'static Param, bool)> + '_ {
        let flags = self.flags;
        self.params.iter().map(|p| (p, false)).chain(
            COMMON
                .iter()
                .filter(move |c| match c.group {
                    Group::Cmdlet => flags.contains('B'),
                    Group::ShouldProcess => flags.contains('P'),
                })
                .map(|c| (&c.param, true)),
        )
    }
}

/// What PowerShell does with an assignment to a variable of the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VarKind {
    /// Assigning it fails.
    Constant,
    /// Assigning it fails.
    Readonly,
    /// PowerShell overwrites it.
    Automatic,
    /// The session set it; a script may assign it.
    Session,
}

/// A .NET method whose relative path arguments resolve against the process directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dotnet {
    /// `io.file` or `io.directory`.
    pub type_name: &'static str,
    pub method: &'static str,
    pub paths: &'static [usize],
}

include!(concat!(env!("OUT_DIR"), "/pwsh_table.rs"));

/// The table's facts, for the one shell they describe.
#[derive(Debug, Clone, Copy)]
pub struct Facts(());

impl Facts {
    /// The facts for `shell`: pwsh 7 only.
    pub fn for_shell(shell: Shell) -> Option<Facts> {
        (shell == Shell::Pwsh).then_some(Facts(()))
    }

    /// The command `name` (any case), or `None` when the table does not hold it.
    pub fn cmdlet(self, name: &str) -> Option<&'static Cmdlet> {
        let key = name.to_lowercase();
        CMDLETS
            .binary_search_by(|c| c.name.cmp(key.as_str()))
            .ok()
            .map(|i| &CMDLETS[i])
    }

    /// The command an alias (any case) names.
    pub fn alias_target(self, name: &str) -> Option<&'static str> {
        let key = name.to_lowercase();
        ALIASES
            .binary_search_by(|(a, _)| a.cmp(&key.as_str()))
            .ok()
            .map(|i| ALIASES[i].1)
    }

    /// What a session does with an assignment to `$name` (any case).
    pub fn variable_kind(self, name: &str) -> Option<VarKind> {
        let key = name.to_lowercase();
        VARIABLES
            .binary_search_by(|(v, _)| v.cmp(&key.as_str()))
            .ok()
            .map(|i| VARIABLES[i].1)
    }

    pub fn is_approved_verb(self, verb: &str) -> bool {
        let key = verb.to_lowercase();
        VERBS.binary_search(&key.as_str()).is_ok()
    }

    /// The path argument positions of `[<type_name>]::<method>` (any case, with or without
    /// `System.`).
    pub fn dotnet_path_args(self, type_name: &str, method: &str) -> Option<&'static [usize]> {
        let ty = type_name.to_lowercase();
        let ty = ty.strip_prefix("system.").unwrap_or(&ty).to_string();
        let method = method.to_lowercase();
        DOTNET
            .binary_search_by(|d| (d.type_name, d.method).cmp(&(ty.as_str(), method.as_str())))
            .ok()
            .map(|i| DOTNET[i].paths)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The table as the `.tsv` says, read the slow way: the pin the generated code is held to.
    #[derive(Debug, PartialEq, Default)]
    struct Loaded {
        platform: String,
        cmdlets: Vec<(String, String, Vec<String>)>,
        common: Vec<String>,
        aliases: Vec<(String, String)>,
        variables: Vec<(String, String)>,
        verbs: Vec<String>,
        dotnet: Vec<(String, String, Vec<usize>)>,
    }

    fn param_text(p: &Param) -> String {
        let sets: Vec<String> = p
            .sets
            .iter()
            .map(|m| format!("{}:{}:{}", m.set, m.position, u8::from(m.mandatory)))
            .collect();
        format!(
            "{} {} {} {} {}",
            p.name,
            p.switch,
            p.dynamic,
            p.aliases.join(","),
            sets.join(";")
        )
    }

    fn load(text: &str) -> Loaded {
        let mut t = Loaded::default();
        let mut params: Vec<(String, String)> = Vec::new();
        for line in text.lines().filter(|l| !l.is_empty() && !l.starts_with('#')) {
            let f: Vec<&str> = line.split('\t').collect();
            match f[0] {
                "platform" => t.platform = f[1..].join(" "),
                "cmdlet" => t.cmdlets.push((f[1].into(), f[5].into(), Vec::new())),
                "param" => {
                    let sets: Vec<String> = f[6]
                        .split(';')
                        .filter(|m| !m.is_empty())
                        .map(|m| m.rsplit_once(':').unwrap().0.to_string())
                        .collect();
                    params.push((
                        f[1].into(),
                        format!(
                            "{} {} {} {} {}",
                            f[2],
                            f[3] == "switch",
                            f[4] == "1",
                            f[5],
                            sets.join(";")
                        ),
                    ));
                }
                "common" => t.common.push(format!(
                    "{} {} false {}  {}",
                    f[1],
                    f[2] == "switch",
                    f[3],
                    f[4]
                )),
                "aka" => t.aliases.push((f[1].into(), f[2].into())),
                "variable" => t.variables.push((f[1].into(), f[2].into())),
                "verb" => t.verbs.push(f[1].into()),
                "dotnet" => t.dotnet.push((
                    f[1].into(),
                    f[2].into(),
                    f[3].split(',').map(|p| p.parse().unwrap()).collect(),
                )),
                k => panic!("unknown row kind {k}"),
            }
        }
        for (cmd, p) in params {
            t.cmdlets.iter_mut().find(|c| c.0 == cmd).unwrap().2.push(p);
        }
        t.cmdlets.sort();
        t.aliases.sort();
        t.variables.sort();
        t.verbs.sort();
        t.dotnet.sort();
        t
    }

    fn generated() -> Loaded {
        let kind = |k: VarKind| match k {
            VarKind::Constant => "constant",
            VarKind::Readonly => "readonly",
            VarKind::Automatic => "automatic",
            VarKind::Session => "session",
        };
        Loaded {
            platform: PLATFORM.to_string(),
            cmdlets: CMDLETS
                .iter()
                .map(|c| {
                    (
                        c.name.into(),
                        c.flags.into(),
                        c.params.iter().map(param_text).collect(),
                    )
                })
                .collect(),
            common: COMMON
                .iter()
                .map(|c| {
                    let group = match c.group {
                        Group::Cmdlet => "B",
                        Group::ShouldProcess => "P",
                    };
                    format!("{} {group}", param_text(&c.param))
                })
                .collect(),
            aliases: ALIASES.iter().map(|(a, c)| ((*a).into(), (*c).into())).collect(),
            variables: VARIABLES
                .iter()
                .map(|(v, k)| ((*v).into(), kind(*k).into()))
                .collect(),
            verbs: VERBS.iter().map(|v| (*v).into()).collect(),
            dotnet: DOTNET
                .iter()
                .map(|d| (d.type_name.into(), d.method.into(), d.paths.to_vec()))
                .collect(),
        }
    }

    #[test]
    fn the_generated_table_equals_the_tsv() {
        let want = load(include_str!("../../../data/pwsh_commands.tsv"));
        assert!(want.cmdlets.len() > 300 && want.aliases.len() > 100, "{}", want.cmdlets.len());
        assert_eq!(generated(), want);
    }

    #[test]
    fn lookups_find_rows_by_any_case_and_only_for_pwsh_7() {
        let t = Facts::for_shell(Shell::Pwsh).unwrap();
        assert!(Facts::for_shell(Shell::Powershell5).is_none());
        assert!(Facts::for_shell(Shell::Bash(crate::BashProfile::GitBash)).is_none());
        let gci = t.cmdlet("Get-ChildItem").expect("pwsh has Get-ChildItem");
        assert!(gci.params.iter().any(|p| p.name == "recurse"));
        assert!(gci.all_params().any(|(p, common)| common && p.name == "erroraction"));
        assert!(t.cmdlet("get-wmiobject").is_none(), "a 5.1-only cmdlet");
        assert_eq!(t.alias_target("LS"), Some("get-childitem"));
        assert_eq!(t.variable_kind("HOME"), Some(VarKind::Readonly));
        assert_eq!(t.variable_kind("args"), Some(VarKind::Automatic));
        assert!(t.is_approved_verb("Get"));
        assert!(!t.is_approved_verb("Frob"));
        assert_eq!(t.dotnet_path_args("System.IO.Directory", "Move"), Some(&[0, 1][..]));
        assert_eq!(t.dotnet_path_args("IO.File", "ReadAllText"), Some(&[0][..]));
        assert_eq!(t.dotnet_path_args("IO.File", "Exists"), None);
    }
}
