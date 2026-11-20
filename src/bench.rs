//! `shellwise bench`: replay the corpus in process through `analyse` and report the meters.
//!
//! Every corpus row runs as a command line with the default config (or `--config`, the file the
//! host setup installs), the row's cwd, on the OS its cwd shape names (`CwdShape`) and with a fixed
//! synthetic environment of that OS (`WINDOWS_ENV`, `POSIX_ENV`), never the machine's own. The
//! result still depends on the machine that runs it: the rules read this machine's disk (a row
//! whose cwd is gone here cannot fire a rule that reads the disk: `rows_cwd_missing`,
//! `disk_reading_rules`; system paths are read by the row's OS), and the default config's allowed
//! root is this machine's temp folder. The report keeps four lines apart
//! (Global Constraints, F8): meter 1, rows the real shell's parser also refuses, parity denials
//! baseline-guard already makes, and the own line of the owner-requested length rule; then meter 2
//! (split by those lines and by rule family), `parse_kind_false_deny`, per rule × label counts,
//! parity per installed baseline-guard rule and its exception keys, the in-process latency (the
//! median over `--passes` passes) and each rule's own cost.
//!
//! A baseline-guard id reaches a shellwise id only through the rule map (`tools/corpus/rule_map.toml`,
//! compiled in; `--rule-map` replaces it). The meters are reported, never gating; the run fails
//! (exit 1, one `FAIL:` line each) only when it cannot measure or a known answer is wrong:
//! - 0 rows, or 0 rows for one shell, or 0 rows joined to the baseline;
//! - a baseline-guard id in the baseline or in `known.jsonl` that the map does not name;
//! - a map key without a `runs_on` entry, or a mapped rule that fires outside its entry on a row
//!   baseline-guard denies with that id;
//! - a config or a parity exception file that does not load;
//! - 0 `known.jsonl` rows checked, a checked row missing from the corpus, or one missing its rule;
//! - with `--diff`, a second replay of the same build (the head-vs-head control) that moves a row.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::io::{self, BufRead, BufReader};
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use serde::Deserialize;
use serde_json::{Value, json};

use shellwise::adapter::claude_code::shell_for;
use shellwise::config::Config;
use shellwise::fs::resolve::env_view;
use shellwise::fs::{FileId, Fs, LinkKind, Meta, RealFs, SharedFs};
use shellwise::ir::{EnvView, Script};
use shellwise::level::{Finding, Level, Verdict};
use shellwise::parse::{self, ParseKind};
use shellwise::rules::inline_length;
use shellwise::rules::parse_error::PARSE_ERROR;
use shellwise::rules::{Ctx, Rule};
use shellwise::{
    ANALYSIS_INCOMPLETE, AnalyseInput, BashProfile, CheckInput, Deadline, MAX_INPUT_BYTES, Origin,
    Os, Shell, analyse, rules, scan,
};

/// The rule map every run uses unless `--rule-map` names another.
const RULE_MAP: &str = include_str!("../tools/corpus/rule_map.toml");
/// The known-answer slice `baseline.py --known` writes next to the corpus.
const KNOWN_NAME: &str = "known.jsonl";
/// Meter 1: at most this share of the non-destructive `ok` rows.
const METER_1_SHARE: f64 = 0.001;
/// The own line: at most this share of the `ok` rows of each shell.
const OWN_LINE_SHARE: f64 = 0.005;
/// Meter 2: at most this many destructive `ok` rows denied per corpus day.
const METER_2_PER_DAY: f64 = 2.0;
/// The header of a `--dump` file.
const DUMP_HEADER: &str = "id\tlevel\trules\traw_hit\trule_levels";
/// The header of a dump written before the `rule_levels` column; `--diff` still reads it.
const OLD_DUMP_HEADER: &str = "id\tlevel\trules\traw_hit";
/// The stack of the replay thread, as large as the worker `analyse` runs the parse on.
const REPLAY_STACK: usize = 64 * 1024 * 1024;
/// What the hook reads of its environment on Windows (`env_view`): `~` and `$HOME` from
/// `USERPROFILE`, Git Bash's `/tmp` from `TEMP`. Synthetic: no real user name.
const WINDOWS_ENV: [(&str, &str); 3] = [
    ("USERPROFILE", r"C:\Profiles\bench"),
    ("TEMP", r"C:\Profiles\bench\AppData\Local\Temp"),
    ("TMP", r"C:\Profiles\bench\AppData\Local\Temp"),
];
/// What the hook reads of its environment on Linux: `HOME`; `/tmp` is itself.
const POSIX_ENV: [(&str, &str); 1] = [("HOME", "/h/bench")];
/// The corpus labels (`extract.py`), the keys a parity exception may name.
const LABELS: [&str; 4] = ["ok", "failed", "denied-hook", "denied-permission"];
/// The parity shape classes the bench computes for a row baseline-guard denies and shellwise allows.
const SHAPE_MAPPED_WARN: &str = "mapped-warn";
const SHAPE_MAPPED_SILENT: &str = "mapped-silent";
const SHAPES: [&str; 2] = [SHAPE_MAPPED_WARN, SHAPE_MAPPED_SILENT];

/// The shape of a row's recorded cwd, which names the OS the row ran on (the corpus records no
/// platform). Claude Code records the cwd in its own OS's form.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum CwdShape {
    /// `C:\…` or `C:/…`: Windows.
    Drive,
    /// `\\host\share\…` or `//host/share/…`: Windows (a Windows process on a share, the WSL one
    /// included).
    Unc,
    /// `/mnt/<letter>` or below: Linux, a WSL session in a mounted Windows drive.
    WslMnt,
    /// Any other `/…`: Linux.
    Posix,
    /// No cwd: Windows, as before (a relative path then has no location on either OS).
    Missing,
    /// Anything else (a relative cwd): Windows, as before; the location stays unknown.
    Other,
}

impl CwdShape {
    const ALL: [CwdShape; 6] = [
        CwdShape::Drive,
        CwdShape::Unc,
        CwdShape::WslMnt,
        CwdShape::Posix,
        CwdShape::Missing,
        CwdShape::Other,
    ];

    fn of(cwd: Option<&str>) -> CwdShape {
        let Some(c) = cwd.filter(|c| !c.is_empty()) else {
            return CwdShape::Missing;
        };
        let b = c.as_bytes();
        if b.len() >= 3
            && b[0].is_ascii_alphabetic()
            && b[1] == b':'
            && matches!(b[2], b'\\' | b'/')
        {
            CwdShape::Drive
        } else if c.starts_with(r"\\") || c.starts_with("//") {
            CwdShape::Unc
        } else if let Some(rest) = c.strip_prefix("/mnt/")
            && rest.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
            && matches!(rest.as_bytes().get(1), None | Some(b'/'))
        {
            CwdShape::WslMnt
        } else if c.starts_with('/') {
            CwdShape::Posix
        } else {
            CwdShape::Other
        }
    }

    fn os(self) -> Os {
        match self {
            CwdShape::WslMnt | CwdShape::Posix => Os::Posix,
            CwdShape::Drive | CwdShape::Unc | CwdShape::Missing | CwdShape::Other => Os::Windows,
        }
    }

    fn name(self) -> &'static str {
        match self {
            CwdShape::Drive => "drive",
            CwdShape::Unc => "unc",
            CwdShape::WslMnt => "wsl-mnt",
            CwdShape::Posix => "posix",
            CwdShape::Missing => "missing",
            CwdShape::Other => "other",
        }
    }
}

/// The name a report gives an OS.
fn os_name(os: Os) -> &'static str {
    match os {
        Os::Windows => "Windows",
        Os::Posix => "Linux",
    }
}

/// What the hook would see for this row: the shell its tool runs on the row's OS, the OS, the
/// cwd and the synthetic environment of that OS.
fn replay_input(row: &CorpusRow, tool: Tool) -> (Shell, Os, Option<PathBuf>, EnvView) {
    let os = CwdShape::of(row.cwd.as_deref()).os();
    let shell = tool.shell(os);
    let vars: &[(&str, &str)] = match os {
        Os::Windows => &WINDOWS_ENV,
        Os::Posix => &POSIX_ENV,
    };
    let env = env_view(
        shell,
        os,
        vars.iter().map(|(k, v)| (k.to_string(), v.to_string())),
    );
    (shell, os, row.cwd.as_ref().map(PathBuf::from), env)
}

#[derive(clap::Args)]
pub struct BenchArgs {
    /// The corpus `extract.py` writes.
    #[arg(long, value_name = "FILE")]
    corpus: PathBuf,
    /// The baseline-guard replay `baseline.py` writes.
    #[arg(long, value_name = "FILE")]
    baseline: PathBuf,
    /// Where the JSON report goes.
    #[arg(long, value_name = "FILE")]
    out: PathBuf,
    /// The known-answer slice; default: `known.jsonl` next to the corpus.
    #[arg(long, value_name = "FILE")]
    known: Option<PathBuf>,
    /// A rule map in place of the compiled-in `tools/corpus/rule_map.toml`.
    #[arg(long, value_name = "FILE")]
    rule_map: Option<PathBuf>,
    /// What the real shells' parsers say of each row (`tools/corpus/real_parse.ps1`).
    #[arg(long, value_name = "FILE")]
    real_parse: Option<PathBuf>,
    /// Write one line per row: id, level, rule ids, whether the raw scan hits, `rule:level` pairs.
    #[arg(long, value_name = "FILE")]
    dump: Option<PathBuf>,
    /// An earlier dump: list every row whose level or rules moved since.
    #[arg(long, value_name = "FILE")]
    diff: Option<PathBuf>,
    /// Boxed so the `bench` subcommand stays near the size of the others.
    #[command(flatten)]
    measure: Box<MeasureArgs>,
}

/// What the replay measures with: the config, the parity exceptions and the timing passes.
#[derive(clap::Args)]
struct MeasureArgs {
    /// An integration config file (the one the host setup installs); the default config otherwise.
    /// Neither the user file nor a repo file is read.
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,
    /// Parity exceptions (`tests/cases/parity_exceptions.toml` format: `[[exception]]` with
    /// `baseline_guard`, `shape`, `label`, `expected`, `why`).
    #[arg(long, value_name = "FILE")]
    parity_exceptions: Option<PathBuf>,
    /// Timing passes over the corpus: the latency and each rule's cost are the median over them.
    /// The verdicts come from the first.
    #[arg(long, value_name = "N", default_value_t = 3)]
    passes: u32,
}

#[derive(Deserialize)]
struct CorpusRow {
    id: String,
    ts: String,
    tool: String,
    command: String,
    cwd: Option<String>,
    label: String,
    destructive: bool,
}

#[derive(Deserialize)]
struct BaselineRow {
    id: String,
    /// `check()`: the full set, which the known slice and the `runs_on` check also read.
    #[serde(default)]
    full: Vec<String>,
    installed: Vec<String>,
}

#[derive(Deserialize)]
struct KnownRow {
    id: String,
    /// The OS `baseline.py` read from the row's cwd; must be the one the bench replays it on.
    #[serde(default)]
    os: Option<String>,
    expected_rules: Vec<String>,
}

/// `tools/corpus/rule_map.toml`; its header documents the keys.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleMap {
    map: BTreeMap<String, String>,
    #[serde(default)]
    own_line_rules: Vec<String>,
    runs_on: BTreeMap<String, RunsOn>,
}

/// Where the shellwise rule a baseline-guard id maps to can fire, read from that rule's gate.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunsOn {
    tools: Vec<String>,
    os: Vec<String>,
    why: String,
}

/// A parity exception file.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ParityFile {
    #[serde(default)]
    exception: Vec<ParityException>,
}

/// Rows of one installed baseline-guard rule that shellwise allows on purpose, keyed by the rule,
/// a shape class the bench computes (`SHAPES`) and the row's label, with the expected count of
/// that key; never row ids (F9).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ParityException {
    baseline_guard: String,
    shape: String,
    label: String,
    expected: u64,
    why: String,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Tool {
    Bash,
    Pwsh,
}

impl Tool {
    const ALL: [Tool; 2] = [Tool::Bash, Tool::Pwsh];

    fn from_name(name: &str) -> Option<Tool> {
        Tool::ALL.into_iter().find(|t| t.name() == name)
    }

    fn name(self) -> &'static str {
        match self {
            Tool::Bash => "Bash",
            Tool::Pwsh => "PowerShell",
        }
    }

    /// The shell the hook picks for this tool on `os` (Git Bash on Windows, POSIX bash on Linux).
    fn shell(self, os: Os) -> Shell {
        shell_for(self.name(), os).expect("Bash and PowerShell are shell tools")
    }
}

/// One row's verdict, reduced to what the report and the dump need.
#[derive(Clone)]
struct Replayed {
    level: Level,
    /// Each rule once, at its highest level, in the order the findings name them.
    rules: Vec<(&'static str, Level)>,
    /// `None` when the raw scan panicked.
    raw_hit: Option<bool>,
    nanos: u64,
    /// The finding ids the delete and git rules gave this row in the timed run of the rules.
    delete_git: Vec<&'static str>,
}

impl Replayed {
    fn from_verdict(v: &Verdict, raw_hit: Option<bool>, nanos: u64) -> Replayed {
        let mut rules: Vec<(&'static str, Level)> = Vec::new();
        for f in &v.findings {
            match rules.iter_mut().find(|(r, _)| *r == f.rule) {
                Some((_, level)) => *level = (*level).max(f.level),
                None => rules.push((f.rule, f.level)),
            }
        }
        Replayed {
            level: v.level,
            rules,
            raw_hit,
            nanos,
            delete_git: Vec::new(),
        }
    }

    fn denied(&self) -> bool {
        self.level >= Level::Break
    }

    fn deny_rules(&self) -> BTreeSet<&'static str> {
        self.rules
            .iter()
            .filter(|(_, l)| *l >= Level::Break)
            .map(|(r, _)| *r)
            .collect()
    }

    /// A parse error of a deny kind: with the default config it is the only finding, at break.
    fn deny_kind(&self) -> bool {
        self.rules
            .iter()
            .any(|(r, l)| *r == PARSE_ERROR && *l == Level::Break)
    }

    fn names(&self, id: &str) -> bool {
        self.rules.iter().any(|(r, _)| *r == id)
    }

    fn rule_list(&self) -> String {
        if self.rules.is_empty() {
            return "-".to_string();
        }
        self.rules
            .iter()
            .map(|(r, _)| *r)
            .collect::<Vec<_>>()
            .join(",")
    }

    fn rule_levels(&self) -> String {
        if self.rules.is_empty() {
            return "-".to_string();
        }
        self.rules
            .iter()
            .map(|(r, l)| format!("{r}:{}", l.as_str()))
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// Run the bench and return the exit code.
pub fn run(args: BenchArgs) -> i32 {
    match bench(&args) {
        Ok(fails) if fails.is_empty() => 0,
        Ok(fails) => {
            for f in &fails {
                println!("FAIL: {f}");
            }
            1
        }
        Err(e) => {
            println!("FAIL: {e}");
            1
        }
    }
}

/// The config the replay runs with: the integration file alone, or the default. Any finding of
/// the load (an unknown key, a bad value, a missing file) stops the run.
fn load_config(path: Option<&Path>) -> Result<Config, String> {
    let Some(path) = path else {
        return Ok(Config::default());
    };
    let (cfg, findings) = Config::load(Some(path), None, None);
    match findings.first() {
        Some(f) => Err(format!(
            "the config did not load ({}): {}",
            path.display(),
            f.message
        )),
        None => Ok(cfg),
    }
}

/// The parity exceptions of `path`, each key once; none without the flag.
fn load_exceptions(path: Option<&Path>, map: &RuleMap) -> Result<Vec<ParityException>, String> {
    let Some(path) = path else {
        return Ok(Vec::new());
    };
    let name = path.display().to_string();
    let text = fs::read_to_string(path).map_err(|e| format!("cannot read {name}: {e}"))?;
    let file: ParityFile = toml::from_str(&text).map_err(|e| format!("{name}: {e}"))?;
    let mut seen: BTreeSet<(&str, &str, &str)> = BTreeSet::new();
    for e in &file.exception {
        if !map.map.contains_key(&e.baseline_guard) {
            return Err(format!(
                "{name}: the parity exception {} names {}, which the map does not",
                e.shape, e.baseline_guard
            ));
        }
        if !SHAPES.contains(&e.shape.as_str()) {
            return Err(format!(
                "{name}: the parity exception of {}: shape {} is not one of {}",
                e.baseline_guard,
                e.shape,
                SHAPES.join(", ")
            ));
        }
        if !LABELS.contains(&e.label.as_str()) {
            return Err(format!(
                "{name}: the parity exception of {}: label {} is not one of {}",
                e.baseline_guard,
                e.label,
                LABELS.join(", ")
            ));
        }
        if e.why.is_empty() || e.expected == 0 {
            return Err(format!(
                "{name}: a parity exception of {} needs a why and an expected count above 0",
                e.baseline_guard
            ));
        }
        if !seen.insert((&e.baseline_guard, &e.shape, &e.label)) {
            return Err(format!(
                "{name}: {} {} {} is listed twice",
                e.baseline_guard, e.shape, e.label
            ));
        }
    }
    Ok(file.exception)
}

/// The whole run. `Err` stops it before a report exists; the returned list holds the failures
/// found after the report was written.
fn bench(args: &BenchArgs) -> Result<Vec<String>, String> {
    if args.measure.passes == 0 {
        return Err("--passes must be at least 1".to_string());
    }
    let map = load_rule_map(args.rule_map.as_deref())?;
    let cfg = load_config(args.measure.config.as_deref())?;
    let exceptions = load_exceptions(args.measure.parity_exceptions.as_deref(), &map)?;
    let corpus: Vec<CorpusRow> = read_jsonl(&args.corpus)?;
    let baseline: Vec<BaselineRow> = read_jsonl(&args.baseline)?;
    let known_path = match &args.known {
        Some(p) => p.clone(),
        None => args
            .corpus
            .parent()
            .unwrap_or(Path::new(""))
            .join(KNOWN_NAME),
    };
    let known: Vec<KnownRow> = read_jsonl(&known_path)?;
    let real = match &args.real_parse {
        Some(p) => Some(read_real_parse(p)?),
        None => None,
    };
    let mut fails = Vec::new();

    let mut rows: Vec<(&CorpusRow, Tool)> = Vec::new();
    let mut other_tool = 0u64;
    for row in &corpus {
        match Tool::from_name(&row.tool) {
            Some(tool) => rows.push((row, tool)),
            None => other_tool += 1,
        }
    }
    if rows.is_empty() {
        return Err(format!("0 rows read from {}", args.corpus.display()));
    }
    for tool in Tool::ALL {
        if !rows.iter().any(|(_, t)| *t == tool) {
            return Err(format!(
                "0 {} rows read from {}",
                tool.name(),
                args.corpus.display()
            ));
        }
    }

    let installed: HashMap<&str, &Vec<String>> = baseline
        .iter()
        .map(|b| (b.id.as_str(), &b.installed))
        .collect();
    let mut unmapped: BTreeSet<&str> = BTreeSet::new();
    for b in &baseline {
        for r in b.installed.iter().chain(&b.full) {
            if !map.map.contains_key(r) {
                unmapped.insert(r);
            }
        }
    }
    for k in &known {
        for r in &k.expected_rules {
            if !map.map.contains_key(r) {
                unmapped.insert(r);
            }
        }
    }
    if !unmapped.is_empty() {
        return Err(format!(
            "the rule map names no shellwise id for these baseline-guard ids: {}",
            unmapped.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }

    if let (Some(answers), Some(path)) = (&real, &args.real_parse)
        && !rows.iter().any(|(r, _)| answers.contains_key(&r.id))
    {
        return Err(format!("0 rows of {} joined to the corpus", path.display()));
    }

    let head = replay(&rows, 1, &cfg)?;
    let mut timing = vec![head.timing(&rows)];
    for k in 1..args.measure.passes {
        timing.push(replay(&rows, TIMING_PASS + k, &cfg)?.timing(&rows));
    }
    let head_rows = &head.rows;
    let joined = rows
        .iter()
        .filter(|(r, _)| installed.contains_key(r.id.as_str()))
        .count();
    if joined == 0 {
        return Err(format!(
            "0 corpus rows joined to the baseline {}",
            args.baseline.display()
        ));
    }

    if let Some(path) = &args.dump {
        write_dump(path, &rows, head_rows)?;
    }
    let moves = match &args.diff {
        Some(old) => {
            let control = replay(&rows, 2, &cfg)?;
            let control_moves = compare_passes(&rows, head_rows, &control.rows);
            if !control_moves.is_empty() {
                for m in &control_moves {
                    println!("control moved {m}");
                }
                fails.push(format!(
                    "the head-vs-head control moved {} rows: the replay is not repeatable",
                    control_moves.len()
                ));
            }
            Some(diff(old, &rows, head_rows, control_moves.len())?)
        }
        None => None,
    };

    let full: HashMap<&str, BTreeSet<&str>> = baseline
        .iter()
        .map(|b| {
            let ids = b.installed.iter().chain(&b.full).map(String::as_str);
            (b.id.as_str(), ids.collect())
        })
        .collect();
    fails.extend(check_runs_on(&rows, head_rows, &full, &map));

    let cwd_missing = cwd_missing(&rows);
    let report = Report::build(
        &rows,
        &head,
        &timing,
        &installed,
        &map,
        real.as_ref(),
        &cwd_missing,
    );
    let known_result = check_known(&known, &rows, head_rows, &map);
    fails.extend(known_result.fails.iter().cloned());

    let baseline_missing = rows.len() - joined;
    let mut json = report.json(&map, &exceptions, other_tool, baseline_missing);
    json["config"] = json!(
        args.measure
            .config
            .as_ref()
            .map(|p| p.display().to_string())
    );
    json["passes"] = json!(args.measure.passes);
    json["known"] = known_result.json();
    if let Some(m) = &moves {
        json["moves"] = m.clone();
    }
    json["fails"] = json!(fails);
    let text = serde_json::to_string_pretty(&json).map_err(|e| e.to_string())?;
    fs::write(&args.out, text + "\n")
        .map_err(|e| format!("cannot write {}: {e}", args.out.display()))?;
    match &args.measure.config {
        Some(p) => println!("config: {}", p.display()),
        None => println!("config: default"),
    }
    println!("baseline missing: {baseline_missing} rows");
    report.print(&exceptions);
    known_result.print();
    if let Some(m) = &moves {
        println!(
            "moves: up {}, down {}, changed {}, unchanged {}, control {}, missing in old {}, missing in new {}",
            m["up"],
            m["down"],
            m["changed"],
            m["unchanged"],
            m["control_moves"],
            m["missing_in_old"],
            m["missing_in_new"]
        );
        println!(
            "moves by OS: Windows {}, Linux {}",
            m["moved_by_os"]["Windows"], m["moved_by_os"]["Linux"]
        );
    }
    Ok(fails)
}

fn load_rule_map(path: Option<&Path>) -> Result<RuleMap, String> {
    let (text, name) = match path {
        Some(p) => (
            fs::read_to_string(p).map_err(|e| format!("cannot read {}: {e}", p.display()))?,
            p.display().to_string(),
        ),
        None => (RULE_MAP.to_string(), "the compiled-in rule map".to_string()),
    };
    let map: RuleMap = toml::from_str(&text).map_err(|e| format!("{name}: {e}"))?;
    if map.map.is_empty() {
        return Err(format!("{name}: the map is empty"));
    }
    for (k, v) in &map.map {
        if v.is_empty() {
            return Err(format!("{name}: {k} maps to an empty id"));
        }
        if !map.runs_on.contains_key(k) {
            return Err(format!("{name}: no runs_on entry for {k}"));
        }
    }
    let oses = [Os::Windows, Os::Posix].map(os_name);
    for (k, r) in &map.runs_on {
        if !map.map.contains_key(k) {
            return Err(format!("{name}: runs_on names {k}, which the map does not"));
        }
        let tools_ok = r.tools.iter().all(|t| Tool::from_name(t).is_some());
        let os_ok = r.os.iter().all(|o| oses.contains(&o.as_str()));
        if r.tools.is_empty() || r.os.is_empty() || !tools_ok || !os_ok || r.why.is_empty() {
            return Err(format!(
                "{name}: runs_on {k} needs tools from {}, OSes from {} and a why",
                Tool::ALL.map(Tool::name).join(", "),
                oses.join(", ")
            ));
        }
    }
    Ok(map)
}

/// The rows where a mapped rule fires on a tool or OS its `runs_on` entry leaves out, among the
/// rows baseline-guard denies with that id (elsewhere the mapped rule may fire for its own reasons).
fn check_runs_on(
    rows: &[(&CorpusRow, Tool)],
    head: &[Replayed],
    denies: &HashMap<&str, BTreeSet<&str>>,
    map: &RuleMap,
) -> Vec<String> {
    let mut outside: BTreeMap<(&str, &'static str, &'static str), u64> = BTreeMap::new();
    for ((row, tool), r) in rows.iter().zip(head) {
        let os = os_name(CwdShape::of(row.cwd.as_deref()).os());
        for sg in denies.get(row.id.as_str()).into_iter().flatten() {
            let (Some(id), Some(on)) = (map.map.get(*sg), map.runs_on.get(*sg)) else {
                continue;
            };
            let listed = on.tools.iter().any(|t| t == tool.name()) && on.os.iter().any(|o| o == os);
            if r.names(id) && !listed {
                *outside.entry((sg, tool.name(), os)).or_default() += 1;
            }
        }
    }
    outside
        .into_iter()
        .map(|((sg, tool, os), n)| {
            format!(
                "{sg} ({}) fires on {n} {tool} rows on {os} outside its runs_on entry",
                map.map[sg]
            )
        })
        .collect()
}

/// How long one cwd read may take: a share no host answers makes `is_dir` wait for the network.
const CWD_READ_MS: u64 = 500;

/// Rows whose recorded cwd is not a folder on this machine, per OS: a rule that reads the disk
/// cannot fire on them. Each distinct cwd is read once, under `CWD_READ_MS`; one that does not
/// answer in time counts as gone.
fn cwd_missing(rows: &[(&CorpusRow, Tool)]) -> BTreeMap<&'static str, PerTool> {
    let mut gone: HashMap<&str, bool> = HashMap::new();
    let mut out: BTreeMap<&'static str, PerTool> = [Os::Windows, Os::Posix]
        .map(|os| (os_name(os), PerTool::default()))
        .into();
    for (row, tool) in rows {
        let Some(cwd) = row.cwd.as_deref().filter(|c| !c.is_empty()) else {
            continue;
        };
        let is_gone = *gone.entry(cwd).or_insert_with(|| {
            let path = PathBuf::from(cwd);
            let bound = Deadline::new(Instant::now(), CWD_READ_MS);
            !shellwise::fs::bounded(&bound, move || path.is_dir()).unwrap_or(false)
        });
        if is_gone {
            let os = os_name(CwdShape::of(Some(cwd)).os());
            out.entry(os).or_default().add(*tool);
        }
    }
    out
}

/// Every non-empty line of a JSON Lines file. A line that does not parse stops the run.
fn read_jsonl<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Vec<T>, String> {
    let file = fs::File::open(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let mut out = Vec::new();
    for (n, line) in BufReader::new(file).lines().enumerate() {
        let line = line.map_err(|e| format!("{}: line {}: {e}", path.display(), n + 1))?;
        if line.trim().is_empty() {
            continue;
        }
        let row = serde_json::from_str(&line)
            .map_err(|e| format!("{}: line {}: {e}", path.display(), n + 1))?;
        out.push(row);
    }
    Ok(out)
}

/// `real_parse.ps1` output: `id`, `refused` (`yes`/`no`), the first error id. `true` = refused.
fn read_real_parse(path: &Path) -> Result<HashMap<String, bool>, String> {
    let text =
        fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let mut out = HashMap::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() || (n == 0 && line.starts_with("id\t")) {
            continue;
        }
        let mut cols = line.split('\t');
        let (Some(id), Some(refused)) = (cols.next(), cols.next()) else {
            return Err(format!(
                "{}: line {}: fewer than 2 columns",
                path.display(),
                n + 1
            ));
        };
        let refused = match refused {
            "yes" => true,
            "no" => false,
            other => {
                return Err(format!(
                    "{}: line {}: refused is {other:?}, not yes or no",
                    path.display(),
                    n + 1
                ));
            }
        };
        out.insert(id.to_string(), refused);
    }
    if out.is_empty() {
        return Err(format!("0 rows read from {}", path.display()));
    }
    Ok(out)
}

/// The first timing pass after the verdict pass; pass 2 stays the `--diff` control.
const TIMING_PASS: u32 = 100;

/// A rule that read the disk on at least one row.
#[derive(Default, Clone)]
struct DiskRule {
    rows: u64,
}

/// One pass over the corpus.
struct Pass {
    rows: Vec<Replayed>,
    /// Each rule's own check, in nanoseconds, per rule (`Rule::id`) and shell.
    rule_nanos: BTreeMap<(&'static str, Tool), Vec<u64>>,
    disk: BTreeMap<&'static str, DiskRule>,
    /// The finding ids each rule (`Rule::id`) gave in this pass.
    emitted: BTreeMap<&'static str, BTreeSet<&'static str>>,
}

/// What one pass's timing gives: the latency per shell and each rule's cost, both as (p50, p99)
/// in milliseconds.
struct Timing {
    latency: BTreeMap<Tool, (f64, f64)>,
    rules: BTreeMap<(&'static str, Tool), (u64, f64, f64)>,
}

impl Pass {
    fn timing(&self, rows: &[(&CorpusRow, Tool)]) -> Timing {
        let mut by_tool: BTreeMap<Tool, Vec<u64>> = BTreeMap::new();
        for ((_, tool), r) in rows.iter().zip(&self.rows) {
            by_tool.entry(*tool).or_default().push(r.nanos);
        }
        let latency = by_tool
            .into_iter()
            .map(|(tool, mut ns)| {
                ns.sort_unstable();
                (tool, (percentile(&ns, 0.50), percentile(&ns, 0.99)))
            })
            .collect();
        let rules = self
            .rule_nanos
            .iter()
            .map(|(k, ns)| {
                let mut ns = ns.clone();
                ns.sort_unstable();
                let n = ns.len() as u64;
                (*k, (n, percentile(&ns, 0.50), percentile(&ns, 0.99)))
            })
            .collect();
        Timing { latency, rules }
    }
}
/// One pass over the corpus, each row through `analyse`, then each rule's own check timed on the
/// rows `analyse` finished. The pass runs on one big-stack thread, as `analyse` runs its own scan,
/// so a deeply nested row cannot end the run without a report; a panic in the raw scan makes that
/// row's `raw_hit` an error.
fn replay(rows: &[(&CorpusRow, Tool)], pass: u32, cfg: &Config) -> Result<Pass, String> {
    std::thread::scope(|s| {
        std::thread::Builder::new()
            .name(format!("replay-{pass}"))
            .stack_size(REPLAY_STACK)
            .spawn_scoped(s, || replay_rows(rows, pass, cfg))
            .map_err(|e| format!("the replay thread did not start: {e}"))?
            .join()
            .map_err(|_| format!("the replay pass {pass} panicked"))
    })
}

fn replay_rows(rows: &[(&CorpusRow, Tool)], pass: u32, cfg: &Config) -> Pass {
    let timed = TimedRules::new();
    let mut out = Pass {
        rows: Vec::with_capacity(rows.len()),
        rule_nanos: BTreeMap::new(),
        disk: BTreeMap::new(),
        emitted: BTreeMap::new(),
    };
    for (i, (row, tool)) in rows.iter().enumerate() {
        let (shell, os, cwd, env) = replay_input(row, *tool);
        let input = AnalyseInput {
            bytes: row.command.as_bytes(),
            shell,
            os,
            cwd: cwd.clone(),
            env: env.clone(),
            origin: Origin::CommandLine,
            problem: None,
        };
        let start = Instant::now();
        let verdict = analyse(&input, cfg, &Deadline::for_config(start, cfg));
        let nanos = start.elapsed().as_nanos() as u64;
        let raw_hit =
            std::panic::catch_unwind(|| scan::destructive_row(&row.command).is_some()).ok();
        let mut r = Replayed::from_verdict(&verdict, raw_hit, nanos);
        if !r.names(ANALYSIS_INCOMPLETE) {
            let check = CheckInput {
                shell,
                os,
                command: &row.command,
                cwd,
                env,
                origin: Origin::CommandLine,
            };
            r.delete_git =
                panic::catch_unwind(AssertUnwindSafe(|| timed.run(&check, *tool, cfg, &mut out)))
                    .unwrap_or_default();
        }
        perturb(pass, i, &mut r);
        out.rows.push(r);
    }
    out
}

/// `RealFs` that counts its calls, so the timed run sees which rule read the disk. The counter is
/// shared: `bounded` hands the file system to a worker thread.
struct CountingFs {
    calls: Arc<AtomicU64>,
}

impl CountingFs {
    fn count(&self) {
        self.calls.fetch_add(1, Ordering::Relaxed);
    }
}

impl Fs for CountingFs {
    fn lstat(&self, p: &Path) -> io::Result<Meta> {
        self.count();
        RealFs.lstat(p)
    }
    fn read_dir(&self, p: &Path) -> io::Result<Vec<PathBuf>> {
        self.count();
        RealFs.read_dir(p)
    }
    fn link_target(&self, p: &Path) -> io::Result<Option<PathBuf>> {
        self.count();
        RealFs.link_target(p)
    }
    fn long_path(&self, p: &Path) -> io::Result<PathBuf> {
        self.count();
        RealFs.long_path(p)
    }
    fn link_kind(&self, p: &Path) -> io::Result<LinkKind> {
        self.count();
        RealFs.link_kind(p)
    }
    fn file_id(&self, p: &Path) -> io::Result<Option<FileId>> {
        self.count();
        RealFs.file_id(p)
    }
    fn device(&self, p: &Path) -> io::Result<Option<u64>> {
        self.count();
        RealFs.device(p)
    }
    fn mount_points(&self) -> io::Result<Option<Vec<PathBuf>>> {
        self.count();
        RealFs.mount_points()
    }
    fn drive_exists(&self, letter: char) -> io::Result<bool> {
        self.count();
        RealFs.drive_exists(letter)
    }
    fn is_hidden(&self, p: &Path) -> io::Result<bool> {
        self.count();
        RealFs.is_hidden(p)
    }
}

/// One rule with its own counting file system.
struct TimedRule {
    rule: Box<dyn Rule>,
    fs: SharedFs,
    calls: Arc<AtomicU64>,
}

impl TimedRule {
    fn new(rule: Box<dyn Rule>) -> TimedRule {
        let calls = Arc::new(AtomicU64::new(0));
        let fs: SharedFs = Arc::new(CountingFs {
            calls: Arc::clone(&calls),
        });
        TimedRule { rule, fs, calls }
    }

    /// Run the check timed; the ids of its findings.
    fn time(&self, ctx: &Ctx, tool: Tool, pass: &mut Pass) -> Vec<&'static str> {
        if !self.rule.scope().covers(ctx.input.origin) {
            return Vec::new();
        }
        let id = self.rule.id();
        let before = self.calls.load(Ordering::Relaxed);
        let mut found: Vec<Finding> = Vec::new();
        let start = Instant::now();
        self.rule.check(ctx, &mut found);
        let nanos = start.elapsed().as_nanos() as u64;
        pass.rule_nanos.entry((id, tool)).or_default().push(nanos);
        if self.calls.load(Ordering::Relaxed) > before {
            pass.disk.entry(id).or_default().rows += 1;
        }
        let ids: Vec<&'static str> = found.iter().map(|f| f.rule).collect();
        pass.emitted
            .entry(id)
            .or_default()
            .extend(ids.iter().copied());
        ids
    }
}

/// The rules as `analyse` runs them (the length rules on the raw text, then the parse and every
/// rule), each timed alone. Timing and attribution only: the verdicts come from `analyse`.
struct TimedRules {
    length: Vec<TimedRule>,
    all: Vec<TimedRule>,
}

impl TimedRules {
    fn new() -> TimedRules {
        TimedRules {
            length: rules::length_rules()
                .into_iter()
                .map(TimedRule::new)
                .collect(),
            all: rules::all().into_iter().map(TimedRule::new).collect(),
        }
    }

    /// Time every rule on `input`; the finding ids the delete and git rules gave.
    fn run(
        &self,
        input: &CheckInput,
        tool: Tool,
        cfg: &Config,
        pass: &mut Pass,
    ) -> Vec<&'static str> {
        let deadline = Deadline::for_config(Instant::now(), cfg);
        let empty = Script::default();
        for t in &self.length {
            let ctx = Ctx {
                input,
                script: &empty,
                parse_error: None,
                cfg,
                fs: &t.fs,
                deadline: &deadline,
            };
            t.time(&ctx, tool, pass);
        }
        if input.command.len() > MAX_INPUT_BYTES {
            return Vec::new();
        }
        let parsed = match input.shell {
            Shell::Pwsh | Shell::Powershell5 => {
                parse::pwsh::parse(input.command, input.shell, input.os)
            }
            Shell::Bash(profile) => parse::bash::parse(input.command, profile),
        };
        let (script, parse_error) = match parsed {
            Ok(script) => (script, None),
            Err(e) if matches!(e.kind, ParseKind::Internal(_)) => return Vec::new(),
            Err(e) => (Script::default(), Some(e)),
        };
        let mut delete_git = Vec::new();
        for t in &self.all {
            let ctx = Ctx {
                input,
                script: &script,
                parse_error: parse_error.as_ref(),
                cfg,
                fs: &t.fs,
                deadline: &deadline,
            };
            let ids = t.time(&ctx, tool, pass);
            let id = t.rule.id();
            if id == rules::delete::DELETE_CRITICAL || id == rules::git::GIT_RESTORE_DISCARDS {
                delete_git.extend(ids);
            }
        }
        delete_git
    }
}

/// With the `testhooks` feature, `SHELLWISE_TESTHOOK=bench-control-move` changes the first row of
/// the second pass, so the head-vs-head control has a known answer.
#[cfg(feature = "testhooks")]
fn perturb(pass: u32, index: usize, r: &mut Replayed) {
    if pass == 2 && index == 0 && rules::testhooks::active("bench-control-move") {
        r.level = if r.level == Level::Ok {
            Level::Break
        } else {
            Level::Ok
        };
    }
}

#[cfg(not(feature = "testhooks"))]
fn perturb(_pass: u32, _index: usize, _r: &mut Replayed) {}

fn write_dump(path: &Path, rows: &[(&CorpusRow, Tool)], head: &[Replayed]) -> Result<(), String> {
    let mut text = String::from(DUMP_HEADER);
    text.push('\n');
    for ((row, _), r) in rows.iter().zip(head) {
        text.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\n",
            row.id,
            r.level.as_str(),
            r.rule_list(),
            match r.raw_hit {
                Some(true) => "yes",
                Some(false) => "no",
                None => "error",
            },
            r.rule_levels()
        ));
    }
    fs::write(path, text).map_err(|e| format!("cannot write {}: {e}", path.display()))
}

/// The rows whose level or rules (with their levels) differ between two passes of this build.
fn compare_passes(rows: &[(&CorpusRow, Tool)], a: &[Replayed], b: &[Replayed]) -> Vec<String> {
    rows.iter()
        .zip(a.iter().zip(b))
        .filter(|(_, (x, y))| x.level != y.level || x.rule_levels() != y.rule_levels())
        .map(|((row, _), (x, y))| {
            format!(
                "{} {}[{}] -> {}[{}]",
                row.id,
                x.level.as_str(),
                x.rule_levels(),
                y.level.as_str(),
                y.rule_levels()
            )
        })
        .collect()
}

fn parse_level(s: &str) -> Option<Level> {
    match s {
        "ok" => Some(Level::Ok),
        "warn" => Some(Level::Warn),
        "break" => Some(Level::Break),
        "danger" => Some(Level::Danger),
        "critical" => Some(Level::Critical),
        _ => None,
    }
}

/// One row of an old dump: its level, rule ids and, from a dump with that column, `rule:level`.
struct OldRow<'a> {
    level: Level,
    rules: &'a str,
    rule_levels: Option<&'a str>,
}

/// Every row whose level or rules moved since the dump at `old`, by its old→new pair. A dump
/// without `rule_levels` (an older build) compares rules by name only.
fn diff(
    old: &Path,
    rows: &[(&CorpusRow, Tool)],
    head: &[Replayed],
    control_moves: usize,
) -> Result<Value, String> {
    let text =
        fs::read_to_string(old).map_err(|e| format!("cannot read {}: {e}", old.display()))?;
    let mut before: HashMap<&str, OldRow> = HashMap::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() || (n == 0 && (line == DUMP_HEADER || line == OLD_DUMP_HEADER)) {
            continue;
        }
        let cols: Vec<&str> = line.split('\t').collect();
        let level = cols.get(1).and_then(|l| parse_level(l));
        match (cols.len(), level) {
            (4 | 5, Some(level)) => {
                before.insert(
                    cols[0],
                    OldRow {
                        level,
                        rules: cols[2],
                        rule_levels: cols.get(4).copied(),
                    },
                );
            }
            _ => {
                return Err(format!(
                    "{}: line {}: not a dump line (id, level, rules, raw_hit[, rule_levels])",
                    old.display(),
                    n + 1
                ));
            }
        }
    }
    if before.is_empty() {
        return Err(format!("0 rows read from {}", old.display()));
    }
    let (mut up, mut down, mut changed, mut unchanged, mut missing_in_old) = (0, 0, 0, 0, 0);
    let mut moved = Vec::new();
    let mut moved_by_os: BTreeMap<&str, u64> =
        [Os::Windows, Os::Posix].map(|os| (os_name(os), 0)).into();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for ((row, _), r) in rows.iter().zip(head) {
        seen.insert(row.id.as_str());
        let Some(old_row) = before.get(row.id.as_str()) else {
            missing_in_old += 1;
            continue;
        };
        let (old_level, old_rules) = (old_row.level, old_row.rules);
        let new_rules = r.rule_list();
        let same_rules = match old_row.rule_levels {
            Some(old_levels) => old_levels == r.rule_levels(),
            None => old_rules == new_rules,
        };
        if old_level == r.level && same_rules {
            unchanged += 1;
            continue;
        }
        let way = if r.level > old_level {
            up += 1;
            "up"
        } else if r.level < old_level {
            down += 1;
            "down"
        } else {
            changed += 1;
            "changed"
        };
        println!(
            "moved {way} {} {}[{old_rules}] -> {}[{new_rules}]",
            row.id,
            old_level.as_str(),
            r.level.as_str()
        );
        let os = os_name(CwdShape::of(row.cwd.as_deref()).os());
        *moved_by_os.entry(os).or_default() += 1;
        moved.push(json!({
            "id": row.id,
            "os": os,
            "way": way,
            "old_level": old_level.as_str(),
            "old_rules": old_rules,
            "old_rule_levels": old_row.rule_levels,
            "new_level": r.level.as_str(),
            "new_rules": new_rules,
            "new_rule_levels": r.rule_levels(),
        }));
    }
    if up + down + changed + unchanged == 0 {
        return Err(format!("0 rows of {} joined to the corpus", old.display()));
    }
    let missing_in_new = before.keys().filter(|id| !seen.contains(*id)).count();
    Ok(json!({
        "up": up,
        "down": down,
        "changed": changed,
        "unchanged": unchanged,
        "missing_in_old": missing_in_old,
        "missing_in_new": missing_in_new,
        "control_moves": control_moves,
        "moved_by_os": moved_by_os,
        "moved": moved,
    }))
}

/// The line a denied, non-destructive `ok` row counts on. Exactly one, in this order: the real
/// parser refuses the text; every deny rule is a port of a baseline-guard rule that denies this row
/// too; every deny rule is a parity or own-line rule (at least one own-line); otherwise meter 1.
/// Meter 2's rows are split by the same lines.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Line {
    Refused,
    Parity,
    Own,
    Meter1,
}

impl Line {
    const ALL: [Line; 4] = [Line::Refused, Line::Parity, Line::Own, Line::Meter1];

    fn key(self) -> &'static str {
        match self {
            Line::Refused => "refused",
            Line::Parity => "parity",
            Line::Own => "own_line",
            Line::Meter1 => "meter_1",
        }
    }

    fn name(self) -> &'static str {
        match self {
            Line::Refused => "refused",
            Line::Parity => "parity",
            Line::Own => "own line",
            Line::Meter1 => "meter 1",
        }
    }
}

fn line_of(
    deny: &BTreeSet<&'static str>,
    parity: &BTreeSet<&str>,
    own: &BTreeSet<&str>,
    refused: Option<bool>,
) -> Line {
    if refused == Some(true) {
        Line::Refused
    } else if deny.is_empty() {
        // A denied row names no deny rule only when a finding's level is wrong: count it.
        Line::Meter1
    } else if deny.iter().all(|r| parity.contains(r)) {
        Line::Parity
    } else if deny.iter().all(|r| parity.contains(r) || own.contains(r)) {
        Line::Own
    } else {
        Line::Meter1
    }
}

/// A count in total and per shell.
#[derive(Default, Clone, Copy)]
struct PerTool {
    bash: u64,
    pwsh: u64,
}

impl PerTool {
    fn add(&mut self, tool: Tool) {
        match tool {
            Tool::Bash => self.bash += 1,
            Tool::Pwsh => self.pwsh += 1,
        }
    }

    fn total(self) -> u64 {
        self.bash + self.pwsh
    }

    fn json(self) -> Value {
        json!({ "rows": self.total(), "Bash": self.bash, "PowerShell": self.pwsh })
    }
}

#[derive(Default)]
struct RuleLabel {
    deny: u64,
    warn: u64,
}

#[derive(Default)]
struct ParityRule {
    baseline_guard_denies: u64,
    shellwise_allows: u64,
    /// Allowed rows per (shape, label).
    keys: BTreeMap<(&'static str, String), u64>,
}

/// The median of `v` (the mean of the two middle values for an even count).
fn median(mut v: Vec<f64>) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    v.sort_by(f64::total_cmp);
    let n = v.len();
    (v[(n - 1) / 2] + v[n / 2]) / 2.0
}

/// (p50, p99) as the median over the passes, then each pass's (p50, p99).
type PassLatency = ((f64, f64), Vec<(f64, f64)>);

struct Report {
    rows: PerTool,
    /// Rows replayed per OS (both keys always present, so 0 Linux rows shows).
    rows_per_os: BTreeMap<&'static str, PerTool>,
    /// Rows per OS whose recorded cwd is not a folder on this machine.
    rows_cwd_missing: BTreeMap<&'static str, PerTool>,
    cwd_shapes: BTreeMap<CwdShape, u64>,
    days: u64,
    ok: PerTool,
    ok_non_destructive: PerTool,
    meter_1: PerTool,
    refused: PerTool,
    parity: PerTool,
    own_line: PerTool,
    meter_2: PerTool,
    meter_2_by_line: BTreeMap<Line, PerTool>,
    /// Meter 2 rows a delete or git rule denies, and the rest.
    meter_2_delete_git: PerTool,
    meter_2_other: PerTool,
    /// Whether `--real-parse` was given: without it the refused line is not measured and meter 1
    /// holds its rows, so it is an upper bound.
    real_measured: bool,
    /// Denied non-destructive `ok` rows with no `--real-parse` answer (counted on another line).
    real_parse_missing: u64,
    /// `None` without `--real-parse`.
    parse_kind_false_deny: Option<u64>,
    parse_kind_unmeasured: u64,
    per_rule: BTreeMap<&'static str, BTreeMap<String, RuleLabel>>,
    parity_per_rule: BTreeMap<String, ParityRule>,
    /// Per shell: (p50, p99) as the median over the passes, then each pass's (p50, p99).
    latency: BTreeMap<Tool, PassLatency>,
    /// Per rule and shell: rows, then p50 and p99 as the median over the passes.
    rule_cost: BTreeMap<&'static str, BTreeMap<Tool, (u64, f64, f64)>>,
    /// The rules that read the disk, with the rows they read it on and the finding ids they gave.
    disk: BTreeMap<&'static str, (u64, BTreeSet<&'static str>)>,
}

impl Report {
    fn build(
        rows: &[(&CorpusRow, Tool)],
        head: &Pass,
        timing: &[Timing],
        installed: &HashMap<&str, &Vec<String>>,
        map: &RuleMap,
        real: Option<&HashMap<String, bool>>,
        cwd_missing: &BTreeMap<&'static str, PerTool>,
    ) -> Report {
        let own: BTreeSet<&str> = map.own_line_rules.iter().map(String::as_str).collect();
        let mut r = Report {
            rows: PerTool::default(),
            rows_per_os: [Os::Windows, Os::Posix]
                .map(|os| (os_name(os), PerTool::default()))
                .into(),
            rows_cwd_missing: cwd_missing.clone(),
            cwd_shapes: CwdShape::ALL.map(|s| (s, 0)).into(),
            days: 0,
            ok: PerTool::default(),
            ok_non_destructive: PerTool::default(),
            meter_1: PerTool::default(),
            refused: PerTool::default(),
            parity: PerTool::default(),
            own_line: PerTool::default(),
            meter_2: PerTool::default(),
            meter_2_by_line: Line::ALL.map(|l| (l, PerTool::default())).into(),
            meter_2_delete_git: PerTool::default(),
            meter_2_other: PerTool::default(),
            real_measured: real.is_some(),
            real_parse_missing: 0,
            parse_kind_false_deny: real.map(|_| 0),
            parse_kind_unmeasured: 0,
            per_rule: BTreeMap::new(),
            parity_per_rule: BTreeMap::new(),
            latency: BTreeMap::new(),
            rule_cost: BTreeMap::new(),
            disk: BTreeMap::new(),
        };
        let mut days: BTreeSet<&str> = BTreeSet::new();
        for ((row, tool), v) in rows.iter().zip(&head.rows) {
            let tool = *tool;
            r.rows.add(tool);
            let shape = CwdShape::of(row.cwd.as_deref());
            *r.cwd_shapes.entry(shape).or_default() += 1;
            r.rows_per_os
                .entry(os_name(shape.os()))
                .or_default()
                .add(tool);
            days.insert(row.ts.get(..10).unwrap_or(&row.ts));
            for (rule, level) in &v.rules {
                let cell = r
                    .per_rule
                    .entry(*rule)
                    .or_default()
                    .entry(row.label.clone())
                    .or_default();
                if *level >= Level::Break {
                    cell.deny += 1;
                } else if *level == Level::Warn {
                    cell.warn += 1;
                }
            }
            let sg = installed.get(row.id.as_str()).copied();
            for sg_rule in sg.into_iter().flatten() {
                let p = r.parity_per_rule.entry(sg_rule.clone()).or_default();
                p.baseline_guard_denies += 1;
                if !v.denied() {
                    p.shellwise_allows += 1;
                    let mapped = map.map.get(sg_rule).is_some_and(|id| v.names(id));
                    let shape = if mapped {
                        SHAPE_MAPPED_WARN
                    } else {
                        SHAPE_MAPPED_SILENT
                    };
                    *p.keys.entry((shape, row.label.clone())).or_default() += 1;
                }
            }
            let refused = real.and_then(|m| m.get(&row.id).copied());
            if v.deny_kind() {
                match (r.parse_kind_false_deny.as_mut(), refused) {
                    (Some(n), Some(false)) => *n += 1,
                    (_, None) => r.parse_kind_unmeasured += 1,
                    _ => {}
                }
            }
            if row.label != "ok" {
                continue;
            }
            r.ok.add(tool);
            if !row.destructive {
                r.ok_non_destructive.add(tool);
            }
            if !v.denied() {
                continue;
            }
            let parity: BTreeSet<&str> = sg
                .into_iter()
                .flatten()
                .filter_map(|s| map.map.get(s).map(String::as_str))
                .collect();
            let deny = v.deny_rules();
            let line = line_of(&deny, &parity, &own, refused);
            if row.destructive {
                r.meter_2.add(tool);
                r.meter_2_by_line.entry(line).or_default().add(tool);
                if deny.iter().any(|d| v.delete_git.contains(d)) {
                    r.meter_2_delete_git.add(tool);
                } else {
                    r.meter_2_other.add(tool);
                }
                continue;
            }
            if real.is_some() && refused.is_none() {
                r.real_parse_missing += 1;
            }
            let line = match line {
                Line::Refused => &mut r.refused,
                Line::Parity => &mut r.parity,
                Line::Own => &mut r.own_line,
                Line::Meter1 => &mut r.meter_1,
            };
            line.add(tool);
        }
        r.days = days.len() as u64;
        for tool in Tool::ALL {
            let per: Vec<(f64, f64)> = timing
                .iter()
                .filter_map(|t| t.latency.get(&tool).copied())
                .collect();
            if per.is_empty() {
                continue;
            }
            let p50 = median(per.iter().map(|p| p.0).collect());
            let p99 = median(per.iter().map(|p| p.1).collect());
            r.latency.insert(tool, ((p50, p99), per));
        }
        let mut keys: BTreeSet<(&'static str, Tool)> = BTreeSet::new();
        for t in timing {
            keys.extend(t.rules.keys().copied());
        }
        for (rule, tool) in keys {
            let per: Vec<(u64, f64, f64)> = timing
                .iter()
                .filter_map(|t| t.rules.get(&(rule, tool)).copied())
                .collect();
            let rows_run = head
                .rule_nanos
                .get(&(rule, tool))
                .map_or(0, |v| v.len() as u64);
            let p50 = median(per.iter().map(|p| p.1).collect());
            let p99 = median(per.iter().map(|p| p.2).collect());
            r.rule_cost
                .entry(rule)
                .or_default()
                .insert(tool, (rows_run, p50, p99));
        }
        for (rule, d) in &head.disk {
            let ids = head.emitted.get(rule).cloned().unwrap_or_default();
            r.disk.insert(rule, (d.rows, ids));
        }
        r
    }

    /// Each key of one baseline-guard rule: the allowed rows the bench counted and the exceptions'
    /// expected counts, as (shape, label, allows, expected, why).
    fn parity_keys<'a>(
        p: Option<&'a ParityRule>,
        exceptions: &'a [&'a ParityException],
    ) -> Vec<(&'a str, &'a str, u64, u64, Option<&'a str>)> {
        let mut keys: BTreeMap<(&str, &str), (u64, u64, Option<&str>)> = BTreeMap::new();
        if let Some(p) = p {
            for ((shape, label), n) in &p.keys {
                keys.entry((shape, label.as_str())).or_default().0 += n;
            }
        }
        for e in exceptions {
            let k = keys
                .entry((e.shape.as_str(), e.label.as_str()))
                .or_default();
            k.1 += e.expected;
            k.2 = Some(&e.why);
        }
        keys.into_iter()
            .map(|((shape, label), (allows, expected, why))| (shape, label, allows, expected, why))
            .collect()
    }

    fn json(
        &self,
        map: &RuleMap,
        exceptions: &[ParityException],
        other_tool: u64,
        baseline_missing: usize,
    ) -> Value {
        let meter_1_budget = self.ok_non_destructive.total() as f64 * METER_1_SHARE;
        let meter_2_per_day = if self.days == 0 {
            0.0
        } else {
            self.meter_2.total() as f64 / self.days as f64
        };
        let own_budget = |n: u64| n as f64 * OWN_LINE_SHARE;
        let per_rule: BTreeMap<&str, BTreeMap<&str, Value>> = self
            .per_rule
            .iter()
            .map(|(rule, labels)| {
                let cells = labels
                    .iter()
                    .map(|(label, c)| (label.as_str(), json!({ "deny": c.deny, "warn": c.warn })))
                    .collect();
                (*rule, cells)
            })
            .collect();
        let mut sgs: BTreeSet<&str> = self.parity_per_rule.keys().map(String::as_str).collect();
        sgs.extend(exceptions.iter().map(|e| e.baseline_guard.as_str()));
        let parity_per_rule: BTreeMap<&str, Value> = sgs
            .into_iter()
            .map(|sg| {
                let p = self.parity_per_rule.get(sg);
                let mine: Vec<&ParityException> =
                    exceptions.iter().filter(|e| e.baseline_guard == sg).collect();
                let keys = Report::parity_keys(p, &mine);
                let excepted: u64 = keys.iter().map(|k| k.3).sum();
                let unexplained: u64 = keys.iter().map(|k| k.2.saturating_sub(k.3)).sum();
                let over: u64 = keys.iter().map(|k| k.3.saturating_sub(k.2)).sum();
                let value = json!({
                    "shellwise_id": map.map.get(sg),
                    "baseline_guard_denies": p.map_or(0, |p| p.baseline_guard_denies),
                    "shellwise_allows": p.map_or(0, |p| p.shellwise_allows),
                    "excepted": excepted,
                    "unexplained": unexplained,
                    "excepted_over_allows": over,
                    "keys": keys
                        .iter()
                        .map(|(shape, label, allows, expected, why)| json!({
                            "shape": shape,
                            "label": label,
                            "allows": allows,
                            "expected": expected,
                            "unexplained": allows.saturating_sub(*expected),
                            "excepted_over_allows": expected.saturating_sub(*allows),
                            "why": why,
                        }))
                        .collect::<Vec<_>>(),
                });
                (sg, value)
            })
            .collect();
        let latency: BTreeMap<&str, Value> = self
            .latency
            .iter()
            .map(|(t, ((p50, p99), per))| {
                (
                    t.name(),
                    json!({
                        "p50": p50,
                        "p99": p99,
                        "p50_per_pass": per.iter().map(|p| p.0).collect::<Vec<_>>(),
                        "p99_per_pass": per.iter().map(|p| p.1).collect::<Vec<_>>(),
                    }),
                )
            })
            .collect();
        let rule_cost: BTreeMap<&str, BTreeMap<&str, Value>> = self
            .rule_cost
            .iter()
            .map(|(rule, tools)| {
                let cells = tools
                    .iter()
                    .map(|(t, (n, p50, p99))| {
                        (t.name(), json!({ "rows": n, "p50": p50, "p99": p99 }))
                    })
                    .collect();
                (*rule, cells)
            })
            .collect();
        let disk: BTreeMap<&str, Value> = self
            .disk
            .iter()
            .map(|(rule, (n, ids))| (*rule, json!({ "rows": n, "finding_ids": ids })))
            .collect();
        let per_os = |m: &BTreeMap<&'static str, PerTool>| -> BTreeMap<&str, Value> {
            m.iter().map(|(os, c)| (*os, c.json())).collect()
        };
        let cwd_shapes: BTreeMap<&str, u64> = self
            .cwd_shapes
            .iter()
            .map(|(s, n)| (s.name(), *n))
            .collect();
        let by_line: BTreeMap<&str, Value> = self
            .meter_2_by_line
            .iter()
            .map(|(l, c)| (l.key(), c.json()))
            .collect();
        json!({
            "rows": self.rows.json(),
            "rows_per_os": per_os(&self.rows_per_os),
            "rows_cwd_missing": per_os(&self.rows_cwd_missing),
            "cwd_shapes": cwd_shapes,
            "rows_of_other_tools": other_tool,
            "baseline_missing": baseline_missing,
            "days": self.days,
            "denominators": {
                "ok": self.ok.json(),
                "ok_non_destructive": self.ok_non_destructive.json(),
            },
            "meter_1": {
                "count": self.meter_1.json(),
                "budget": meter_1_budget,
                "within": self.meter_1.total() as f64 <= meter_1_budget,
                "upper_bound": !self.real_measured,
            },
            "refused_by_real_parser": if self.real_measured {
                self.refused.json()
            } else {
                Value::Null
            },
            "parity": self.parity.json(),
            "own_line": {
                "rules": map.own_line_rules,
                "count": self.own_line.json(),
                "budget": {
                    "Bash": own_budget(self.ok.bash),
                    "PowerShell": own_budget(self.ok.pwsh),
                },
                "within": self.own_line.bash as f64 <= own_budget(self.ok.bash)
                    && self.own_line.pwsh as f64 <= own_budget(self.ok.pwsh),
            },
            "meter_2": {
                "count": self.meter_2.json(),
                "per_day": meter_2_per_day,
                "budget_per_day": METER_2_PER_DAY,
                "within": meter_2_per_day <= METER_2_PER_DAY,
                "by_line": by_line,
                "by_family": {
                    "delete_git": self.meter_2_delete_git.json(),
                    "other": self.meter_2_other.json(),
                },
            },
            "real_parse_missing": self.real_parse_missing,
            "parse_kind_false_deny": self.parse_kind_false_deny,
            "parse_kind_unmeasured": self.parse_kind_unmeasured,
            "per_rule": per_rule,
            "parity_per_rule": parity_per_rule,
            "latency_ms": latency,
            "rule_cost_ms": rule_cost,
            "disk_reading_rules": disk,
        })
    }

    fn print(&self, exceptions: &[ParityException]) {
        let line = |name: &str, c: PerTool| {
            println!(
                "{name}: {} (Bash {}, PowerShell {})",
                c.total(),
                c.bash,
                c.pwsh
            );
        };
        line("rows", self.rows);
        for os in [Os::Windows, Os::Posix] {
            let name = os_name(os);
            line(
                &format!("replayed on {name}"),
                self.rows_per_os.get(name).copied().unwrap_or_default(),
            );
            line(
                &format!("cwd gone here, replayed on {name}"),
                self.rows_cwd_missing.get(name).copied().unwrap_or_default(),
            );
        }
        println!(
            "rules that read the disk (lower bounds where the cwd is gone): {}",
            if self.disk.is_empty() {
                "none on these rows".to_string()
            } else {
                self.disk
                    .iter()
                    .map(|(rule, (n, ids))| {
                        let ids: Vec<&str> = ids.iter().copied().collect();
                        format!("{rule} ({n} rows; gives {})", ids.join(", "))
                    })
                    .collect::<Vec<_>>()
                    .join("; ")
            }
        );
        println!(
            "cwd shapes: {}",
            self.cwd_shapes
                .iter()
                .map(|(s, n)| format!("{} {n}", s.name()))
                .collect::<Vec<_>>()
                .join(", ")
        );
        println!("days: {}", self.days);
        println!(
            "meter 1: {} of {} non-destructive ok rows (budget {:.1}){}",
            self.meter_1.total(),
            self.ok_non_destructive.total(),
            self.ok_non_destructive.total() as f64 * METER_1_SHARE,
            if self.real_measured {
                ""
            } else {
                ", an upper bound: the real-parser line is not measured"
            }
        );
        if self.real_measured {
            line("refused by the real parser", self.refused);
        } else {
            println!("refused by the real parser: not measured (pass the real_parse.ps1 output)");
        }
        line("parity", self.parity);
        line("own line", self.own_line);
        let (p, b) = (
            inline_length::threshold(Shell::Pwsh),
            inline_length::threshold(Shell::Bash(BashProfile::GitBash)),
        );
        println!(
            "inline-script-too-long thresholds: PowerShell over {} lines or {} characters, Bash over {} lines or {} characters",
            p.lines, p.chars, b.lines, b.chars
        );
        line("meter 2", self.meter_2);
        println!(
            "meter 2 by line: {}",
            self.meter_2_by_line
                .iter()
                .map(|(l, c)| format!("{} {}", l.name(), c.total()))
                .collect::<Vec<_>>()
                .join(", ")
        );
        println!(
            "meter 2 by family: delete/git {}, other {}",
            self.meter_2_delete_git.total(),
            self.meter_2_other.total()
        );
        match self.parse_kind_false_deny {
            Some(n) => println!(
                "parse_kind_false_deny: {n} ({} deny-kind rows without a real-parse answer)",
                self.parse_kind_unmeasured
            ),
            None => println!(
                "parse_kind_false_deny: not measured ({} deny-kind rows; pass the real_parse.ps1 output)",
                self.parse_kind_unmeasured
            ),
        }
        if self.real_parse_missing > 0 {
            println!(
                "real parse: {} denied non-destructive ok rows have no answer",
                self.real_parse_missing
            );
        }
        let mut sgs: BTreeSet<&str> = self.parity_per_rule.keys().map(String::as_str).collect();
        sgs.extend(exceptions.iter().map(|e| e.baseline_guard.as_str()));
        for sg in sgs {
            let p = self.parity_per_rule.get(sg);
            if let Some(p) = p.filter(|p| p.shellwise_allows > 0) {
                println!(
                    "parity {sg}: baseline-guard denies {}, shellwise allows {}",
                    p.baseline_guard_denies, p.shellwise_allows
                );
            }
            let mine: Vec<&ParityException> =
                exceptions.iter().filter(|e| e.baseline_guard == sg).collect();
            for (shape, label, allows, expected, _) in Report::parity_keys(p, &mine) {
                println!(
                    "parity {sg} {shape} {label}: shellwise allows {allows}, expected {expected}, unexplained {}",
                    allows.saturating_sub(expected)
                );
            }
        }
        for (tool, ((p50, p99), per)) in &self.latency {
            println!(
                "latency {}: p50 {p50:.3} ms, p99 {p99:.3} ms (median of {} passes)",
                tool.name(),
                per.len()
            );
        }
        for (rule, tools) in &self.rule_cost {
            for (tool, (n, p50, p99)) in tools {
                println!(
                    "rule cost {rule} {}: {n} rows, p50 {p50:.4} ms, p99 {p99:.4} ms",
                    tool.name()
                );
            }
        }
    }
}

/// The value at rank `ceil(p * n)` of sorted nanoseconds, in milliseconds.
fn percentile(sorted: &[u64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let rank = ((p * sorted.len() as f64).ceil() as usize).clamp(1, sorted.len());
    sorted[rank - 1] as f64 / 1_000_000.0
}

struct KnownResult {
    rows: usize,
    checked: usize,
    not_landed: usize,
    none_rows: usize,
    none_denied: usize,
    fails: Vec<String>,
}

impl KnownResult {
    fn json(&self) -> Value {
        json!({
            "rows": self.rows,
            "checked": self.checked,
            "not_landed": self.not_landed,
            "none_rows": self.none_rows,
            "none_denied": self.none_denied,
        })
    }

    fn print(&self) {
        println!(
            "known: {} of {} rows checked ({} expect a rule not landed yet; {} of {} rows that expect none are denied)",
            self.checked, self.rows, self.not_landed, self.none_denied, self.none_rows
        );
    }
}

/// The known-answer slice. A row whose baseline-guard ids map to a landed rule (`rules::all()` or
/// `rules::length_rules()`) is checked: each such mapped id must be among its findings. A row that
/// expects none is reported when denied, not failed (the meters gate nothing before Task 35).
fn check_known(
    known: &[KnownRow],
    rows: &[(&CorpusRow, Tool)],
    head: &[Replayed],
    map: &RuleMap,
) -> KnownResult {
    let landed: BTreeSet<&'static str> = rules::all()
        .iter()
        .chain(rules::length_rules().iter())
        .map(|r| r.id())
        .collect();
    let by_id: HashMap<&str, &Replayed> = rows
        .iter()
        .zip(head)
        .map(|((row, _), r)| (row.id.as_str(), r))
        .collect();
    let mut out = KnownResult {
        rows: known.len(),
        checked: 0,
        not_landed: 0,
        none_rows: 0,
        none_denied: 0,
        fails: Vec::new(),
    };
    let os_of: HashMap<&str, &'static str> = rows
        .iter()
        .map(|(row, _)| {
            let os = os_name(CwdShape::of(row.cwd.as_deref()).os());
            (row.id.as_str(), os)
        })
        .collect();
    for k in known {
        let found = by_id.get(k.id.as_str()).copied();
        if let (Some(want), Some(got)) = (k.os.as_deref(), os_of.get(k.id.as_str()))
            && want != *got
        {
            out.fails.push(format!(
                "known row {} is {want} in the slice but replays on {got}",
                k.id
            ));
        }
        if k.expected_rules.is_empty() {
            out.none_rows += 1;
            if found.is_some_and(Replayed::denied) {
                out.none_denied += 1;
            }
            continue;
        }
        let wanted: Vec<&str> = k
            .expected_rules
            .iter()
            .filter_map(|sg| map.map.get(sg).map(String::as_str))
            .filter(|id| landed.contains(id))
            .collect();
        if wanted.is_empty() {
            out.not_landed += 1;
            continue;
        }
        out.checked += 1;
        let Some(r) = found else {
            out.fails
                .push(format!("known row {} is not in the corpus", k.id));
            continue;
        };
        for id in wanted {
            if !r.rules.iter().any(|(rule, _)| *rule == id) {
                out.fails.push(format!(
                    "known row {} misses {id}: {}[{}]",
                    k.id,
                    r.level.as_str(),
                    r.rule_list()
                ));
            }
        }
    }
    if out.checked == 0 {
        out.fails.push(format!(
            "0 of {} known rows checked: none expects a landed rule",
            known.len()
        ));
    }
    out
}

/// Known answers for what `replay_input` hands the analysis: a row's delete target resolved by
/// the real parser and resolver with the shell, OS, cwd and env the bench replays it with. No
/// rule on this base resolves a delete target, so the verdict alone cannot show these.
#[cfg(test)]
mod tests {
    use super::*;
    use shellwise::fs::resolve::{Location, Target, delete_by, target};
    use shellwise::fs::{Fs, Meta, RealFs, SharedFs};
    use shellwise::ir::{Elem, Stmt};
    use shellwise::parse;
    use std::io;
    use std::sync::Arc;

    /// `RealFs` with only drive C: present, so a row reads the same on any machine.
    struct DriveC;

    impl Fs for DriveC {
        fn lstat(&self, p: &Path) -> io::Result<Meta> {
            RealFs.lstat(p)
        }
        fn read_dir(&self, p: &Path) -> io::Result<Vec<PathBuf>> {
            RealFs.read_dir(p)
        }
        fn link_target(&self, p: &Path) -> io::Result<Option<PathBuf>> {
            RealFs.link_target(p)
        }
        fn drive_exists(&self, letter: char) -> io::Result<bool> {
            Ok(letter.eq_ignore_ascii_case(&'c'))
        }
    }

    /// The last word of the row's first command, resolved as a delete target.
    fn resolved(tool: Tool, cwd: &str, command: &str) -> Target {
        let row = CorpusRow {
            id: "f000000000c1".to_string(),
            ts: "2026-11-01T10:00:00.000Z".to_string(),
            tool: tool.name().to_string(),
            command: command.to_string(),
            cwd: Some(cwd.to_string()),
            label: "ok".to_string(),
            destructive: true,
        };
        let (shell, os, cwd, env) = replay_input(&row, tool);
        let script = match shell {
            Shell::Bash(profile) => parse::bash::parse(command, profile),
            _ => parse::pwsh::parse(command, shell, os),
        }
        .expect("the command parses");
        let Some(Stmt::Pipeline(p)) = script.stmts.first() else {
            panic!("no pipeline in {command:?}");
        };
        let Some(Elem::Cmd(c)) = p.elems.first() else {
            panic!("no command in {command:?}");
        };
        let mut loc = Location::new(shell, os, cwd.as_deref());
        loc.read_script(&script);
        let fs: SharedFs = Arc::new(DriveC);
        let word = c.args.last().expect("a target");
        target(
            word,
            &loc,
            &env,
            delete_by(c, shell, os),
            &fs,
            &Deadline::new(Instant::now(), 60_000),
        )
    }

    /// The cases `tools/corpus/baseline.py` (`row_os`, a copy of this rule) is tested on too.
    #[test]
    fn each_cwd_shape_names_its_os() {
        let table = include_str!("../tests/bench_fixture/cwd_shapes.tsv");
        let mut n = 0;
        for line in table.lines().skip(1).filter(|l| !l.is_empty()) {
            let cols: Vec<&str> = line.split('\t').collect();
            let cwd = (cols[0] != "-").then_some(cols[0]);
            let shape = CwdShape::of(cwd);
            assert_eq!(shape.name(), cols[1], "{line}");
            assert_eq!(os_name(shape.os()), cols[2], "{line}");
            n += 1;
        }
        assert_eq!(n, 12, "rows read from cwd_shapes.tsv");
    }

    /// R2-5: a cwd on a share no host answers (a documentation address) is read under a bound:
    /// the bench does not stall on it, and the row counts as a cwd gone here.
    #[cfg(windows)]
    #[test]
    fn a_cwd_no_host_answers_is_read_under_a_bound() {
        let row = CorpusRow {
            id: "unc".to_string(),
            ts: String::new(),
            tool: "Bash".to_string(),
            command: "ls".to_string(),
            cwd: Some(r"\\192.0.2.1\share\repo".to_string()),
            label: "ok".to_string(),
            destructive: false,
        };
        let start = Instant::now();
        let missing = cwd_missing(&[(&row, Tool::Bash)]);
        let took = start.elapsed();
        assert!(
            took.as_millis() < u128::from(CWD_READ_MS) + 1500,
            "took {took:?}"
        );
        assert_eq!(missing[os_name(Os::Windows)].bash, 1);
    }

    fn paths(v: &[&str]) -> Target {
        Target::Paths(v.iter().map(PathBuf::from).collect())
    }

    #[test]
    fn a_linux_row_resolves_a_relative_delete_inside_its_project() {
        assert_eq!(
            resolved(Tool::Bash, "/fixture/proj", "rm -rf build"),
            paths(&["/fixture/proj/build"])
        );
    }

    #[test]
    fn a_windows_row_resolves_as_before() {
        assert_eq!(
            resolved(Tool::Bash, r"C:\fixture\proj", "rm -rf build"),
            paths(&[r"C:\fixture\proj\build"])
        );
        assert_eq!(
            resolved(Tool::Pwsh, r"C:\fixture\proj", "Remove-Item -Recurse build"),
            paths(&[r"C:\fixture\proj\build"])
        );
    }

    #[test]
    fn git_bash_tmp_maps_into_the_synthetic_temp() {
        assert_eq!(
            resolved(Tool::Bash, r"C:\fixture\proj", "rm -rf /tmp/fixture"),
            paths(&[r"C:\Profiles\bench\AppData\Local\Temp\fixture"])
        );
    }
}
