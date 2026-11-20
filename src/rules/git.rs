//! The git rules: what a git command discards or deletes, and the policy rules ported from
//! baseline-guard (`git-restore-discards`, `git-worktree-junction`, `git-no-verify`,
//! `git-unreadable`). Subcommands, options and config keys come from the program's `discard`
//! facts in `data/programs.toml` (`Program::extra`); which flags make a subcommand destructive
//! from `data/destructive.toml`. `git clean` is judged as a delete inside the folder git runs in.

use std::path::Path;
use std::sync::{Arc, OnceLock};

use serde::Deserialize;

use super::delete::{
    self, CONFIRM_FIX, Call, How, Node, Read, Scene, facts_of, finding, is_pwsh, literal,
    literals, max_finding, read_call, row_holds, walk_script,
};
use super::{Ctx, Rule};
use crate::fs::bounded;
use crate::fs::resolve::{self, DeleteBy, Location, Target};
use crate::fs::walk::{self, WalkResult};
use crate::ir::{Word, WordPart};
use crate::level::{Finding, Level, Span};
use crate::programs::Program;
use crate::scan;

/// A version-control program's facts: the `[program.discard]` table of its row.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct GitFacts {
    /// Global options before the subcommand that take the next word (`-C`, `-c`, `--git-dir`).
    pub global_value_options: Vec<String>,
    /// Global options whose value is a config `key=value` (`-c`).
    pub config_options: Vec<String>,
    /// Config keys, lowercased, that can point git at another hooks folder.
    pub hook_config_keys: Vec<String>,
    /// The option that turns the hooks off, and the one that turns them back on.
    pub no_verify: String,
    pub verify: String,
    /// `restore`: limited to the index, and writing the working tree.
    pub staged: Vec<String>,
    pub worktree: Vec<String>,
    /// `restore`: options whose next word is a revision.
    pub source_options: Vec<String>,
    /// `checkout`/`restore`: options that choose hunk by hunk.
    pub hunk_options: Vec<String>,
    /// `checkout`: options that make it a branch operation.
    pub branch_options: Vec<String>,
    /// `clean`: options whose next word is a pattern, not a pathspec.
    pub clean_value_options: Vec<String>,
    pub subcommands: Vec<GitSub>,
}

/// One subcommand the rules know (`commit`, or two words: `worktree remove`). The key is
/// `words`, not `name`: the shape test reads every `name` in the table as a program name.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GitSub {
    pub words: String,
    pub action: GitAction,
    /// `hooks`: the short flags that mean `--no-verify` (`n` for commit).
    #[serde(default)]
    pub no_verify_short: String,
    /// `hooks`: short flags that take a value (`m` for commit's `-m <msg>`).
    #[serde(default)]
    pub value_shorts: String,
    /// `hooks`: long options that take the next word as their value.
    #[serde(default)]
    pub value_long: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum GitAction {
    /// Runs the repository's hooks (`git-no-verify`).
    Hooks,
    /// `git worktree remove` (`git-worktree-junction`).
    WorktreeRemove,
    /// `git checkout` (`git-restore-discards`, or `git-discard` with `-f`).
    CheckoutPaths,
    /// `git restore` (`git-restore-discards`).
    RestorePaths,
    /// Throws away uncommitted work when its table row holds (`git-discard`).
    Discard,
    /// `git clean`: a delete inside the folder git runs in.
    Clean,
}

pub(crate) fn discard_facts(prog: &Program) -> Option<&'static GitFacts> {
    static CACHE: OnceLock<Vec<Option<GitFacts>>> = OnceLock::new();
    facts_of(&CACHE, "discard", prog)
}

pub const GIT_RESTORE_DISCARDS: &str = "git-restore-discards";
pub const GIT_WORKTREE_JUNCTION: &str = "git-worktree-junction";
pub const GIT_DISCARD: &str = "git-discard";
pub const GIT_NO_VERIFY: &str = "git-no-verify";
pub const GIT_UNREADABLE: &str = "git-unreadable";

pub struct GitRule;

impl Rule for GitRule {
    fn id(&self) -> &'static str {
        GIT_RESTORE_DISCARDS
    }

    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
        let shell = ctx.input.shell;
        let os = ctx.input.os;
        if !delete::any_node(ctx.script, &mut |n| match n {
            Node::Cmd { cmd, .. } => {
                matches!(read_call(cmd, false, shell, os), Read::Call(_, p) if discard_facts(p).is_some())
            }
            Node::Method(_) => false,
        }) {
            return;
        }
        let mut scene = Scene::new(ctx);
        let env = scene.env.clone();
        let mut loc = scene.location();
        walk_script(ctx.script, &mut loc, &env, &mut |node, loc| {
            let Node::Cmd { cmd, piped } = node else {
                return;
            };
            if let Read::Call(call, prog) = read_call(cmd, piped, shell, os)
                && let Some(facts) = discard_facts(prog)
            {
                out.extend(judge(&mut scene, &call, facts, loc));
            }
        });
    }
}

/// The span text of a word, or its literal text.
fn shown(scene: &Scene, w: &Word) -> String {
    scene
        .ctx
        .input
        .command
        .get(w.span.start..w.span.end)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| literal(w))
        .unwrap_or_default()
}

/// A word that is one expansion and nothing else: a PowerShell array or list may stand there.
fn whole_expansion(w: &Word) -> bool {
    matches!(w.parts.as_slice(), [WordPart::Var(_) | WordPart::Subst(_)])
        || w.parts.contains(&WordPart::ListSep)
}

/// `t` looks like a git subcommand name: lowercase letters and `-`.
fn subcommand_like(t: &str) -> bool {
    t.starts_with(|c: char| c.is_ascii_lowercase())
        && t.chars().all(|c| c.is_ascii_lowercase() || c == '-')
}

fn unreadable(scene: &Scene, w: &Word, span: Span) -> Finding {
    finding(
        GIT_UNREADABLE,
        scene.ctx.cfg.dynamic_target,
        format!(
            "the guard cannot tell what git runs here: `{}` stands before or in the subcommand and is a variable or an expression, so a `worktree remove` or a `checkout` would go unchecked",
            shown(scene, w)
        ),
        "write git's options and the subcommand literally, for example `git -C <path> <subcommand> ...`".to_string(),
        span,
    )
}

/// The one finding of a git call, in this order: what the guard cannot read, skipped hooks,
/// then what the subcommand discards or deletes.
fn judge(scene: &mut Scene, call: &Call, facts: &GitFacts, loc: &Location) -> Option<Finding> {
    let args = call.args();
    let lits = literals(args);
    let pwsh = is_pwsh(scene.ctx.input.shell);
    // git's own options, then the subcommand.
    let mut i = 0;
    let sub_at = loop {
        let w = args.get(i)?;
        let Some(t) = &lits[i] else {
            return Some(unreadable(scene, w, call.span()));
        };
        if facts.global_value_options.contains(t) {
            if let Some(v) = args.get(i + 1)
                && lits[i + 1].is_none()
            {
                // Bash splits an unquoted expansion; PowerShell an array or a list: either
                // may carry the subcommand, unless a literal name follows it.
                let splits = !pwsh || whole_expansion(v);
                let named_next = lits
                    .get(i + 2)
                    .and_then(|x| x.as_deref())
                    .is_some_and(subcommand_like);
                if splits && !named_next {
                    return Some(unreadable(scene, v, call.span()));
                }
            }
            i += 2;
            continue;
        }
        if t.starts_with('-') {
            i += 1;
            continue;
        }
        break i;
    };
    let sub_text = lits[sub_at].clone().unwrap_or_default();
    let mut matched: Option<(&GitSub, usize)> = None;
    for s in &facts.subcommands {
        let words: Vec<&str> = s.words.split_whitespace().collect();
        if words.first() != Some(&sub_text.as_str()) {
            continue;
        }
        if words.len() == 1 {
            matched = Some((s, sub_at + 1));
            break;
        }
        match lits.get(sub_at + 1) {
            Some(None) => return Some(unreadable(scene, &args[sub_at + 1], call.span())),
            Some(Some(next)) if words[1] == next.as_str() => {
                matched = Some((s, sub_at + 2));
                break;
            }
            _ => {}
        }
    }
    let (sub, rest_at) = matched?;
    let rest = &args[rest_at.min(args.len())..];
    let rest_lits = &lits[rest_at.min(lits.len())..];
    let git_loc = loc.for_git(&call.run, &scene.env);
    match sub.action {
        GitAction::Hooks => {
            if !scene.ctx.cfg.policies.git_no_verify {
                return None;
            }
            hooks(facts, sub, &args[..sub_at], &lits[..sub_at], rest_lits, call.span())
        }
        GitAction::WorktreeRemove => worktree_remove(scene, rest, rest_lits, &git_loc, call),
        GitAction::CheckoutPaths | GitAction::RestorePaths => {
            let found = restore(scene, facts, sub, rest, rest_lits, &git_loc, call.span());
            if found.is_some() {
                return found;
            }
            // `git checkout -f`: no path, but the table says it discards.
            discard(call, sub, rest_lits)
        }
        GitAction::Discard => discard(call, sub, rest_lits),
        GitAction::Clean => clean(scene, facts, call, sub, rest, rest_lits, &git_loc),
    }
}

/// The destructive table's row for `git <sub>` holds for these words.
fn holds(call: &Call, sub: &GitSub, rest_lits: &[Option<String>]) -> Option<bool> {
    let mut name = vec![call.name.clone()];
    name.extend(sub.words.split_whitespace().map(str::to_lowercase));
    row_holds(&name, rest_lits)
}

fn discard(call: &Call, sub: &GitSub, rest_lits: &[Option<String>]) -> Option<Finding> {
    let hit = match holds(call, sub, rest_lits) {
        Some(h) => h,
        None => sub.action == GitAction::Discard,
    };
    hit.then(|| {
        finding(
            GIT_DISCARD,
            Level::Danger,
            format!(
                "`git {}` throws away uncommitted work that no commit or stash holds",
                sub.words
            ),
            CONFIRM_FIX.to_string(),
            call.span(),
        )
    })
}

/// `git-no-verify`: a flag that turns the hooks off, or a `-c` value that may point git at
/// another hooks folder. The last of `--no-verify`/`--verify` wins.
fn hooks(
    facts: &GitFacts,
    sub: &GitSub,
    global: &[Word],
    global_lits: &[Option<String>],
    rest_lits: &[Option<String>],
    span: Span,
) -> Option<Finding> {
    let mut k = 0;
    while k < global.len() {
        let is_config = global_lits[k]
            .as_ref()
            .is_some_and(|t| facts.config_options.contains(t));
        if is_config && let Some(v) = global.get(k + 1) {
            // The key up to the first `=`, as git splits `-c`. A key the guard cannot read
            // may be any key.
            let lead = delete::leading_literal(v).unwrap_or_default();
            let key = match (global_lits[k + 1].as_deref(), lead.split_once('=')) {
                (Some(t), _) => Some(t.split('=').next().unwrap_or(t).to_lowercase()),
                (None, Some((key, _))) => Some(key.to_lowercase()),
                (None, None) => None,
            };
            let redirects = key.is_none_or(|k| facts.hook_config_keys.contains(&k));
            if redirects {
                return Some(no_verify(
                    &sub.words,
                    &global_lits[k + 1].clone().unwrap_or_else(|| lead.to_string()),
                    span,
                ));
            }
        }
        k += if global_lits[k]
            .as_ref()
            .is_some_and(|t| facts.global_value_options.contains(t))
        {
            2
        } else {
            1
        };
    }
    let mut flag: Option<String> = None;
    let mut j = 0;
    while j < rest_lits.len() {
        let Some(a) = rest_lits[j].as_deref() else {
            j += 1;
            continue;
        };
        if a == "--" {
            break;
        }
        if a.starts_with("--") {
            let name = a.split('=').next().unwrap_or(a);
            if name == facts.no_verify {
                flag = Some(a.to_string());
            } else if name == facts.verify {
                flag = None;
            } else if !a.contains('=') && sub.value_long.iter().any(|v| v == name) {
                j += 1;
            }
        } else if a.starts_with('-') && a.len() > 1 {
            let cluster = &a[1..];
            for (n, ch) in cluster.chars().enumerate() {
                if sub.no_verify_short.contains(ch) {
                    flag = Some(a.to_string());
                } else if sub.value_shorts.contains(ch) {
                    // The value is the next word unless attached.
                    if n + 1 == cluster.chars().count() {
                        j += 1;
                    }
                    break;
                }
            }
        }
        j += 1;
    }
    flag.map(|f| no_verify(&sub.words, &f, span))
}

fn no_verify(sub: &str, flag: &str, span: Span) -> Finding {
    finding(
        GIT_NO_VERIFY,
        Level::Danger,
        format!(
            "`git {sub}` with `{flag}` skips the repository's hooks, which the project's rules forbid unless the owner asked for it"
        ),
        format!("run the same `git {sub}` without `{flag}` and fix what the hook reports"),
        span,
    )
}

/// Whether `p` is a folder now (`None` when the deadline passed).
fn is_dir(scene: &Scene, p: &Path) -> Option<bool> {
    let fs = Arc::clone(scene.ctx.fs);
    let p = p.to_path_buf();
    bounded(scene.ctx.deadline, move || fs.lstat(&p).map(|m| m.is_dir)).ok().map(|r| r.unwrap_or(false))
}

/// Whether `p` exists now (`None` when the deadline passed).
fn exists(scene: &Scene, p: &Path) -> Option<bool> {
    let fs = Arc::clone(scene.ctx.fs);
    let p = p.to_path_buf();
    bounded(scene.ctx.deadline, move || fs.lstat(&p).is_ok()).ok()
}

/// `git worktree remove` deletes through junctions inside the tree, with or without `--force`,
/// and empties their targets. A worktree outside the project is no finding by itself: git
/// removes only a registered worktree, and refuses a dirty one without `--force`.
fn worktree_remove(
    scene: &mut Scene,
    rest: &[Word],
    rest_lits: &[Option<String>],
    git_loc: &Location,
    call: &Call,
) -> Option<Finding> {
    let mut j = 0;
    while j < rest.len() {
        match rest_lits[j].as_deref() {
            Some("--") => {
                j += 1;
                break;
            }
            Some(t) if t.starts_with('-') => j += 1,
            _ => break,
        }
    }
    let word = rest.get(j)?;
    let text = shown(scene, word);
    let cannot_tell = |why: &str| {
        finding(
            GIT_WORKTREE_JUNCTION,
            Level::Danger,
            format!(
                "`git worktree remove` deletes through junctions inside the tree and empties their targets, and the guard cannot tell which folder `{text}` is: {why}"
            ),
            "pass the worktree's full path".to_string(),
            call.span(),
        )
    };
    let target = resolve::target(
        word,
        git_loc,
        &scene.env,
        DeleteBy::Native,
        scene.ctx.fs,
        scene.ctx.deadline,
    );
    let paths = match target {
        Target::Paths(ps) => ps,
        Target::Dynamic(_) => return Some(cannot_tell("it holds a variable or a substitution")),
        Target::UnknownLocation(_) | Target::DriveUnproven { .. } => {
            return Some(cannot_tell("the folder git runs in is not known"));
        }
        Target::NotAFile | Target::SessionCommand => return None,
        Target::Timeout => return Some(scene.timeout(call.span(), &text)),
    };
    let literal_text = rest_lits[j].as_deref();
    let absolute = literal_text.is_some_and(|t| {
        Path::new(t).is_absolute() || t.starts_with('/') || t.starts_with('\\')
    });
    let shell = scene.ctx.input.shell;
    let mut worst = None;
    for p in paths {
        match scene.critical(&p, false) {
            Err(_) => return Some(scene.timeout(call.span(), &text)),
            Ok(Some(reason)) => return Some(delete::critical(&p, reason, call.span())),
            Ok(None) => {}
        }
        let found = match is_dir(scene, &p) {
            None => Some(scene.timeout(call.span(), &text)),
            // git matches a relative name against the end of each registered worktree first,
            // which the guard does not list.
            Some(false) if !absolute => Some(cannot_tell(
                "no folder of that name is here, and git may match it to a registered worktree by its name",
            )),
            Some(false) => None,
            Some(true) => match walk::outside_links(&p, scene.ctx.fs, scene.ctx.deadline) {
                WalkResult::Clean => None,
                WalkResult::Outside(links) => {
                    let link = links.first().map(|l| l.path.clone()).unwrap_or_default();
                    let unlink = if is_pwsh(shell) {
                        format!("[IO.Directory]::Delete('{}')", link.display())
                    } else {
                        format!("rm '{}'", link.display().to_string().replace('\\', "/"))
                    };
                    Some(finding(
                        GIT_WORKTREE_JUNCTION,
                        Level::Danger,
                        format!(
                            "`git worktree remove` deletes through junctions, with or without --force: `{}` holds `{}`, so git would empty its target",
                            p.display(),
                            link.display()
                        ),
                        format!(
                            "remove each link inside it first with `{unlink}` in a command of its own, then remove the worktree"
                        ),
                        call.span(),
                    ))
                }
                WalkResult::Unreadable(at) => Some(finding(
                    delete::WALK_UNREADABLE,
                    Level::Danger,
                    format!(
                        "the guard cannot read `{}` inside the worktree `{}`, so it cannot tell whether a junction there leads outside it",
                        at.display(),
                        p.display()
                    ),
                    CONFIRM_FIX.to_string(),
                    call.span(),
                )),
                WalkResult::Timeout => Some(scene.timeout(call.span(), &text)),
            },
        };
        worst = max_finding(worst, found);
    }
    worst
}

/// `git checkout -- <paths>`, `git checkout .`, `git checkout <file>` and `git restore`
/// overwrite uncommitted edits in the working tree.
fn restore(
    scene: &mut Scene,
    facts: &GitFacts,
    sub: &GitSub,
    rest: &[Word],
    rest_lits: &[Option<String>],
    git_loc: &Location,
    span: Span,
) -> Option<Finding> {
    if rest_lits
        .iter()
        .flatten()
        .any(|a| facts.hunk_options.contains(a))
    {
        // Conflict resolution or interactive: chosen hunk by hunk.
        return None;
    }
    let end = rest_lits.iter().position(|a| a.as_deref() == Some("--"));
    let is_dot = |a: &Option<String>| a.as_deref().is_some_and(|t| t.len() == 1 && t.starts_with('.'));
    let mut paths: Vec<&Word> = Vec::new();
    let mut unknown = false;
    if sub.action == GitAction::CheckoutPaths {
        if let Some(e) = end {
            paths.extend(&rest[e + 1..]);
        } else if let Some(k) = rest_lits.iter().position(is_dot) {
            paths.push(&rest[k]);
        } else if rest_lits
            .iter()
            .flatten()
            .any(|a| facts.branch_options.iter().any(|b| scan::flag_matches(b, a)))
        {
            // A branch operation: git takes no path here.
            return None;
        } else {
            // A word on disk is a path; a word the guard cannot place may be one.
            for (w, t) in rest.iter().zip(rest_lits) {
                if t.as_deref().is_some_and(|t| t.starts_with('-')) {
                    continue;
                }
                match resolve::target(w, git_loc, &scene.env, DeleteBy::Native, scene.ctx.fs, scene.ctx.deadline) {
                    Target::Paths(ps) => {
                        if ps.iter().any(|p| exists(scene, p) != Some(false)) {
                            paths.push(w);
                        }
                    }
                    Target::NotAFile | Target::SessionCommand => {}
                    _ => {
                        unknown = true;
                        paths.push(w);
                    }
                }
            }
        }
    } else {
        let before = &rest_lits[..end.unwrap_or(rest_lits.len())];
        let has = |list: &[String]| {
            before
                .iter()
                .flatten()
                .any(|a| list.iter().any(|e| scan::flag_matches(e, a)))
        };
        if has(&facts.staged) && !has(&facts.worktree) {
            return None;
        }
        let mut j = 0;
        while j < rest.len() {
            let t = rest_lits[j].as_deref();
            if end == Some(j) {
                j += 1;
                continue;
            }
            let after_end = end.is_some_and(|e| j > e);
            match t {
                Some(t) if !after_end && facts.source_options.iter().any(|s| s == t) => j += 2,
                Some(t) if !after_end && t.starts_with('-') => j += 1,
                _ => {
                    paths.push(&rest[j]);
                    j += 1;
                }
            }
        }
    }
    if paths.is_empty() {
        return None;
    }
    let names: Vec<String> = paths.iter().take(3).map(|w| shown(scene, w)).collect();
    let list = names.join(" ");
    let message = if unknown && end.is_none() {
        format!(
            "the guard cannot tell whether `{}` names a file here, and `git {}` on a file throws away every uncommitted edit in it",
            names[0], sub.words
        )
    } else {
        format!(
            "`git {}` on {list} throws away every uncommitted edit in those files, not only yours",
            sub.words
        )
    };
    let fix = if unknown && end.is_none() {
        "switch branches with `git switch <branch>`; to restore a file, name it after `--`, or, if this is intended, run the same command again with ` # shellwise: allow` at its end".to_string()
    } else {
        format!("look at `git diff --stat -- {list}` first; {CONFIRM_FIX}")
    };
    Some(finding(GIT_RESTORE_DISCARDS, Level::Danger, message, fix, span))
}

/// `git clean -f` deletes untracked files inside the folder git runs in, or inside the
/// pathspecs it is given: judged as a delete of their contents.
fn clean(
    scene: &mut Scene,
    facts: &GitFacts,
    call: &Call,
    sub: &GitSub,
    rest: &[Word],
    rest_lits: &[Option<String>],
    git_loc: &Location,
) -> Option<Finding> {
    if holds(call, sub, rest_lits) != Some(true) {
        return None;
    }
    let how = How {
        recursive: false,
        contents: true,
    };
    let mut specs: Vec<&Word> = Vec::new();
    let mut ended = false;
    let mut j = 0;
    while j < rest.len() {
        match rest_lits[j].as_deref() {
            Some("--") if !ended => ended = true,
            Some(t) if !ended && facts.clean_value_options.iter().any(|v| v == t) => j += 1,
            Some(t) if !ended && t.starts_with('-') => {}
            _ => specs.push(&rest[j]),
        }
        j += 1;
    }
    let mut worst = None;
    if specs.is_empty() {
        let shown_cmd = scene
            .ctx
            .input
            .command
            .get(call.span().start..call.span().end)
            .unwrap_or_default()
            .to_string();
        match git_loc.dirs() {
            Some(dirs) => {
                for d in dirs {
                    let found = scene.judge_path(&d, how, call.span(), &shown_cmd);
                    worst = max_finding(worst, found);
                }
            }
            None => {
                return Some(scene.unknown_location(
                    call.span(),
                    &shown_cmd,
                    "the folder git runs in is not known",
                ));
            }
        }
        return worst;
    }
    for w in specs {
        let found = scene.judge_word(w, git_loc, DeleteBy::Native, how, call.span());
        worst = max_finding(worst, found);
    }
    worst
}
