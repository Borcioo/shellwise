//! The allow marker: a real trailing comment `# shellwise: allow` (or the transition alias
//! `# baseline-guard: allow`) at the very end of the command confirms it. It downgrades `break`
//! and `danger` findings to `ok` and never touches `critical`, the host-limit rules (F7: the
//! text is too long for the host whatever the agent means) or a failed analysis (without a
//! parse nothing shows the marker is a comment). Text inside a string, a heredoc or a
//! here-string is no comment, so the parsers never report it.

use crate::ir::{Comment, Script};
use crate::level::{Level, Verdict};

/// The marker texts after `#`, as written.
pub const MARKERS: [&str; 2] = ["shellwise: allow", "baseline-guard: allow"];

/// Rules the marker never downgrades: the host limits (`too-long`, `inline-script-too-long`)
/// and the two failure rules.
const NOT_CONFIRMABLE: [&str; 5] = [
    super::length::TOO_LONG,
    // Task 31's rule; its constant replaces this text when it lands.
    "inline-script-too-long",
    super::parse_error::PARSE_ERROR,
    super::parse_error::PARSE_ERROR_DESTRUCTIVE,
    crate::ANALYSIS_INCOMPLETE,
];

fn is_marker(c: &Comment, command: &str) -> bool {
    let text = c.text.strip_prefix('#').unwrap_or("").trim();
    c.trailing
        && MARKERS.contains(&text)
        && command
            .get(c.span.end..)
            .is_some_and(|rest| rest.trim().is_empty())
}

/// The command ends with the marker as a trailing comment.
pub fn is_marked(script: &Script, command: &str) -> bool {
    script.comments.iter().any(|c| is_marker(c, command))
}

/// The verdict once the marker is read. `parse_failed`: the text did not parse, so the script
/// holds no comment the marker could be; the verdict stays as it is.
pub fn apply(script: &Script, command: &str, parse_failed: bool, verdict: Verdict) -> Verdict {
    if parse_failed || !is_marked(script, command) {
        return verdict;
    }
    let findings = verdict
        .findings
        .into_iter()
        .map(|mut f| {
            if matches!(f.level, Level::Break | Level::Danger)
                && !NOT_CONFIRMABLE.contains(&f.rule)
            {
                f.level = Level::Ok;
                f.message = format!("{} (confirmed by the trailing allow marker)", f.message);
            }
            f
        })
        .collect();
    Verdict::new(findings)
}
