//! Levels, findings and the verdict every check returns.

use serde::Serialize;

/// Severity of a finding. The order is the order of the variants: `Ok < Warn < Break < Danger < Critical`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Ok,
    Warn,
    Break,
    Danger,
    Critical,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Ok => "ok",
            Level::Warn => "warn",
            Level::Break => "break",
            Level::Danger => "danger",
            Level::Critical => "critical",
        }
    }
}

/// Byte offsets into the original command text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub rule: &'static str,
    pub level: Level,
    pub message: String,
    pub fix: Option<String>,
    pub span: Span,
}

impl Finding {
    /// The correction as one line, `Fix: <text>`; `None` when the finding has none.
    pub fn fix_line(&self) -> Option<String> {
        self.fix
            .as_deref()
            .filter(|f| !f.is_empty())
            .map(|f| format!("Fix: {f}"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Verdict {
    pub level: Level,
    pub findings: Vec<Finding>,
}

impl Verdict {
    /// The verdict of these findings: the highest level wins, `Ok` when there are none.
    pub fn new(findings: Vec<Finding>) -> Verdict {
        let level = findings.iter().map(|f| f.level).max().unwrap_or(Level::Ok);
        Verdict { level, findings }
    }
}

/// Exit code of `shellwise check` for a verdict level.
pub fn exit_code(level: Level) -> i32 {
    match level {
        Level::Ok | Level::Warn => 0,
        Level::Break => 1,
        Level::Danger => 2,
        Level::Critical => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(level: Level) -> Finding {
        Finding {
            rule: "r",
            level,
            message: String::new(),
            fix: None,
            span: Span::default(),
        }
    }

    #[test]
    fn verdict_level_is_the_highest_finding() {
        assert_eq!(Verdict::new(vec![]).level, Level::Ok);
        let v = Verdict::new(vec![
            finding(Level::Warn),
            finding(Level::Danger),
            finding(Level::Break),
        ]);
        assert_eq!(v.level, Level::Danger);
        assert_eq!(v.findings.len(), 3);
        let v = Verdict::new(vec![finding(Level::Critical), finding(Level::Warn)]);
        assert_eq!(v.level, Level::Critical);
    }

    #[test]
    fn exit_code_table() {
        let table = [
            (Level::Ok, 0),
            (Level::Warn, 0),
            (Level::Break, 1),
            (Level::Danger, 2),
            (Level::Critical, 3),
        ];
        for (level, code) in table {
            assert_eq!(exit_code(level), code, "{level:?}");
        }
    }

    #[test]
    fn levels_are_ordered() {
        assert!(Level::Ok < Level::Warn);
        assert!(Level::Warn < Level::Break);
        assert!(Level::Break < Level::Danger);
        assert!(Level::Danger < Level::Critical);
    }
}
