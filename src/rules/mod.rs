//! Rules run over the IR of one command.

use crate::config::Config;
use crate::fs::SharedFs;
use crate::ir::Script;
use crate::level::Finding;
use crate::parse::ParseError;
use crate::{CheckInput, Deadline, Origin};

pub mod parse_error;

pub struct Ctx<'a> {
    pub input: &'a CheckInput<'a>,
    /// Empty when the parse failed; `parse_error` then holds why.
    pub script: &'a Script,
    pub parse_error: Option<&'a ParseError>,
    pub cfg: &'a Config,
    /// Shared so a bounded call can hand it to a worker thread that may outlive the check.
    pub fs: &'a SharedFs,
    pub deadline: &'a Deadline,
}

/// Which texts a rule checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    CommandLine,
    File,
    Both,
}

impl Scope {
    pub fn covers(self, origin: Origin) -> bool {
        match self {
            Scope::Both => true,
            Scope::CommandLine => origin == Origin::CommandLine,
            Scope::File => origin == Origin::File,
        }
    }
}

pub trait Rule {
    fn id(&self) -> &'static str;
    fn scope(&self) -> Scope {
        Scope::Both
    }
    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>);
}

/// The rules on the raw text, run before any size cap and before the parse: their context has an
/// empty script and no parse error.
pub fn length_rules() -> Vec<Box<dyn Rule>> {
    vec![
        #[cfg(feature = "testhooks")]
        Box::new(testhooks::LengthHook),
    ]
}

/// Every rule, in the order they run.
pub fn all() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(parse_error::ParseErrorRule),
        #[cfg(feature = "testhooks")]
        Box::new(testhooks::TestHook),
    ]
}

/// Test-only behaviour selected by `SHELLWISE_TESTHOOK`: `panic` panics inside the rule, `sleep`
/// blocks for a minute, `length` makes a length rule fire and `length-panic` panics in it.
/// Compiled only with the `testhooks` feature.
#[cfg(feature = "testhooks")]
pub mod testhooks {
    use super::*;

    pub fn mode() -> String {
        std::env::var("SHELLWISE_TESTHOOK").unwrap_or_default()
    }

    pub struct TestHook;

    impl Rule for TestHook {
        fn id(&self) -> &'static str {
            "testhook"
        }

        fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>) {
            match mode().as_str() {
                "slow" => {
                    std::thread::sleep(std::time::Duration::from_secs(1));
                    out.push(Finding {
                        rule: "testhook-done",
                        level: crate::level::Level::Warn,
                        message: "the analysis finished".to_string(),
                        fix: None,
                        span: crate::level::Span::default(),
                    });
                }
                "panic" | "panic-scan-sleep" => panic!("testhook: panic inside a rule"),
                "sleep" => std::thread::sleep(std::time::Duration::from_secs(60)),
                "recurse" => {
                    let depth = ctx.input.command.bytes().filter(|&b| b == b'(').count();
                    std::hint::black_box(recurse(depth));
                }
                _ => {}
            }
        }
    }

    /// A length rule that fires on any text in the `length` mode.
    pub struct LengthHook;

    impl Rule for LengthHook {
        fn id(&self) -> &'static str {
            "testhook-length"
        }

        fn check(&self, _ctx: &Ctx, out: &mut Vec<Finding>) {
            if mode() == "length-panic" {
                panic!("testhook: panic inside a length rule");
            }
            if mode() == "length" {
                out.push(Finding {
                    rule: "testhook-length",
                    level: crate::level::Level::Break,
                    message: "the length hook fired".to_string(),
                    fix: Some("unset SHELLWISE_TESTHOOK".to_string()),
                    span: crate::level::Span::default(),
                });
            }
        }
    }

    /// About 1 KB of stack per level, as a recursive lowering of nested groups would use.
    fn recurse(depth: usize) -> u8 {
        let frame = std::hint::black_box([depth as u8; 1024]);
        if depth == 0 {
            return frame[0];
        }
        recurse(depth - 1).wrapping_add(frame[depth % 1024])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_scope_covers_its_origins() {
        let table = [
            (Scope::Both, Origin::CommandLine, true),
            (Scope::Both, Origin::File, true),
            (Scope::CommandLine, Origin::CommandLine, true),
            (Scope::CommandLine, Origin::File, false),
            (Scope::File, Origin::File, true),
            (Scope::File, Origin::CommandLine, false),
        ];
        for (scope, origin, want) in table {
            assert_eq!(scope.covers(origin), want, "{scope:?} {origin:?}");
        }
    }
}
