//! Rules run over the IR of one command.

use crate::config::Config;
use crate::fs::Fs;
use crate::ir::Script;
use crate::level::Finding;
use crate::{CheckInput, Deadline};

pub struct Ctx<'a> {
    pub input: &'a CheckInput<'a>,
    pub script: &'a Script,
    pub cfg: &'a Config,
    pub fs: &'a dyn Fs,
    pub deadline: &'a Deadline,
}

pub trait Rule {
    fn id(&self) -> &'static str;
    fn check(&self, ctx: &Ctx, out: &mut Vec<Finding>);
}

/// Every rule, in the order they run.
pub fn all() -> Vec<Box<dyn Rule>> {
    vec![
        #[cfg(feature = "testhooks")]
        Box::new(testhooks::TestHook),
    ]
}

/// Test-only behaviour selected by `SHELLWISE_TESTHOOK`: `panic` panics inside the rule, `sleep`
/// blocks for a minute. Compiled only with the `testhooks` feature.
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

    /// About 1 KB of stack per level, as a recursive lowering of nested groups would use.
    fn recurse(depth: usize) -> u8 {
        let frame = std::hint::black_box([depth as u8; 1024]);
        if depth == 0 {
            return frame[0];
        }
        recurse(depth - 1).wrapping_add(frame[depth % 1024])
    }
}
