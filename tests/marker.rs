//! The allow marker's message through `analyse`.

use std::time::Instant;

use shellwise::config::Config;
use shellwise::ir::EnvView;
use shellwise::level::Level;
use shellwise::{AnalyseInput, BashProfile, Deadline, Origin, Os, Shell, analyse};

/// F-A6: a config that lowers `delete-critical` to danger lets the marker confirm it, and the
/// message then no longer says the marker cannot.
#[test]
fn a_confirmed_critical_a_config_lowered_does_not_say_the_marker_cannot_confirm_it() {
    let command = "rm -rf / # shellwise: allow";
    let input = AnalyseInput {
        bytes: command.as_bytes(),
        shell: Shell::Bash(BashProfile::Posix),
        os: Os::Posix,
        cwd: None,
        env: EnvView::new(),
        origin: Origin::CommandLine,
        problem: None,
    };
    let deadline = Deadline::new(Instant::now(), 8000);
    // Control: at its default level the marker does not touch it, and the message says so.
    let v = analyse(&input, &Config::default(), &deadline);
    assert_eq!(v.level, Level::Critical, "{v:?}");
    assert!(v.findings[0].message.contains("cannot confirm"), "{v:?}");

    let mut cfg = Config::default();
    cfg.levels
        .insert("delete-critical".to_string(), Level::Danger);
    let v = analyse(&input, &cfg, &deadline);
    assert_eq!(v.level, Level::Ok, "{v:?}");
    let m = &v.findings[0].message;
    assert!(
        m.ends_with("(confirmed by the trailing allow marker)"),
        "{m}"
    );
    assert!(!m.contains("cannot confirm"), "{m}");
}
