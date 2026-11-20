//! The JSON form of `shellwise check --json`.

use serde::Serialize;

use crate::level::{Finding, Level, Verdict};

#[derive(Serialize)]
struct Doc<'a> {
    version: u32,
    level: Level,
    findings: &'a [Finding],
}

/// `{"version":1,"level":…,"findings":[{"rule","level","message","fix","span":{"start","end"}}]}`
pub fn render(verdict: &Verdict) -> String {
    let doc = Doc {
        version: 1,
        level: verdict.level,
        findings: &verdict.findings,
    };
    serde_json::to_string(&doc).expect("a verdict always serialises")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::level::{Finding, Level, Span};

    #[test]
    fn renders_the_documented_shape() {
        let v = Verdict::new(vec![
            Finding {
                rule: "analysis-failed",
                level: Level::Danger,
                message: "m \"q\"".into(),
                fix: Some("f".into()),
                span: Span { start: 3, end: 9 },
            },
            Finding {
                rule: "w",
                level: Level::Warn,
                message: "n".into(),
                fix: None,
                span: Span { start: 0, end: 1 },
            },
        ]);
        assert_eq!(
            render(&v),
            concat!(
                r#"{"version":1,"level":"danger","findings":["#,
                r#"{"rule":"analysis-failed","level":"danger","message":"m \"q\"","fix":"f","span":{"start":3,"end":9}},"#,
                r#"{"rule":"w","level":"warn","message":"n","fix":null,"span":{"start":0,"end":1}}]}"#
            )
        );
        assert_eq!(
            render(&Verdict::new(vec![])),
            r#"{"version":1,"level":"ok","findings":[]}"#
        );
    }
}
