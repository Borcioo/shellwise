//! Configuration. Only the defaults so far; the integration, user and repo layers come later.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Upper bound for the whole analysis, folder walks included.
    pub walk_budget_ms: u64,
    /// The host's hook timeout; the analysis ends 1500 ms before it.
    pub hook_timeout_ms: u64,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            walk_budget_ms: 8000,
            hook_timeout_ms: 10000,
        }
    }
}
