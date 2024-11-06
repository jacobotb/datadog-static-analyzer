use crate::datadog_static_analyzer::{declare_options, parse_options, run_analysis};
use anyhow::Result;
use cli::datadog_utils::get_secrets_rules;
use kernel::analysis::analyze::LocalAnalysisEngine;

mod datadog_static_analyzer;

fn main() -> Result<()> {
    let mut opts = declare_options();
    opts.optflag("", "secrets", "enable secrets detection (BETA)");

    let (matches, mut configuration) = parse_options(opts)?;

    if matches.opt_present("secrets") {
        configuration.secrets_enabled = true;
        configuration.secrets_rules = get_secrets_rules(configuration.use_staging)?;
    }

    run_analysis(configuration, LocalAnalysisEngine {})
}
