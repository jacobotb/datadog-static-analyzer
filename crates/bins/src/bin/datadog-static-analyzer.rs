use cli::config_file::read_config_file;
use cli::datadog_utils::get_ruleset;
use cli::file_utils::{
    are_subdirectories_safe, check_can_scan, filter_files_for_language, get_files,
    read_files_from_gitignore,
};
use cli::model::config_file::{ConfigFile, PathConfig};
use cli::rule_utils::{get_languages_for_rules, get_rulesets_from_file};
use itertools::Itertools;
use kernel::analysis::analyze::analyze;
use kernel::constants::{CARGO_VERSION, VERSION};
use kernel::model::analysis::{AnalysisOptions, ERROR_RULE_TIMEOUT};
use kernel::model::common::OutputFormat;
use kernel::model::rule::{Rule, RuleInternal, RuleResult};

use anyhow::{Context, Result};
use cli::constants::DEFAULT_MAX_FILE_SIZE_KB;
use cli::csv;
use cli::model::cli_configuration::{CliConfiguration, PathConfigStack, RuleWithPaths};
use cli::sarif::sarif_utils::generate_sarif_report;
use getopts::Options;
use indicatif::ProgressBar;
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::io::prelude::*;
use std::process::exit;
use std::time::SystemTime;
use std::{env, fs};

fn get_path_config_stack(a: &PathConfig) -> PathConfigStack {
    let only = match &a.only {
        None => vec![],
        Some(paths) => vec![paths.clone()],
    };
    let ignore = match &a.ignore {
        None => vec![],
        Some(paths) => paths.clone(),
    };
    PathConfigStack { only, ignore }
}

fn extend_paths(base: &PathConfigStack, paths: &PathConfig) -> PathConfigStack {
    let new_stack = get_path_config_stack(paths);
    let mut only = base.only.clone();
    only.extend(new_stack.only);
    let mut ignore = base.ignore.clone();
    ignore.extend(new_stack.ignore);
    PathConfigStack {
        only,
        ignore: ignore.iter().unique().cloned().collect(),
    }
}

// Get all the rules from different rulesets from Datadog
fn get_rules_from_config(config: &ConfigFile, use_staging: bool) -> Result<Vec<RuleWithPaths>> {
    let base_pcr = get_path_config_stack(&config.paths);
    let mut rules_with_paths = Vec::new();
    for (ruleset_name, ruleset_cfg) in &config.rulesets {
        let rules = get_ruleset(&ruleset_name, use_staging)?.rules;
        let ruleset_pcr = extend_paths(&base_pcr, &ruleset_cfg.paths);
        for rule in rules {
            if let Some((_, basename)) = rule.name.split_once("/") {
                let paths = match ruleset_cfg.rules.as_ref().and_then(|r| r.get(basename)) {
                    None => ruleset_pcr.clone(),
                    Some(paths) => extend_paths(&ruleset_pcr, &paths),
                };
                rules_with_paths.push(RuleWithPaths { rule, paths });
            }
        }
    }
    Ok(rules_with_paths)
}

// Returns a list of rules that should be applied to this file.
pub fn filter_rules(
    rules: &[RuleInternal],
    cfg: &CliConfiguration,
    file_path: &str,
) -> HashSet<String> {
    let restrictions = &cfg.rule_restrictions;
    let mut output = HashSet::new();
    for rule in rules {
        let can_scan = match restrictions.get(&rule.name) {
            None => true,
            Some(paths) => check_can_scan(paths, file_path),
        };
        if can_scan {
            output.insert(rule.name.clone());
        }
    }
    output
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} FILE [options]", program);
    print!("{}", opts.usage(&brief));
}

fn print_configuration(configuration: &CliConfiguration) {
    let configuration_method = if configuration.use_configuration_file {
        "config file (static-analysis.datadog.[yml|yaml])"
    } else {
        "rule file"
    };

    let output_format_str = match configuration.output_format {
        OutputFormat::Csv => "csv",
        OutputFormat::Sarif => "sarif",
        OutputFormat::Json => "json",
    };

    let languages = get_languages_for_rules(&configuration.rules);
    let languages_string: Vec<String> = languages.iter().map(|l| l.to_string()).collect();
    let ignore_paths_str = if configuration.ignore_paths.is_empty() {
        "no ignore path".to_string()
    } else {
        configuration.ignore_paths.join(",")
    };
    let only_paths_str = if configuration.only_paths.is_none() {
        "all".to_string()
    } else {
        configuration.only_paths.as_ref().unwrap().join(",")
    };

    println!("Configuration");
    println!("=============");
    println!("version             : {}", CARGO_VERSION);
    println!("revision            : {}", VERSION);
    println!("config method       : {}", configuration_method);
    println!("cores available     : {}", num_cpus::get());
    println!("cores used          : {}", configuration.num_cpus);
    println!("#rules loaded       : {}", configuration.rules.len());
    println!("source directory    : {}", configuration.source_directory);
    println!(
        "subdirectories      : {}",
        configuration.source_subdirectories.clone().join(",")
    );
    println!("output file         : {}", configuration.output_file);
    println!("output format       : {}", output_format_str);
    println!("ignore paths        : {}", ignore_paths_str);
    println!("only paths          : {}", only_paths_str);
    println!("ignore gitignore    : {}", configuration.ignore_gitignore);
    println!(
        "use config file     : {}",
        configuration.use_configuration_file
    );
    println!("use debug           : {}", configuration.use_debug);
    println!("use staging         : {}", configuration.use_staging);
    println!("rules languages     : {}", languages_string.join(","));
    println!(
        "max file size       : {} kb",
        configuration.max_file_size_kb
    );
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let mut opts = Options::new();
    #[allow(unused_assignments)]
    let mut use_configuration_file = false;
    let mut ignore_gitignore = false;
    let mut max_file_size_kb = DEFAULT_MAX_FILE_SIZE_KB;

    opts.optopt(
        "i",
        "directory",
        "directory to scan (valid existing directory)",
        "/path/to/code/to/analyze",
    );
    opts.optmulti(
        "u",
        "subdirectory",
        "subdirectory to scan within the repository",
        "sub/directory",
    );
    opts.optopt(
        "r",
        "rules",
        "rules to use (json file)",
        "/path/to/rules.json",
    );
    opts.optopt("d", "debug", "use debug mode", "yes/no");
    opts.optopt("f", "format", "format of the output file", "json/sarif/csv");
    opts.optopt("o", "output", "output file name", "output.json");
    opts.optopt(
        "c",
        "cpus",
        format!("allow N CPUs at once; if unspecified, defaults to the number of logical cores on the platform or {}, whichever is less", DEFAULT_MAX_CPUS).as_str(),
        "--cpus 5",
    );
    opts.optmulti(
        "p",
        "ignore-path",
        "path to ignore - the value is a glob",
        "**/test*.py (multiple values possible)",
    );
    opts.optflag("h", "help", "print this help");
    opts.optflag("v", "version", "shows the tool version");
    opts.optflag(
        "b",
        "bypass-checksum",
        "bypass checksum verification for the rules",
    );
    opts.optflag(
        "x",
        "performance-statistics",
        "enable performance statistics",
    );
    opts.optflag("s", "staging", "use staging");
    opts.optflag(
        "g",
        "add-git-info",
        "add Git information to the SARIF report",
    );

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => {
            panic!("error when parsing arguments: {}", f)
        }
    };

    if matches.opt_present("v") {
        println!("Version: {}, revision: {}", CARGO_VERSION, VERSION);
        exit(1);
    }

    if matches.opt_present("h") {
        print_usage(&program, opts);
        exit(1);
    }

    if !matches.opt_present("o") {
        eprintln!("output file not specified");
        print_usage(&program, opts);
        exit(1);
    }

    let should_verify_checksum = !matches.opt_present("b");
    let use_staging = matches.opt_present("s");
    let add_git_info = matches.opt_present("g");
    let enable_performance_statistics = matches.opt_present("x");

    let output_format = match matches.opt_str("f") {
        Some(f) => match f.as_str() {
            "csv" => OutputFormat::Csv,
            "sarif" => OutputFormat::Sarif,
            _ => OutputFormat::Json,
        },
        None => OutputFormat::Json,
    };

    let use_debug = *matches
        .opt_str("d")
        .map(|value| value == "yes")
        .get_or_insert(env::var_os("DD_SA_DEBUG").is_some());
    let output_file = matches
        .opt_str("o")
        .context("output file must be specified")?;

    // Show the ignore paths
    let mut ignore_paths: Vec<String> = Vec::new();
    let ignore_paths_from_options = matches.opt_strs("p");
    let directory_to_analyze_option = matches.opt_str("i");
    let subdirectories_to_analyze = matches.opt_strs("u");
    let mut only_paths: Option<Vec<String>> = None;

    let rules_file = matches.opt_str("r");

    if directory_to_analyze_option.is_none() {
        eprintln!("no directory passed, specify a directory with option -i");
        print_usage(&program, opts);
        exit(1)
    }

    let directory_to_analyze = directory_to_analyze_option.unwrap();
    let directory_path = std::path::Path::new(&directory_to_analyze);

    if !directory_path.is_dir() {
        eprintln!("directory to analyze is not correct");
        exit(1)
    }

    if !are_subdirectories_safe(directory_path, &subdirectories_to_analyze) {
        eprintln!("sub-directories are not safe and point outside of the repository");
        exit(1)
    }

    let configuration_file: Option<ConfigFile> =
        read_config_file(directory_to_analyze.as_str()).unwrap();
    let mut rules: Vec<Rule> = Vec::new();
    let mut rule_restrictions = HashMap::new();

    // if there is a configuration file, we load the rules from it. But it means
    // we cannot have the rule parameter given.
    if let Some(conf) = configuration_file {
        use_configuration_file = true;
        ignore_gitignore = conf.ignore_gitignore.unwrap_or(false);
        if rules_file.is_some() {
            eprintln!("a rule file cannot be specified when a configuration file is present.");
            exit(1);
        }

        let rules_from_api = get_rules_from_config(&conf, use_staging)
            .context("error when reading rules from API")?;
        rules.extend(rules_from_api.iter().map(|r| r.rule.clone()));
        rule_restrictions = rules_from_api
            .iter()
            .map(|r| (r.rule.name.clone(), r.paths.clone()))
            .collect();

        // copy the ignore paths from the configuration file
        if let Some(v) = conf.ignore_paths {
            ignore_paths.extend(v);
        }
        if let Some(v) = conf.paths.ignore {
            ignore_paths.extend(v);
        }
        only_paths = conf.paths.only;

        // Get the max file size from the configuration or default to the default constant.
        max_file_size_kb = conf.max_file_size_kb.unwrap_or(DEFAULT_MAX_FILE_SIZE_KB)
    } else {
        use_configuration_file = false;
        // if there is no config file, we must read the rules from a file.
        // Otherwise, we exit.
        if rules_file.is_none() {
            eprintln!("no configuration and no rule files specified. Please have a static-analysis.datadog.yml file or specify rules with -r");
            print_usage(&program, opts);
            exit(1);
        }

        let rulesets_from_file = get_rulesets_from_file(rules_file.clone().unwrap().as_str());
        let rules_from_file: Vec<Rule> = rulesets_from_file
            .context("cannot read ruleset")?
            .iter()
            .flat_map(|v| v.rules.clone())
            .collect();
        rules.extend(rules_from_file);
    }

    // add ignore path from the options
    ignore_paths.extend(ignore_paths_from_options);

    // ignore all directories that are in gitignore
    if !ignore_gitignore {
        let paths_from_gitignore = read_files_from_gitignore(directory_to_analyze.as_str());
        ignore_paths.extend(paths_from_gitignore.expect("error when reading gitignore file"));
    }

    let languages = get_languages_for_rules(&rules);

    let files_to_analyze = get_files(
        directory_to_analyze.as_str(),
        subdirectories_to_analyze.clone(),
        &ignore_paths,
        &only_paths,
    )
    .expect("unable to get the list of files to analyze");

    let num_cores_requested = matches
        .opt_str("c")
        .map(|val| {
            val.parse::<usize>()
                .context("unable to parse `cpus` flag as integer")
        })
        .transpose()?;
    // Select the number of cores to use based on the user's CLI arg (or lack of one)
    let num_cpus = choose_cpu_count(num_cores_requested);

    // build the configuration object that contains how the CLI should behave.
    let configuration = CliConfiguration {
        use_debug,
        use_configuration_file,
        ignore_gitignore,
        source_directory: directory_to_analyze.clone(),
        source_subdirectories: subdirectories_to_analyze.clone(),
        ignore_paths,
        only_paths,
        rules_file,
        output_format,
        num_cpus,
        rules,
        rule_restrictions,
        output_file,
        max_file_size_kb,
        use_staging,
    };

    print_configuration(&configuration);

    let mut all_rule_results = vec![];

    let analysis_options = AnalysisOptions {
        log_output: true,
        use_debug,
    };

    // verify rule checksum
    if should_verify_checksum {
        if configuration.use_debug {
            print!("Checking rule checksum ... ");
        }
        for r in &configuration.rules {
            if !r.verify_checksum() {
                panic!("Checksum invalid for rule {}", r.name);
            }
        }
        if configuration.use_debug {
            println!("done!");
        }
    } else {
        println!("Skipping checksum verification");
    }

    // we always keep one thread free and some room for the management threads that monitor
    // the rule execution.
    let ideal_threads = ((configuration.num_cpus as f32 - 1.0) * 0.90) as usize;
    let num_threads = if ideal_threads == 0 { 1 } else { ideal_threads };

    rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build_global()?;

    let mut total_files_analyzed: usize = 0;
    let start_timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    for language in &languages {
        let files_for_language = filter_files_for_language(&files_to_analyze, language);

        println!(
            "Analyzing {} {:?} files",
            files_for_language.len(),
            language
        );

        // we only use the progress bar when the debug mode is not active, otherwise, it puts
        // too much information on the screen.
        let progress_bar = if !configuration.use_debug {
            Some(ProgressBar::new(files_for_language.len() as u64))
        } else {
            None
        };
        total_files_analyzed += files_for_language.len();

        let rules_for_language: Vec<RuleInternal> = configuration
            .rules
            .iter()
            .filter(|r| r.language == *language)
            .map(|r| {
                r.to_rule_internal()
                    .context("cannot convert to rule internal")
            })
            .collect::<Result<Vec<_>>>()?;

        if use_debug {
            println!(
                "Analyzing {}, {} files detected",
                language,
                files_for_language.len()
            )
        }

        // take the relative path for the analysis
        let rule_results: Vec<RuleResult> = files_for_language
            .into_par_iter()
            .flat_map(|path| match fs::read_to_string(&path) {
                Ok(file_content) => {
                    let file_path = path
                        .strip_prefix(directory_path)
                        .unwrap()
                        .to_str()
                        .expect("path contains non-Unicode characters");
                    let enabled_rules =
                        filter_rules(&rules_for_language, &configuration, file_path);
                    let res = analyze(
                        language,
                        &rules_for_language,
                        Some(enabled_rules),
                        file_path,
                        &file_content,
                        &analysis_options,
                    );

                    if let Some(pb) = &progress_bar {
                        pb.inc(1);
                    }

                    res
                }
                Err(_) => {
                    eprintln!("error when getting content of path {}", &path.display());
                    vec![]
                }
            })
            .collect();
        all_rule_results.append(rule_results.clone().as_mut());

        if let Some(pb) = &progress_bar {
            pb.finish();
        }
    }

    let end_timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let nb_violations: u32 = all_rule_results
        .iter()
        .map(|x| x.violations.len() as u32)
        .sum();

    println!(
        "Found {} violations in {} files using {} rules within {} secs",
        nb_violations,
        total_files_analyzed,
        configuration.rules.len(),
        end_timestamp - start_timestamp
    );

    // If the performance statistics are enabled, we show the total execution time per rule
    // and the rule that timed-out.
    if enable_performance_statistics {
        let mut rules_execution_time_ms: HashMap<String, u128> = HashMap::new();

        // first, get the rule execution time
        for rule_result in &all_rule_results {
            let current_value = rules_execution_time_ms
                .get(&rule_result.rule_name)
                .unwrap_or(&0u128);
            let new_value = current_value + rule_result.execution_time_ms;
            rules_execution_time_ms.insert(rule_result.rule_name.clone(), new_value);
        }

        println!("Rule execution time");
        println!("-------------------");
        // Show execution time, in sorted order
        for v in rules_execution_time_ms
            .iter()
            .sorted_by(|a, b| Ord::cmp(b.1, a.1))
            .as_slice()
        {
            println!("rule {:?} execution time {:?} ms", v.0, v.1);
        }

        // show the rules that timed out
        println!("Rule timed out");
        println!("--------------");
        let rules_timed_out: Vec<RuleResult> = all_rule_results
            .clone()
            .into_iter()
            .filter(|r| r.errors.contains(&ERROR_RULE_TIMEOUT.to_string()))
            .collect();
        if rules_timed_out.is_empty() {
            println!("No rule timed out");
        }
        for v in rules_timed_out {
            println!("Rule {} timed out on file {}", v.rule_name, v.filename);
        }
    }

    let value = match configuration.output_format {
        OutputFormat::Csv => csv::generate_csv_results(&all_rule_results),
        OutputFormat::Json => {
            serde_json::to_string(&all_rule_results).expect("error when getting the JSON report")
        }
        OutputFormat::Sarif => match generate_sarif_report(
            &configuration
                .rules
                .iter()
                .map(|r| r.clone())
                .collect::<Vec<Rule>>(),
            &all_rule_results,
            &directory_to_analyze,
            add_git_info,
            configuration.use_debug,
        ) {
            Ok(report) => {
                serde_json::to_string(&report).expect("error when getting the SARIF report")
            }
            Err(_) => {
                panic!("Error when generating the sarif report");
            }
        },
    };

    // write the reports
    let mut file = fs::File::create(configuration.output_file).context("cannot create file")?;
    file.write_all(value.as_bytes())
        .context("error when writing results")?;
    Ok(())
}

const DEFAULT_MAX_CPUS: usize = 8;

/// Returns the user's requested core count, clamped to the number of logical cores on the system.
/// If unspecified, up to [DEFAULT_MAX_CPUS] CPUs will be used.
fn choose_cpu_count(user_input: Option<usize>) -> usize {
    let logical_cores = num_cpus::get();
    let cores = user_input.unwrap_or(DEFAULT_MAX_CPUS);
    usize::min(logical_cores, cores)
}
