use crate::datadog_static_analyzer::{declare_options, parse_options, run_analysis};
use anyhow::{anyhow, Result};
use cli::constants::{HEADER_CONTENT_TYPE, HEADER_CONTENT_TYPE_APPLICATION_JSON};
use common::analysis_options::AnalysisOptions;
use kernel::analysis::analyze::AnalysisEngine;
use kernel::config_file::config_file_to_yaml;
use kernel::model::common::Language;
use kernel::model::config_file::ConfigFile;
use kernel::model::rule::{Rule, RuleResult};
use kernel::rule_config::RuleConfig;
use kernel::utils::encode_base64_string;
use reqwest::blocking::RequestBuilder;
use server::model::analysis_request::{AnalysisRequest, AnalysisRequestOptions, ServerRule};
use server::model::analysis_response::{AnalysisResponse, RuleResponse};
use std::borrow::Borrow;
use std::process::exit;
use std::sync::Arc;

mod datadog_static_analyzer;

fn main() -> Result<()> {
    let mut opts = declare_options();
    opts.optopt(
        "",
        "server",
        "address of the static analyzer server",
        "https://example.com:443",
    );

    let (matches, mut configuration) = parse_options(opts)?;

    configuration.num_threads = configuration.num_cpus;

    let server = matches
        .opt_str("server")
        .ok_or_else(|| anyhow!("static analyzer server address has not been specified"))?;
    let engine = RemoteAnalysisEngine::new(server, configuration.configuration_file.clone());

    run_analysis(configuration, engine)
}

struct RemoteAnalysisEngine {
    base_url: String,
    config_file_base64: Option<String>,
}

impl RemoteAnalysisEngine {
    pub fn new(base_url: String, config: Option<ConfigFile>) -> Self {
        let config_file_base64 = config.map(|cfg| {
            encode_base64_string(config_file_to_yaml(&cfg).unwrap_or_else(|e| {
                eprintln!("error regenerating config file: {}", e);
                exit(1)
            }))
        });
        RemoteAnalysisEngine {
            base_url,
            config_file_base64,
        }
    }
}

impl AnalysisEngine for RemoteAnalysisEngine {
    fn analyze<I>(
        &self,
        language: &Language,
        rules: I,
        filename: &Arc<str>,
        code: &Arc<str>,
        _: &RuleConfig,
        analysis_option: &AnalysisOptions,
    ) -> Result<Vec<RuleResult>>
    where
        I: IntoIterator,
        I::Item: Borrow<Rule>,
    {
        let payload = AnalysisRequest {
            filename: filename.to_string(),
            language: *language,
            file_encoding: "utf-8".to_string(),
            code_base64: get_code_base64(code),
            rules: get_server_rules(rules),
            configuration_base64: self.config_file_base64.clone(),
            options: get_analysis_options(analysis_option),
        };

        let url = format!("{}/analyze", self.base_url);
        let request_builder = reqwest::blocking::Client::new()
            .post(&url)
            .header(HEADER_CONTENT_TYPE, HEADER_CONTENT_TYPE_APPLICATION_JSON)
            .json(&payload);
        perform_request(request_builder, &url, false).map(|response| {
            for r in response.errors {
                eprintln!("Static analysis error: {}", r);
            }
            get_results(filename, response.rule_responses)
        })
    }
}

fn get_code_base64(code: &str) -> String {
    encode_base64_string(code.to_string())
}

fn get_server_rules<I>(rules: I) -> Vec<ServerRule>
where
    I: IntoIterator,
    I::Item: Borrow<Rule>,
{
    rules
        .into_iter()
        .map(|r| {
            let rule = r.borrow();
            ServerRule {
                name: rule.name.clone(),
                short_description_base64: rule.short_description_base64.clone(),
                description_base64: rule.description_base64.clone(),
                category: Some(rule.category),
                severity: Some(rule.severity),
                language: rule.language,
                rule_type: rule.rule_type,
                entity_checked: rule.entity_checked,
                code_base64: rule.code_base64.clone(),
                checksum: if rule.checksum.is_empty() {
                    None
                } else {
                    Some(rule.checksum.clone())
                },
                pattern: rule.pattern.clone(),
                tree_sitter_query_base64: rule.tree_sitter_query_base64.clone(),
                arguments: rule.arguments.clone(),
            }
        })
        .collect()
}

fn get_analysis_options(analysis_options: &AnalysisOptions) -> Option<AnalysisRequestOptions> {
    Some(AnalysisRequestOptions {
        use_tree_sitter: Some(true),
        log_output: Some(analysis_options.log_output),
    })
}

fn get_results(filename: &str, rule_responses: Vec<RuleResponse>) -> Vec<RuleResult> {
    rule_responses
        .into_iter()
        .map(|r| RuleResult {
            rule_name: r.identifier,
            filename: filename.to_string(),
            violations: r.violations.into_iter().map(|v| v.0).collect(),
            errors: r.errors,
            execution_error: r.execution_error,
            output: r.output,
            execution_time_ms: r.execution_time_ms,
            parsing_time_ms: r.parsing_time_ms,
            query_node_time_ms: r.query_node_time_ms,
        })
        .collect()
}

fn perform_request(
    request_builder: RequestBuilder,
    path: &str,
    debug: bool,
) -> Result<AnalysisResponse> {
    let mut server_response = None;
    let mut retry_time = std::time::Duration::from_secs(1);
    for i in 0..5 {
        match request_builder
            .try_clone()
            .expect("Cloning a request builder should not fail")
            .send()
        {
            Ok(r) => {
                server_response = Some(Ok(r));
                break;
            }
            Err(e) => {
                if debug {
                    eprintln!(
                        "[Attempt #{}] Error when querying the static analyzer server at {path}: {e}",
                        i + 1
                    );
                    eprintln!("Retrying in {} seconds", retry_time.as_secs());
                }
                server_response = Some(Err(e));
                std::thread::sleep(retry_time);
                retry_time *= 2; // Exponential backoff
            }
        }
    }

    let server_response = server_response
        .expect("server_response should have been set")
        .map_err(|e| anyhow!("Error when querying the datadog server at {path}: {e}"))?;

    let status_code = server_response.status();
    if !&status_code.is_success() {
        return Err(anyhow!("server returned error {}", &status_code.as_u16()));
    }

    let response_text = &server_response.text()?;
    Ok(serde_json::from_str::<AnalysisResponse>(response_text)?)
}
