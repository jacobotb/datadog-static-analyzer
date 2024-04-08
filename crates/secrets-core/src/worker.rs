// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::checker::CheckData;
use crate::location::PointLocator;
use crate::rule::{LocatedString, Rule, RuleId, RuleMatch};
use crate::rule_evaluator::{EvaluatorError, RuleEvaluator};
use crate::validator::Candidate;
use crate::Matcher;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::string::FromUtf8Error;
use std::sync::Arc;

pub struct Worker {
    rules: Vec<RuleId>,
    rule_evaluator: RuleEvaluator,
}

#[derive(Debug, thiserror::Error)]
pub enum WorkerError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Utf8(#[from] FromUtf8Error),
    #[error("rule evaluator error: {0}")]
    Evaluator(#[from] EvaluatorError),
}

impl Worker {
    pub fn new(matchers: impl Into<Vec<Matcher>>, rules: impl AsRef<[Arc<Rule>]>) -> Self {
        let rule_ids = rules
            .as_ref()
            .iter()
            .map(|rule| rule.id().clone())
            .collect::<Vec<_>>();
        let rule_evaluator = RuleEvaluator::new(matchers, rules);
        Self {
            rules: rule_ids,
            rule_evaluator,
        }
    }

    /// Performs an IO operation to read the specified rule and run all rules against the content.
    pub fn analyze_file(&mut self, path: &Path) -> Result<Vec<Candidate>, WorkerError> {
        let data = self.read_file(path)?;

        self.scan_file(path, &data)
    }

    /// Performs I/O to read a file at the given path into a byte vector.
    pub fn read_file(&self, path: &Path) -> Result<Vec<u8>, WorkerError> {
        fs::read(path).map_err(WorkerError::Io)
    }

    pub fn scan_file(&mut self, path: &Path, data: &[u8]) -> Result<Vec<Candidate>, WorkerError> {
        let locator = PointLocator::new(data);
        let mut candidates = Vec::new();
        let check_data = CheckData::new(Some(data), None, Some(path));
        let scanner = self.rule_evaluator.scan(check_data);

        for rule_id in &self.rules {
            let scan_iter = scanner.rule(rule_id).map_err(WorkerError::Evaluator)?;
            for checked_match in scan_iter {
                let mut captures = HashMap::<String, LocatedString>::with_capacity(
                    checked_match.0.captures().captures_len(),
                );
                let captures_iter = checked_match.0.captures().into_iter();
                for (name, capture) in captures_iter {
                    if let (Some(name), Some(capture)) = (name, capture) {
                        let located = LocatedString::from_locator(&locator, capture.byte_span())
                            .map_err(WorkerError::Utf8)?;
                        captures.insert(name.to_string(), located);
                    }
                }
                let matched =
                    LocatedString::from_locator(&locator, checked_match.0.entire().byte_span())
                        .map_err(WorkerError::Utf8)?;

                let candidate = Candidate {
                    source: path.to_path_buf(),
                    rule_match: RuleMatch {
                        rule_id: rule_id.clone(),
                        matched,
                        captures,
                    },
                };
                candidates.push(candidate);
            }
        }
        Ok(candidates)
    }
}
