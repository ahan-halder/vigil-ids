pub mod matcher;

use crate::parser::ParsedPacket;
use crate::rules::{RuleCondition, RuleSet};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::SystemTime;

#[derive(Debug, Clone)]
pub struct DetectionEvent {
    pub rule_id: String,
    pub severity: String,
    pub action: String,
    pub timestamp_secs: Option<u64>,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub message: String,
}

#[derive(Debug, Default)]
pub struct DetectionEngine {
    rules: RuleSet,
    state: EngineState,
    synthetic_time_secs: u64,
    rules_path: Option<PathBuf>,
    rules_last_modified: Option<SystemTime>,
}

#[derive(Debug, Default)]
struct EngineState {
    port_scan_ports_by_source: HashMap<String, Vec<(u64, u16)>>,
}

impl DetectionEngine {
    pub fn with_rules(rules: RuleSet, rules_path: Option<PathBuf>) -> Self {
        let rules_last_modified = rules_path
            .as_ref()
            .and_then(|p| std::fs::metadata(p).ok()?.modified().ok());

        Self {
            rules,
            state: EngineState::default(),
            synthetic_time_secs: 0,
            rules_path,
            rules_last_modified,
        }
    }

    pub fn check_and_reload_rules(&mut self) {
        let Some(path) = &self.rules_path else { return };

        if let Ok(metadata) = std::fs::metadata(path) {
            if let Ok(modified) = metadata.modified() {
                let should_reload = match self.rules_last_modified {
                    Some(last) => modified > last,
                    None => true,
                };

                if should_reload {
                    match crate::rules::RuleSet::load_from_path(path) {
                        Ok(new_rules) => {
                            eprintln!("Reloading rules from {}", path.display());
                            self.rules = new_rules;
                            self.rules_last_modified = Some(modified);
                        }
                        Err(e) => {
                            eprintln!("Failed to reload rules from {}: {e}", path.display());
                            // Update modified time so we don't spam errors every check
                            self.rules_last_modified = Some(modified);
                        }
                    }
                }
            }
        }
    }

    pub fn detect(&mut self, packet: &ParsedPacket) -> Vec<DetectionEvent> {
        let event_time_secs = packet.capture_time_secs.unwrap_or_else(|| {
            self.synthetic_time_secs = self.synthetic_time_secs.saturating_add(1);
            self.synthetic_time_secs
        });

        let rules = self.rules.rules.clone();

        let (stateful_rules, stateless_rules): (Vec<_>, Vec<_>) = rules
            .into_iter()
            .partition(|r| matches!(r.condition, RuleCondition::PortScan { .. }));

        use rayon::prelude::*;

        // Process stateless rules in parallel
        let mut detections: Vec<DetectionEvent> = stateless_rules
            .into_par_iter()
            .filter(|rule| matcher::matches(rule, packet))
            .map(|rule| DetectionEvent {
                rule_id: rule.id.clone(),
                severity: rule.severity.clone().unwrap_or_else(|| "low".to_string()),
                action: rule.action.clone().unwrap_or_else(|| "alert".to_string()),
                timestamp_secs: packet.capture_time_secs,
                src_ip: packet.source_ip.clone(),
                dst_ip: packet.destination_ip.clone(),
                message: if let Some(destination_ip) = packet.destination_ip.as_deref() {
                    format!(
                        "{}: {} matched for destination {destination_ip}",
                        rule.name, rule.description
                    )
                } else {
                    format!("{}: {}", rule.name, rule.description)
                },
            })
            .collect();

        // Process stateful rules sequentially
        for rule in stateful_rules {
            let matched = match &rule.condition {
                RuleCondition::PortScan {
                    threshold,
                    window_secs,
                } => self.is_port_scan(packet, event_time_secs, *threshold, *window_secs),
                _ => false,
            };

            if matched {
                detections.push(DetectionEvent {
                    rule_id: rule.id.clone(),
                    severity: rule.severity.clone().unwrap_or_else(|| "low".to_string()),
                    action: rule.action.clone().unwrap_or_else(|| "alert".to_string()),
                    timestamp_secs: packet.capture_time_secs,
                    src_ip: packet.source_ip.clone(),
                    dst_ip: packet.destination_ip.clone(),
                    message: if let Some(destination_ip) = packet.destination_ip.as_deref() {
                        format!(
                            "{}: {} matched for destination {destination_ip}",
                            rule.name, rule.description
                        )
                    } else {
                        format!("{}: {}", rule.name, rule.description)
                    },
                });
            }
        }

        detections
    }

    fn is_port_scan(
        &mut self,
        packet: &ParsedPacket,
        event_time_secs: u64,
        threshold: u32,
        window_secs: u64,
    ) -> bool {
        let Some(source_ip) = packet.source_ip.as_ref() else {
            return false;
        };
        let Some(destination_port) = packet.destination_port else {
            return false;
        };

        let history = self
            .state
            .port_scan_ports_by_source
            .entry(source_ip.clone())
            .or_default();

        history.push((event_time_secs, destination_port));

        let earliest_time = event_time_secs.saturating_sub(window_secs);
        history.retain(|(seen_at, _)| *seen_at >= earliest_time);

        let unique_ports: HashSet<u16> = history.iter().map(|(_, port)| *port).collect();
        unique_ports.len() as u32 >= threshold
    }
}
