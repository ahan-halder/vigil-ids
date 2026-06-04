pub mod matcher;

use crate::parser::ParsedPacket;
use crate::rules::{RuleCondition, RuleSet};
use std::collections::{HashMap, HashSet};

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
}

#[derive(Debug, Default)]
struct EngineState {
    port_scan_ports_by_source: HashMap<String, Vec<(u64, u16)>>,
}

impl DetectionEngine {
    pub fn with_rules(rules: RuleSet) -> Self {
        Self {
            rules,
            state: EngineState::default(),
            synthetic_time_secs: 0,
        }
    }

    pub fn detect(&mut self, packet: &ParsedPacket) -> Vec<DetectionEvent> {
        let event_time_secs = packet.capture_time_secs.unwrap_or_else(|| {
            self.synthetic_time_secs = self.synthetic_time_secs.saturating_add(1);
            self.synthetic_time_secs
        });

        let rules = self.rules.rules.clone();

        rules
            .iter()
            .filter(|rule| match &rule.condition {
                RuleCondition::PortScan {
                    threshold,
                    window_secs,
                } => self.is_port_scan(packet, event_time_secs, *threshold, *window_secs),
                _ => matcher::matches(rule, packet),
            })
            .map(|rule| DetectionEvent {
                rule_id: rule.id.clone(),
                severity: rule.severity.clone().unwrap_or_else(|| "low".to_string()),
                action: rule.action.clone().unwrap_or_else(|| "alert".to_string()),
                timestamp_secs: packet.capture_time_secs,
                src_ip: packet.source_ip.clone(),
                dst_ip: packet.destination_ip.clone(),
                message: if let Some(destination_ip) = packet.destination_ip.as_deref() {
                    format!("{}: {} matched for destination {destination_ip}", rule.name, rule.description)
                } else {
                    format!("{}: {}", rule.name, rule.description)
                },
            })
            .collect()
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