pub mod matcher;

use crate::parser::ParsedPacket;
use crate::rules::RuleSet;

#[derive(Debug, Clone)]
pub struct DetectionEvent {
    pub rule_id: String,
    pub severity: String,
    pub action: String,
    pub message: String,
}

#[derive(Debug, Default)]
pub struct DetectionEngine {
    rules: RuleSet,
}

impl DetectionEngine {
    pub fn with_rules(rules: RuleSet) -> Self {
        Self { rules }
    }

    pub fn detect(&self, packet: &ParsedPacket) -> Vec<DetectionEvent> {
        self.rules
            .iter()
            .filter(|rule| matcher::matches(rule, packet))
            .map(|rule| DetectionEvent {
                rule_id: rule.id.clone(),
                severity: rule.severity.clone().unwrap_or_else(|| "low".to_string()),
                action: rule.action.clone().unwrap_or_else(|| "alert".to_string()),
                message: if let Some(destination_ip) = packet.destination_ip.as_deref() {
                    format!("{}: {} matched for destination {destination_ip}", rule.name, rule.description)
                } else {
                    format!("{}: {}", rule.name, rule.description)
                },
            })
            .collect()
    }
}