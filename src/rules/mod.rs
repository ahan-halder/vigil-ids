pub mod schema;

use std::fs;
use std::path::Path;

pub use schema::{Rule, RuleCondition};

#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
}

impl RuleSet {
    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self, String> {
        let contents = fs::read_to_string(path.as_ref()).map_err(|error| {
            format!(
                "failed to read rules file {}: {error}",
                path.as_ref().display()
            )
        })?;

        let file: schema::RuleFile = serde_yaml::from_str(&contents).map_err(|error| {
            format!(
                "failed to parse YAML rules in {}: {error}",
                path.as_ref().display()
            )
        })?;

        Ok(Self { rules: file.rules })
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Rule> {
        self.rules.iter()
    }
}

pub fn matches_condition(condition: &RuleCondition, packet: &crate::parser::ParsedPacket) -> bool {
    match condition {
        RuleCondition::MatchAll => true,
        RuleCondition::IpBlocklist { src_ips } => packet
            .source_ip
            .as_deref()
            .is_some_and(|source_ip| src_ips.iter().any(|blocked_ip| blocked_ip == source_ip)),
        RuleCondition::PortScan { .. } => false,
    }
}
