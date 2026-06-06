use crate::parser::ParsedPacket;
use crate::rules::{matches_condition, Rule};

pub fn matches(rule: &Rule, packet: &ParsedPacket) -> bool {
    match rule.condition {
        crate::rules::RuleCondition::PortScan { .. } => false,
        _ => matches_condition(&rule.condition, packet),
    }
}
