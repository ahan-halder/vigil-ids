use crate::parser::ParsedPacket;
use crate::rules::{matches_condition, Rule};

pub fn matches(rule: &Rule, packet: &ParsedPacket) -> bool {
    matches_condition(&rule.condition, packet)
}