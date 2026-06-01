use crate::parser::ParsedPacket;
use crate::rules::RuleSet;

pub fn matches(_packet: &ParsedPacket, _rules: &RuleSet) -> bool {
    false
}