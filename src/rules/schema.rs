use serde::Deserialize;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub description: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct RuleFile {
    pub rules: Vec<Rule>,
}