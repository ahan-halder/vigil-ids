pub mod schema;

#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    pub rules: Vec<schema::Rule>,
}