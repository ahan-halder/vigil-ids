pub mod schema;

use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    pub rules: Vec<schema::Rule>,
}

impl RuleSet {
    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self, String> {
        let contents = fs::read_to_string(path.as_ref())
            .map_err(|error| format!("failed to read rules file {}: {error}", path.as_ref().display()))?;

        let file: schema::RuleFile = serde_yaml::from_str(&contents)
            .map_err(|error| format!("failed to parse YAML rules in {}: {error}", path.as_ref().display()))?;

        Ok(Self { rules: file.rules })
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}