use serde::Deserialize;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub condition: RuleCondition,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RuleCondition {
    #[default]
    MatchAll,
    IpBlocklist {
        #[serde(default)]
        src_ips: Vec<String>,
    },
    PortScan {
        #[serde(default = "default_port_scan_threshold")]
        threshold: u32,
        #[serde(default = "default_port_scan_window_secs")]
        window_secs: u64,
    },
}

fn default_port_scan_threshold() -> u32 {
    15
}

fn default_port_scan_window_secs() -> u64 {
    10
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct RuleFile {
    pub rules: Vec<Rule>,
}