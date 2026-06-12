use vigil_ids::rules::RuleSet;

#[test]
fn loads_example_port_scan_rules() {
    let rules = RuleSet::load_from_path("rules/examples/port_scan.yaml")
        .expect("port scan example rules should load");

    assert_eq!(rules.len(), 1);
    assert_eq!(rules.rules[0].id, "PS-001");
}

#[test]
fn loads_example_blocklist_rules() {
    let rules = RuleSet::load_from_path("rules/examples/blocklist.yaml")
        .expect("blocklist example rules should load");

    assert_eq!(rules.len(), 1);
    assert_eq!(rules.rules[0].id, "BL-001");
}

#[test]
fn loads_example_protocol_anomaly_rules() {
    let rules = RuleSet::load_from_path("rules/examples/protocol_anomaly.yaml")
        .expect("protocol anomaly example rules should load");

    assert_eq!(rules.len(), 1);
    assert_eq!(rules.rules[0].id, "PA-001");
}

#[test]
fn loads_default_rules_with_all_types() {
    let rules = RuleSet::load_from_path("rules/default.yaml").expect("default rules should load");

    assert_eq!(rules.len(), 3);
    let ids: Vec<&str> = rules.rules.iter().map(|r| r.id.as_str()).collect();
    assert!(ids.contains(&"BL-001"));
    assert!(ids.contains(&"PS-001"));
    assert!(ids.contains(&"PA-001"));
}
