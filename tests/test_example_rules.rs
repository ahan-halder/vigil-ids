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
