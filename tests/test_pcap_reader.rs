use std::path::Path;

use vigil_ids::capture;
use vigil_ids::capture::pcap_file;
use vigil_ids::engine::DetectionEngine;
use vigil_ids::parser;
use vigil_ids::rules::schema::RuleFile;
use vigil_ids::rules::RuleSet;

#[test]
fn reads_sample_pcap_and_parses_tcp_headers() {
    let packets = pcap_file::read_pcap_file(Path::new("tests/pcap_samples/minimal_tcp.pcap"))
        .expect("sample pcap should load");

    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].timestamp_secs, 1);

    let parsed = parser::parse_with_timestamp(&packets[0].data, packets[0].timestamp_secs);
    assert_eq!(parsed.source_ip.as_deref(), Some("192.168.1.100"));
    assert_eq!(parsed.destination_ip.as_deref(), Some("10.0.0.1"));
    assert_eq!(parsed.source_port, Some(12345));
    assert_eq!(parsed.destination_port, Some(80));
}

#[test]
fn port_scan_rule_uses_packet_history() {
    let rules_yaml = r#"
rules:
  - id: "PS-HISTORY"
    name: "Port Scan History"
    description: "Triggers only after multiple destination ports"
    severity: high
    action: alert
    condition:
      type: port_scan
      threshold: 3
      window_secs: 10
"#;

    let file: RuleFile = serde_yaml::from_str(rules_yaml).expect("rules YAML should parse");
    let rules = RuleSet { rules: file.rules };
    let mut engine = DetectionEngine::with_rules(rules, None);

    let first = parser::parse_with_timestamp(&tcp_packet_bytes(80), 100);
    let second = parser::parse_with_timestamp(&tcp_packet_bytes(443), 101);
    let third = parser::parse_with_timestamp(&tcp_packet_bytes(8080), 102);

    assert!(engine.detect(&first).is_empty());
    assert!(engine.detect(&second).is_empty());

    let detections = engine.detect(&third);
    assert_eq!(detections.len(), 1);
    assert_eq!(detections[0].rule_id, "PS-HISTORY");
}

#[test]
fn process_pcap_file_ingests_multiple_packets() {
    let rules_yaml = r#"
rules:
  - id: "PS-MULTI"
    name: "Port Scan Multi Packet"
    description: "Triggers after the third distinct destination port"
    severity: high
    action: alert
    condition:
      type: port_scan
      threshold: 3
      window_secs: 10
"#;

    let file: RuleFile = serde_yaml::from_str(rules_yaml).expect("rules YAML should parse");
    let rules = RuleSet { rules: file.rules };
    let mut engine = DetectionEngine::with_rules(rules, None);

    let detections = capture::process_pcap_file(
        Path::new("tests/pcap_samples/multi_packet_scan.pcap"),
        &mut engine,
    )
    .expect("pcap processing should succeed");

    assert_eq!(detections.len(), 1);
    assert_eq!(detections[0].rule_id, "PS-MULTI");
    assert_eq!(detections[0].timestamp_secs, Some(3));
}

fn tcp_packet_bytes(destination_port: u16) -> Vec<u8> {
    let mut bytes = vec![
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00, 0x45,
        0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x64,
        0x0a, 0x00, 0x00, 0x01, 0x30, 0x39, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x50, 0x02, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    ];

    let [high, low] = destination_port.to_be_bytes();
    bytes[36] = high;
    bytes[37] = low;
    bytes
}

fn ipv6_packet_bytes() -> Vec<u8> {
    vec![
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x86, 0xdd, 0x60,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    ]
}

#[test]
fn reads_ipv6_packet_and_parses_headers() {
    let parsed = parser::parse_with_timestamp(&ipv6_packet_bytes(), 100);
    assert_eq!(parsed.source_ip.as_deref(), Some("2001:db8::1"));
    assert_eq!(parsed.destination_ip.as_deref(), Some("2001:db8::2"));
    assert!(parsed.ipv6.is_some());
    assert_eq!(parsed.ipv6.unwrap().next_header, 17);
}

#[test]
fn protocol_anomaly_detects_land_attack() {
    let rules_yaml = r#"
rules:
  - id: "PA-LAND"
    name: "Land Attack"
    description: "Source and destination ports are identical"
    severity: medium
    action: alert
    condition:
      type: protocol_anomaly
"#;

    let file: RuleFile = serde_yaml::from_str(rules_yaml).expect("rules YAML should parse");
    let rules = RuleSet { rules: file.rules };
    let mut engine = DetectionEngine::with_rules(rules, None);

    // Land attack: src_port == dst_port (both 80)
    let land_packet = parser::parse_with_timestamp(&tcp_packet_bytes(12345), 100);
    let detections = engine.detect(&land_packet);
    assert_eq!(detections.len(), 1);
    assert_eq!(detections[0].rule_id, "PA-LAND");
}

#[test]
fn protocol_anomaly_ignores_normal_packet() {
    let rules_yaml = r#"
rules:
  - id: "PA-NORMAL"
    name: "Protocol Anomaly"
    description: "Should not trigger on normal traffic"
    severity: medium
    action: alert
    condition:
      type: protocol_anomaly
"#;

    let file: RuleFile = serde_yaml::from_str(rules_yaml).expect("rules YAML should parse");
    let rules = RuleSet { rules: file.rules };
    let mut engine = DetectionEngine::with_rules(rules, None);

    // Normal packet: src_port 12345, dst_port 80 — different ports, no anomaly
    let normal_packet = parser::parse_with_timestamp(&tcp_packet_bytes(80), 100);
    let detections = engine.detect(&normal_packet);
    assert!(detections.is_empty());
}

#[test]
fn blocklist_rule_matches_blocked_source_ip() {
    let rules_yaml = r#"
rules:
  - id: "BL-TEST"
    name: "Blocklist"
    description: "Traffic from blocklisted IP"
    severity: critical
    action: alert
    condition:
      type: ip_blocklist
      src_ips:
        - "192.168.1.100"
"#;

    let file: RuleFile = serde_yaml::from_str(rules_yaml).expect("rules YAML should parse");
    let rules = RuleSet { rules: file.rules };
    let mut engine = DetectionEngine::with_rules(rules, None);

    // tcp_packet_bytes has src IP 192.168.1.100 — should match
    let packet = parser::parse_with_timestamp(&tcp_packet_bytes(80), 100);
    let detections = engine.detect(&packet);
    assert_eq!(detections.len(), 1);
    assert_eq!(detections[0].rule_id, "BL-TEST");
}

#[test]
fn blocklist_rule_ignores_unblocked_source_ip() {
    let rules_yaml = r#"
rules:
  - id: "BL-MISS"
    name: "Blocklist"
    description: "Should not match unknown IPs"
    severity: critical
    action: alert
    condition:
      type: ip_blocklist
      src_ips:
        - "10.10.10.10"
"#;

    let file: RuleFile = serde_yaml::from_str(rules_yaml).expect("rules YAML should parse");
    let rules = RuleSet { rules: file.rules };
    let mut engine = DetectionEngine::with_rules(rules, None);

    // tcp_packet_bytes has src IP 192.168.1.100, not in blocklist
    let packet = parser::parse_with_timestamp(&tcp_packet_bytes(80), 100);
    let detections = engine.detect(&packet);
    assert!(detections.is_empty());
}
