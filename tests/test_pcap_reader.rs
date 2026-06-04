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
    let mut engine = DetectionEngine::with_rules(rules);

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
    let mut engine = DetectionEngine::with_rules(rules);

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
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00,
        0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 0xc0, 0xa8,
        0x01, 0x64, 0x0a, 0x00, 0x00, 0x01, 0x30, 0x39, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    ];

    let [high, low] = destination_port.to_be_bytes();
    bytes[36] = high;
    bytes[37] = low;
    bytes
}
