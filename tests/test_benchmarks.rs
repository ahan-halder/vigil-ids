use std::time::Instant;
use vigil_ids::engine::DetectionEngine;
use vigil_ids::parser;
use vigil_ids::rules::schema::RuleFile;
use vigil_ids::rules::RuleSet;

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

#[test]
fn benchmark_packet_parsing() {
    let raw_packet = tcp_packet_bytes(80);
    let num_packets = if cfg!(debug_assertions) {
        10_000
    } else {
        500_000
    };
    let start = Instant::now();
    for i in 0..num_packets {
        let _ = parser::parse_with_timestamp(&raw_packet, i);
    }
    let elapsed = start.elapsed();
    let pps = num_packets as f64 / elapsed.as_secs_f64();
    println!(
        "Packet Parsing Throughput: {:.2} packets/sec ({:?} for {} packets)",
        pps, elapsed, num_packets
    );
}

#[test]
fn benchmark_detection_engine() {
    let rules_yaml = r#"
rules:
  - id: "BL-001"
    name: "Blocked IP"
    description: "Traffic from a known malicious IP"
    severity: critical
    action: alert
    condition:
      type: ip_blocklist
      src_ips:
        - "192.168.1.100"
        - "10.0.0.55"
  - id: "PS-001"
    name: "Port Scan Detected"
    description: "Multiple destination ports contacted in a short window"
    severity: high
    action: alert
    condition:
      type: port_scan
      threshold: 15
      window_secs: 10
  - id: "PA-001"
    name: "Protocol Anomaly"
    description: "Suspicious packet structure detected"
    severity: medium
    action: alert
    condition:
      type: protocol_anomaly
"#;
    let file: RuleFile = serde_yaml::from_str(rules_yaml).expect("rules YAML should parse");
    let rules = RuleSet { rules: file.rules };
    let mut engine = DetectionEngine::with_rules(rules, None);
    let raw_packet = tcp_packet_bytes(80);
    let mut parsed = parser::parse_with_timestamp(&raw_packet, 100);
    parsed.capture_time_secs = None; // Let synthetic time advance so sliding window expires old history

    let num_packets = if cfg!(debug_assertions) {
        5_000
    } else {
        100_000
    };
    let start = Instant::now();
    let mut alerts = 0;
    for _ in 0..num_packets {
        let events = engine.detect(&parsed);
        alerts += events.len();
    }
    let elapsed = start.elapsed();
    let pps = num_packets as f64 / elapsed.as_secs_f64();
    println!(
        "Detection Engine Throughput (3 rules): {:.2} packets/sec ({:?} for {} packets, {} alerts generated)",
        pps, elapsed, num_packets, alerts
    );
}
