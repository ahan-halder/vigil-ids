mod alerts;
mod capture;
mod cli;
mod engine;
mod parser;
mod rules;

use clap::Parser;
use std::path::PathBuf;

fn main() {
    let cli = cli::Cli::parse();
    let capture_config = capture::CaptureConfig::from(&cli);
    let rules_path = cli
        .rules
        .as_deref()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("rules/default.yaml"));

    if cli.verbose {
        println!("Vigil IDS starting with configuration: {:?}", cli);
    } else {
        println!("Vigil IDS is starting up.");
    }

    let loaded_rules = match rules::RuleSet::load_from_path(&rules_path) {
        Ok(rules) => rules,
        Err(error) => {
            eprintln!("{error}");
            return;
        }
    };

    let packet = parser::parse(&[]);
    let engine = engine::DetectionEngine::with_rules(loaded_rules.clone());
    let backend = capture::pcap_ffi::backend_name();
    let alert = alerts::Alert::new(format!("Vigil IDS boot sequence complete via {backend}"));

    if loaded_rules.is_empty() {
        println!("Loaded rules file is empty");
    }

    match cli.input_source() {
        Some(input) => {
            println!("Selected {} input: {input}", capture_config.source_label());
            println!("Loaded {} rules from {}", loaded_rules.len(), rules_path.display());
            println!("Parsed packet bytes: {}", packet.len());
            let detections = engine.detect(&packet);
            println!("Backend: {backend}");
            println!("Engine ready: {:?}", engine);
            println!("Alert template: {}", alert.message);
            println!("Detections emitted: {}", detections.len());
            for detection in detections {
                println!(
                    "Detection: rule={} severity={} action={} message={}",
                    detection.rule_id, detection.severity, detection.action, detection.message
                );
            }
        }
        None => {
            println!("No capture source selected; use --interface or --pcap");
            println!("Loaded {} rules from {}", loaded_rules.len(), rules_path.display());
            println!("Backend: {backend}");
            println!("Alert template: {}", alert.message);
        }
    }
}