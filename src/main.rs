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
    let engine = engine::DetectionEngine::new();
    let alert = alerts::Alert::new("Vigil IDS boot sequence complete");

    match capture_config.selected_source() {
        Some(input) => {
            println!("Selected {} input: {input}", capture_config.source_label());
            println!("Loaded {} rules from {}", loaded_rules.len(), rules_path.display());
            println!("Parsed packet bytes: {}", packet.len());
            println!("Engine ready: {:?}", engine);
            println!("Alert template: {:?}", alert);
        }
        None => {
            println!("No capture source selected; use --interface or --pcap");
            println!("Loaded {} rules from {}", loaded_rules.len(), rules_path.display());
        }
    }
}