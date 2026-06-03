use clap::Parser;
use std::path::PathBuf;
use vigil_ids::alerts;
use vigil_ids::capture;
use vigil_ids::cli::Cli;
use vigil_ids::engine;
use vigil_ids::rules;

fn main() {
    let cli = Cli::parse();
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

    let mut engine = engine::DetectionEngine::with_rules(loaded_rules.clone());
    let backend = capture::pcap_ffi::backend_name();
    let alert = alerts::Alert::new(format!("Vigil IDS boot sequence complete via {backend}"));

    if loaded_rules.is_empty() {
        println!("Loaded rules file is empty");
    }

    println!("Backend: {backend}");
    println!("Loaded {} rules from {}", loaded_rules.len(), rules_path.display());
    println!("Alert template: {}", alert.message);

    match cli.pcap.as_deref() {
        Some(pcap_path) => {
            println!("Selected {} input: {pcap_path}", capture_config.source_label());
            match capture::process_pcap_file(pcap_path, &mut engine) {
                Ok(detections) => {
                    println!("Detections emitted: {}", detections.len());
                    for detection in detections {
                        println!(
                            "Detection: rule={} severity={} action={} message={}",
                            detection.rule_id, detection.severity, detection.action, detection.message
                        );
                    }
                }
                Err(error) => {
                    eprintln!("{error}");
                }
            }
        }
        None => match cli.interface.as_deref() {
            Some(interface) => {
                match capture::process_live_interface(interface, &mut engine) {
                    Ok(detections) => {
                        println!("Detections emitted: {}", detections.len());
                        for detection in detections {
                            println!(
                                "Detection: rule={} severity={} action={} message={}",
                                detection.rule_id, detection.severity, detection.action, detection.message
                            );
                        }
                    }
                    Err(error) => {
                        eprintln!("{error}");
                    }
                }
            }
            None => {
                println!("No capture source selected; use --interface or --pcap");
            }
        },
    }
}