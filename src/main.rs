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
        eprintln!("Vigil IDS starting with configuration: {:?}", cli);
    } else {
        eprintln!("Vigil IDS is starting up.");
    }

    let loaded_rules = match rules::RuleSet::load_from_path(&rules_path) {
        Ok(rules) => rules,
        Err(error) => {
            eprintln!("{error}");
            return;
        }
    };

    let mut engine = engine::DetectionEngine::with_rules(loaded_rules.clone(), Some(rules_path.clone()));
    let backend = capture::pcap_ffi::backend_name();
    let alert = alerts::Alert::new(format!("Vigil IDS boot sequence complete via {backend}"));

    if loaded_rules.is_empty() {
        eprintln!("Loaded rules file is empty");
    }

    eprintln!("Backend: {backend}");
    eprintln!(
        "Loaded {} rules from {}",
        loaded_rules.len(),
        rules_path.display()
    );
    eprintln!("Alert template: {}", alert.message);

    let syslog_sender = match cli.syslog.as_deref() {
        Some(target) => {
            eprintln!("Syslog output enabled: target={target}");
            match alerts::syslog::SyslogSender::new(target) {
                Ok(sender) => Some(sender),
                Err(e) => {
                    eprintln!("Failed to initialize syslog: {e}");
                    None
                }
            }
        }
        None => None,
    };

    if cli.list_interfaces {
        match capture::list_interfaces() {
            Ok(interfaces) => {
                for interface in interfaces {
                    println!("{interface}");
                }
            }
            Err(error) => eprintln!("{error}"),
        }
        return;
    }

    match cli.pcap.as_deref() {
        Some(pcap_path) => {
            eprintln!(
                "Selected {} input: {pcap_path}",
                capture_config.source_label()
            );
            match capture::process_pcap_file(pcap_path, &mut engine) {
                Ok(detections) => {
                    if let Err(error) = alerts::emit_json_alerts(&detections, cli.output.as_deref(), syslog_sender.as_ref())
                    {
                        eprintln!("{error}");
                    }
                }
                Err(error) => {
                    eprintln!("{error}");
                }
            }
        }
        None => match cli.interface.as_deref() {
            Some(interface) => loop {
                match capture::process_live_interface(interface, &mut engine) {
                    Ok(detections) => {
                        if !detections.is_empty() {
                            if let Err(error) = alerts::emit_json_alerts(&detections, cli.output.as_deref(), syslog_sender.as_ref())
                            {
                                eprintln!("{error}");
                            }
                        }
                    }
                    Err(error) => {
                        eprintln!("{error}");
                        break;
                    }
                }
            },
            None => {
                eprintln!("No capture source selected; use --interface or --pcap");
            }
        },
    }
}
