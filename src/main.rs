mod alerts;
mod capture;
mod cli;
mod engine;
mod parser;
mod rules;

use clap::Parser;

fn main() {
    let cli = cli::Cli::parse();

    if cli.verbose {
        println!("Vigil IDS starting with configuration: {:?}", cli);
    } else {
        println!("Vigil IDS is starting up.");
    }

    let _capture_config = capture::CaptureConfig::from(&cli);
    let _engine = engine::DetectionEngine::new();
    let _rules = rules::RuleSet::default();
    let _alert = alerts::Alert::new("Vigil IDS boot sequence complete");

    if let Some(input) = cli.input_source() {
        println!("Selected input source: {input}");
    }
}