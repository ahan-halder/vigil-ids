pub mod pcap_ffi;
pub mod pcap_file;

use crate::cli::Cli;
use crate::engine::{DetectionEngine, DetectionEvent};
use crate::parser;
use std::path::Path;

#[derive(Debug, Clone, Default)]
pub struct CaptureConfig {
    pub interface: Option<String>,
    pub pcap: Option<String>,
}

impl CaptureConfig {
    pub fn from(cli: &Cli) -> Self {
        Self {
            interface: cli.interface.clone(),
            pcap: cli.pcap.clone(),
        }
    }

    pub fn source_label(&self) -> &'static str {
        if self.interface.is_some() {
            "interface"
        } else if self.pcap.is_some() {
            "pcap"
        } else {
            "none"
        }
    }
}

pub fn process_pcap_file(
    path: impl AsRef<Path>,
    engine: &DetectionEngine,
) -> Result<Vec<DetectionEvent>, String> {
    let packets = pcap_file::read_pcap_file(path)?;
    let mut detections = Vec::new();

    for bytes in packets {
        let parsed = parser::parse(&bytes);
        let _summary = parsed.summary();
        detections.extend(engine.detect(&parsed));
    }

    Ok(detections)
}