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
    engine: &mut DetectionEngine,
) -> Result<Vec<DetectionEvent>, String> {
    let packets = pcap_file::read_pcap_file(path)?;
    let mut detections = Vec::new();

    for packet in packets {
        let parsed = parser::parse_with_timestamp(&packet.data, packet.timestamp_secs);
        let _summary = parsed.summary();
        detections.extend(engine.detect(&parsed));
    }

    Ok(detections)
}

pub fn process_live_interface(
    interface: &str,
    engine: &mut DetectionEngine,
) -> Result<Vec<DetectionEvent>, String> {
    let packets = pcap_ffi::capture_live(interface, 64)?;
    let mut detections = Vec::new();

    for packet in packets {
        let parsed = parser::parse_with_timestamp(&packet.data, packet.timestamp_secs);
        detections.extend(engine.detect(&parsed));
    }

    Ok(detections)
}

pub fn list_interfaces() -> Result<Vec<String>, String> {
    pcap_ffi::list_interfaces()
}