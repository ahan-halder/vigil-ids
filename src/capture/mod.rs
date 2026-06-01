pub mod pcap_ffi;

use crate::cli::Cli;

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
}