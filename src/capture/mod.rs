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

    pub fn selected_source(&self) -> Option<&str> {
        self.interface
            .as_deref()
            .or(self.pcap.as_deref())
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