#[derive(Debug, Clone, Default)]
pub struct ParsedPacket {
    pub bytes: Vec<u8>,
    pub source_ip: Option<String>,
    pub destination_ip: Option<String>,
    pub destination_ports: Vec<u16>,
}

impl ParsedPacket {
    pub fn len(&self) -> usize {
        self.bytes.len()
    }
}

pub fn parse(bytes: &[u8]) -> ParsedPacket {
    ParsedPacket {
        bytes: bytes.to_vec(),
        source_ip: None,
        destination_ip: None,
        destination_ports: Vec::new(),
    }
}