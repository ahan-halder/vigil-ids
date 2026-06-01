#[derive(Debug, Clone, Default)]
pub struct ParsedPacket {
    pub bytes: Vec<u8>,
}

impl ParsedPacket {
    pub fn len(&self) -> usize {
        self.bytes.len()
    }
}

pub fn parse(bytes: &[u8]) -> ParsedPacket {
    ParsedPacket {
        bytes: bytes.to_vec(),
    }
}