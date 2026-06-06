use std::fs;
use std::path::Path;

const PCAP_GLOBAL_HEADER_LEN: usize = 24;
const PCAP_PACKET_HEADER_LEN: usize = 16;

#[derive(Debug, Clone, Copy)]
enum Endianness {
    Little,
    Big,
}

#[derive(Debug, Clone)]
pub struct CapturedPacket {
    pub timestamp_secs: u64,
    pub data: Vec<u8>,
}

pub fn read_pcap_file(path: impl AsRef<Path>) -> Result<Vec<CapturedPacket>, String> {
    let bytes = fs::read(path.as_ref()).map_err(|error| {
        format!(
            "failed to read pcap file {}: {error}",
            path.as_ref().display()
        )
    })?;

    let mut reader = PcapReader::new(&bytes)?;
    let mut packets = Vec::new();

    while let Some(packet) = reader.next_packet()? {
        packets.push(packet);
    }

    Ok(packets)
}

struct PcapReader<'a> {
    bytes: &'a [u8],
    offset: usize,
    endianness: Endianness,
}

impl<'a> PcapReader<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self, String> {
        if bytes.len() < PCAP_GLOBAL_HEADER_LEN {
            return Err("pcap file is too small to contain a global header".to_string());
        }

        let endianness = match [bytes[0], bytes[1], bytes[2], bytes[3]] {
            [0xd4, 0xc3, 0xb2, 0xa1] | [0x4d, 0x3c, 0xb2, 0xa1] => Endianness::Little,
            [0xa1, 0xb2, 0xc3, 0xd4] | [0xa1, 0xb2, 0x3c, 0x4d] => Endianness::Big,
            _ => return Err("unsupported pcap magic number".to_string()),
        };

        Ok(Self {
            bytes,
            offset: PCAP_GLOBAL_HEADER_LEN,
            endianness,
        })
    }

    fn next_packet(&mut self) -> Result<Option<CapturedPacket>, String> {
        if self.offset >= self.bytes.len() {
            return Ok(None);
        }

        if self.bytes.len() - self.offset < PCAP_PACKET_HEADER_LEN {
            return Err("truncated pcap packet header".to_string());
        }

        let header = &self.bytes[self.offset..self.offset + PCAP_PACKET_HEADER_LEN];
        let ts_sec = self.read_u32(&header[0..4]) as u64;
        let incl_len = self.read_u32(&header[8..12]) as usize;
        self.offset += PCAP_PACKET_HEADER_LEN;

        if self.bytes.len() - self.offset < incl_len {
            return Err("truncated pcap packet data".to_string());
        }

        let packet_data = self.bytes[self.offset..self.offset + incl_len].to_vec();
        self.offset += incl_len;
        Ok(Some(CapturedPacket {
            timestamp_secs: ts_sec,
            data: packet_data,
        }))
    }

    fn read_u32(&self, bytes: &[u8]) -> u32 {
        match self.endianness {
            Endianness::Little => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            Endianness::Big => u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        }
    }
}
