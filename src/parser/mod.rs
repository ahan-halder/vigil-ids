#[derive(Debug, Clone, Copy, Default)]
pub struct EthernetHeader {
    pub source_mac: [u8; 6],
    pub destination_mac: [u8; 6],
    pub ethertype: u16,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Ipv4Header {
    pub source_ip: [u8; 4],
    pub destination_ip: [u8; 4],
    pub protocol: u8,
    pub header_len: usize,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TcpHeader {
    pub source_port: u16,
    pub destination_port: u16,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct UdpHeader {
    pub source_port: u16,
    pub destination_port: u16,
}

#[derive(Debug, Clone, Copy)]
pub enum TransportHeader {
    Tcp(TcpHeader),
    Udp(UdpHeader),
}

#[derive(Debug, Clone, Default)]
pub struct ParsedPacket {
    pub bytes: Vec<u8>,
    pub ethernet: Option<EthernetHeader>,
    pub ipv4: Option<Ipv4Header>,
    pub transport: Option<TransportHeader>,
    pub source_ip: Option<String>,
    pub destination_ip: Option<String>,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub destination_ports: Vec<u16>,
}

impl ParsedPacket {
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn summary(&self) -> String {
        let mut parts = Vec::new();

        if let Some(ethernet) = self.ethernet.as_ref() {
            parts.push(format!(
                "eth {} -> {} type=0x{:04x}",
                format_mac(&ethernet.source_mac),
                format_mac(&ethernet.destination_mac),
                ethernet.ethertype
            ));
        }

        if let Some(ipv4) = self.ipv4.as_ref() {
            parts.push(format!(
                "ipv4 {} -> {} proto={} ihl={}",
                format_ipv4(&ipv4.source_ip),
                format_ipv4(&ipv4.destination_ip),
                ipv4.protocol,
                ipv4.header_len
            ));
        }

        if let Some(transport) = self.transport.as_ref() {
            match transport {
                TransportHeader::Tcp(tcp) => {
                    parts.push(format!("tcp {} -> {}", tcp.source_port, tcp.destination_port));
                }
                TransportHeader::Udp(udp) => {
                    parts.push(format!("udp {} -> {}", udp.source_port, udp.destination_port));
                }
            }
        }

        if parts.is_empty() {
            "unparsed packet".to_string()
        } else {
            parts.join(" | ")
        }
    }
}

pub fn parse(bytes: &[u8]) -> ParsedPacket {
    let ethernet = parse_ethernet(bytes);
    let mut parsed = ParsedPacket {
        bytes: bytes.to_vec(),
        ethernet,
        ipv4: None,
        transport: None,
        source_ip: None,
        destination_ip: None,
        source_port: None,
        destination_port: None,
        destination_ports: Vec::new(),
    };

    let Some(ethernet) = ethernet else {
        return parsed;
    };

    if ethernet.ethertype != 0x0800 {
        return parsed;
    }

    let ip_offset = 14;
    let Some((ipv4, transport_offset)) = parse_ipv4(bytes, ip_offset) else {
        return parsed;
    };

    parsed.source_ip = Some(format_ipv4(&ipv4.source_ip));
    parsed.destination_ip = Some(format_ipv4(&ipv4.destination_ip));
    parsed.ipv4 = Some(ipv4);

    match ipv4.protocol {
        6 => {
            if let Some(tcp) = parse_tcp(bytes, transport_offset) {
                parsed.source_port = Some(tcp.source_port);
                parsed.destination_port = Some(tcp.destination_port);
                parsed.destination_ports.push(tcp.destination_port);
                parsed.transport = Some(TransportHeader::Tcp(tcp));
            }
        }
        17 => {
            if let Some(udp) = parse_udp(bytes, transport_offset) {
                parsed.source_port = Some(udp.source_port);
                parsed.destination_port = Some(udp.destination_port);
                parsed.destination_ports.push(udp.destination_port);
                parsed.transport = Some(TransportHeader::Udp(udp));
            }
        }
        _ => {}
    }

    parsed
}

fn parse_ethernet(bytes: &[u8]) -> Option<EthernetHeader> {
    if bytes.len() < 14 {
        return None;
    }

    Some(EthernetHeader {
        destination_mac: [bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]],
        source_mac: [bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11]],
        ethertype: u16::from_be_bytes([bytes[12], bytes[13]]),
    })
}

fn parse_ipv4(bytes: &[u8], offset: usize) -> Option<(Ipv4Header, usize)> {
    if bytes.len() < offset + 20 {
        return None;
    }

    let version = bytes[offset] >> 4;
    if version != 4 {
        return None;
    }

    let header_len = ((bytes[offset] & 0x0f) as usize) * 4;
    if header_len < 20 || bytes.len() < offset + header_len {
        return None;
    }

    let ipv4 = Ipv4Header {
        source_ip: [bytes[offset + 12], bytes[offset + 13], bytes[offset + 14], bytes[offset + 15]],
        destination_ip: [bytes[offset + 16], bytes[offset + 17], bytes[offset + 18], bytes[offset + 19]],
        protocol: bytes[offset + 9],
        header_len,
    };

    Some((ipv4, offset + header_len))
}

fn parse_tcp(bytes: &[u8], offset: usize) -> Option<TcpHeader> {
    if bytes.len() < offset + 20 {
        return None;
    }

    Some(TcpHeader {
        source_port: u16::from_be_bytes([bytes[offset], bytes[offset + 1]]),
        destination_port: u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]),
    })
}

fn parse_udp(bytes: &[u8], offset: usize) -> Option<UdpHeader> {
    if bytes.len() < offset + 8 {
        return None;
    }

    Some(UdpHeader {
        source_port: u16::from_be_bytes([bytes[offset], bytes[offset + 1]]),
        destination_port: u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]),
    })
}

fn format_ipv4(bytes: &[u8; 4]) -> String {
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

fn format_mac(bytes: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}