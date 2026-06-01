pub fn backend_name() -> &'static str {
    if cfg!(feature = "pcap") {
        "libpcap"
    } else {
        "disabled"
    }
}