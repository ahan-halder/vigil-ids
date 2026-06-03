#[derive(Debug, Clone)]
pub struct CapturedPacket {
    pub timestamp_secs: u64,
    pub data: Vec<u8>,
}

pub fn backend_name() -> &'static str {
    if cfg!(has_libpcap) {
        "libpcap"
    } else {
        "disabled"
    }
}

#[cfg(has_libpcap)]
pub fn capture_live(interface: &str, max_packets: usize) -> Result<Vec<CapturedPacket>, String> {
    use std::ffi::{CStr, CString};
    use std::os::raw::{c_char, c_int, c_long, c_uchar};

    #[repr(C)]
    struct TimeVal {
        tv_sec: c_long,
        tv_usec: c_long,
    }

    #[repr(C)]
    struct PcapPkthdr {
        ts: TimeVal,
        caplen: u32,
        len: u32,
    }

    #[repr(C)]
    struct PcapHandle {
        _private: [u8; 0],
    }

    #[cfg(target_os = "windows")]
    #[link(name = "wpcap")]
    unsafe extern "C" {
        fn pcap_open_live(
            device: *const c_char,
            snaplen: c_int,
            promisc: c_int,
            to_ms: c_int,
            errbuf: *mut c_char,
        ) -> *mut PcapHandle;
        fn pcap_next_ex(
            p: *mut PcapHandle,
            pkt_header: *mut *const PcapPkthdr,
            pkt_data: *mut *const c_uchar,
        ) -> c_int;
        fn pcap_close(p: *mut PcapHandle);
        fn pcap_geterr(p: *mut PcapHandle) -> *const c_char;
    }

    #[cfg(not(target_os = "windows"))]
    unsafe extern "C" {
        fn pcap_open_live(
            device: *const c_char,
            snaplen: c_int,
            promisc: c_int,
            to_ms: c_int,
            errbuf: *mut c_char,
        ) -> *mut PcapHandle;
        fn pcap_next_ex(
            p: *mut PcapHandle,
            pkt_header: *mut *const PcapPkthdr,
            pkt_data: *mut *const c_uchar,
        ) -> c_int;
        fn pcap_close(p: *mut PcapHandle);
        fn pcap_geterr(p: *mut PcapHandle) -> *const c_char;
    }

    let mut errbuf = [0i8; 256];
    let interface_cstr = CString::new(interface)
        .map_err(|_| "interface contains an interior null byte".to_string())?;

    let handle = unsafe {
        pcap_open_live(
            interface_cstr.as_ptr(),
            65535,
            1,
            1000,
            errbuf.as_mut_ptr(),
        )
    };

    if handle.is_null() {
        let error_message = unsafe {
            CStr::from_ptr(errbuf.as_ptr())
                .to_string_lossy()
                .trim()
                .to_string()
        };
        return Err(format!("failed to open live interface {interface}: {error_message}"));
    }

    let mut packets = Vec::new();
    let mut idle_timeouts = 0u32;

    while packets.len() < max_packets {
        let mut header_ptr: *const PcapPkthdr = std::ptr::null();
        let mut data_ptr: *const c_uchar = std::ptr::null();

        let result = unsafe { pcap_next_ex(handle, &mut header_ptr, &mut data_ptr) };
        match result {
            1 => {
                idle_timeouts = 0;
                if header_ptr.is_null() || data_ptr.is_null() {
                    continue;
                }
                let header = unsafe { &*header_ptr };
                let packet = unsafe {
                    std::slice::from_raw_parts(data_ptr, header.caplen as usize).to_vec()
                };
                packets.push(CapturedPacket {
                    timestamp_secs: header.ts.tv_sec.max(0) as u64,
                    data: packet,
                });
            }
            0 => {
                idle_timeouts = idle_timeouts.saturating_add(1);
                if idle_timeouts >= 3 {
                    break;
                }
            }
            -1 => {
                let error_ptr = unsafe { pcap_geterr(handle) };
                let error_message = if error_ptr.is_null() {
                    "unknown libpcap error".to_string()
                } else {
                    unsafe { CStr::from_ptr(error_ptr).to_string_lossy().to_string() }
                };
                unsafe { pcap_close(handle) };
                return Err(format!("libpcap capture error: {error_message}"));
            }
            -2 => break,
            _ => break,
        }
    }

    unsafe { pcap_close(handle) };
    Ok(packets)
}

#[cfg(not(has_libpcap))]
pub fn capture_live(_interface: &str, _max_packets: usize) -> Result<Vec<CapturedPacket>, String> {
    Err("live capture requires libpcap discovery (`--features pcap` or VIGIL_ENABLE_PCAP_DISCOVERY=1)".to_string())
}