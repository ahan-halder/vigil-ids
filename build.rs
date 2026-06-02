fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=VIGIL_ENABLE_PCAP_DISCOVERY");
    println!("cargo:rustc-check-cfg=cfg(has_libpcap)");

    if std::env::var_os("CARGO_FEATURE_PCAP").is_none()
        && std::env::var_os("VIGIL_ENABLE_PCAP_DISCOVERY").is_none()
    {
        println!("cargo:warning=libpcap discovery is optional; enable the `pcap` feature or set VIGIL_ENABLE_PCAP_DISCOVERY=1 when the toolchain is ready");
        return;
    }

    if try_pkg_config().or_else(try_vcpkg).is_some() {
        println!("cargo:rustc-cfg=has_libpcap");
    } else {
        println!("cargo:warning=libpcap was not found; continuing with a disabled pcap backend");
    }
}

fn try_pkg_config() -> Option<()> {
    pkg_config::Config::new().probe("libpcap").ok().map(|_| ())
}

fn try_vcpkg() -> Option<()> {
    vcpkg::Config::new().probe("pcap").ok().map(|_| ())
}