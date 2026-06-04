fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=VIGIL_ENABLE_PCAP_DISCOVERY");
    println!("cargo:rerun-if-env-changed=VIGIL_NPCAP_SDK_DIR");
    println!("cargo:rustc-check-cfg=cfg(has_libpcap)");

    if std::env::var_os("CARGO_FEATURE_PCAP").is_none()
        && std::env::var_os("VIGIL_ENABLE_PCAP_DISCOVERY").is_none()
    {
        println!("cargo:warning=libpcap discovery is optional; enable the `pcap` feature or set VIGIL_ENABLE_PCAP_DISCOVERY=1 when the toolchain is ready");
        return;
    }

    if try_pkg_config().or_else(try_vcpkg).or_else(try_npcap_sdk).is_some() {
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

fn try_npcap_sdk() -> Option<()> {
    let sdk_lib_dir = sdk_lib_candidates().into_iter().find(|path| path.exists())?;

    println!("cargo:rustc-link-search=native={}", sdk_lib_dir.display());

    #[cfg(target_os = "windows")]
    {
        println!("cargo:rustc-link-lib=dylib=wpcap");
        println!("cargo:rustc-link-lib=dylib=Packet");
    }

    #[cfg(not(target_os = "windows"))]
    {
        println!("cargo:rustc-link-lib=dylib=pcap");
    }

    Some(())
}

fn sdk_lib_candidates() -> Vec<std::path::PathBuf> {
    let mut candidates = Vec::new();

    if let Some(dir) = std::env::var_os("VIGIL_NPCAP_SDK_DIR") {
        let base = std::path::PathBuf::from(dir);
        candidates.push(base.join("Lib/x64"));
        candidates.push(base.join("Lib/ARM64"));
        candidates.push(base.join("Lib"));
    }

    candidates.push(std::path::PathBuf::from(r"C:\NpcapSDK\Lib\x64"));
    candidates.push(std::path::PathBuf::from(r"C:\NpcapSDK\Lib\ARM64"));
    candidates.push(std::path::PathBuf::from(r"C:\Program Files\Npcap\SDK\Lib\x64"));
    candidates.push(std::path::PathBuf::from(r"C:\Program Files\Npcap\SDK\Lib\ARM64"));

    candidates
}