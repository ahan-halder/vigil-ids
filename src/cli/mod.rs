use clap::{ArgGroup, Parser};

#[derive(Debug, Parser)]
#[command(name = "vigil-ids", version, about = "A minimal network intrusion detection system")]
#[command(group(
    ArgGroup::new("input")
        .required(false)
        .args(["interface", "pcap"])
))]
pub struct Cli {
    #[arg(long)]
    pub interface: Option<String>,

    #[arg(long)]
    pub pcap: Option<String>,

    #[arg(long)]
    pub rules: Option<String>,

    #[arg(long)]
    pub output: Option<String>,

    #[arg(long, default_value_t = false)]
    pub verbose: bool,
}