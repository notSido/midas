use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "midas",
    version = env!("CARGO_PKG_VERSION"),
    about = "Themida VM-analysis toolkit skeleton"
)]
struct Cli;

fn main() {
    env_logger::init();
    let _cli = Cli::parse();

    log::info!("midas started");
    println!("midas: no analysis is implemented yet");
}
