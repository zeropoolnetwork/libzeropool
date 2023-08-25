use std::fs::File;

use clap::Clap;
use fawkes_crypto::{
    backend::plonk::{Parameters, engines::Bn256},
    circuit::cs::CS,
};
use halo2_proofs::poly::commitment::Params;

pub fn main() {
    let opts: Opts = Opts::parse();
    match opts.command {
        SubCommand::Setup(o) => cli_setup(o),
    }
}

fn cli_setup(o:SetupOpts) {
    let params_path = o.params.unwrap_or("plonk_params.bin".to_string());
    let params: Parameters<Bn256> = Parameters::setup(o.k);

    let mut fp = File::create(params_path).unwrap();
    params.0.write(&mut fp).unwrap();

    println!("setup OK");
}

#[derive(Clap)]
struct Opts {
    #[clap(subcommand)]
    command: SubCommand,
}

#[derive(Clap)]
enum SubCommand {
    /// Generate trusted setup parameters
    Setup(SetupOpts),
}

/// A subcommand for generating a trusted setup parameters
#[derive(Clap)]
struct SetupOpts {
    /// Snark trusted setup parameters file
    #[clap(short = "p", long = "params")]
    params: Option<String>,
    /// Security parameter
    #[clap(short = "k", default_value = "16")]
    k: usize,
}

