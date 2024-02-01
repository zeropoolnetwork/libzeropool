use std::fs::File;
use std::io::Write;

use clap::Clap;
use fawkes_crypto::{backend::plonk::{Parameters, engines::Bn256}, BorshSerialize, circuit::cs::CS};
use fawkes_crypto::backend::plonk::setup::setup;
use fawkes_crypto::engines::bn256::Fr;
use near_halo2_verifier::PlonkVerifierData;
use libzeropool::circuit::tree::{CTreePub, CTreeSec, tree_update};
use libzeropool::circuit::tx::{c_transfer, CTransferPub, CTransferSec};
use libzeropool::POOL_PARAMS;

pub fn main() {
    let opts: Opts = Opts::parse();
    match opts.command {
        SubCommand::Setup(o) => cli_setup(o),
    }
}

fn tree_circuit<C:CS<Fr=Fr>>(public: CTreePub<C>, secret: CTreeSec<C>) {
    tree_update(&public, &secret, &*POOL_PARAMS);
}

fn tx_circuit<C:CS<Fr=Fr>>(public: CTransferPub<C>, secret: CTransferSec<C>) {
    c_transfer(&public, &secret, &*POOL_PARAMS);
}

fn cli_setup(o:SetupOpts) {
    let params_path = o.params.unwrap_or("plonk_params.bin".to_string());

    let params = if !std::path::Path::new(&params_path).exists() {
        let params: Parameters<Bn256> = Parameters::setup(o.k);
        println!("setup OK");
        let mut fp = File::create(params_path).unwrap();
        params.write(&mut fp).unwrap();
        params
    } else {
        let mut fp = File::open(params_path).unwrap();
        Parameters::read(&mut fp).unwrap()
    };

    let (vk, pk) = setup(&params, tree_circuit);

    let mut buf = Vec::new();
    vk.write(&mut buf).unwrap();
    let mut fp = File::create("tree_vk.bin").unwrap();
    fp.write_all(&buf).unwrap();

    let mut buf = Vec::new();
    pk.write(&mut buf).unwrap();
    let mut fp = File::create("tree_pk.bin").unwrap();
    fp.write_all(&buf).unwrap();

    let tree_vd = PlonkVerifierData::new(params.0.clone(), vk.0, o.k);
    let tree_vd_bytes = tree_vd.try_to_vec().unwrap();
    let mut fp = File::create("tree_vd.bin").unwrap();
    fp.write_all(&tree_vd_bytes).unwrap();

    println!("tree OK");

    let (vk, pk) = setup(&params, tx_circuit);

    let mut buf = Vec::new();
    vk.write(&mut buf).unwrap();
    let mut fp = File::create("transfer_vk.bin").unwrap();
    fp.write_all(&buf).unwrap();

    let mut buf = Vec::new();
    pk.write(&mut buf).unwrap();
    let mut fp = File::create("transfer_pk.bin").unwrap();
    fp.write_all(&buf).unwrap();

    let tx_vd = PlonkVerifierData::new(params.0.clone(), vk.0, o.k);
    let tx_vd_bytes = tx_vd.try_to_vec().unwrap();
    let mut fp = File::create("transfer_vd.bin").unwrap();
    fp.write_all(&tx_vd_bytes).unwrap();

    println!("tx OK");
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
    #[clap(short = "k", default_value = "20")]
    k: usize,
}

