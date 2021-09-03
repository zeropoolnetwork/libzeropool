mod evm_verifier;

use libzeropool::{
    POOL_PARAMS,
    circuit::tree::{tree_update, CTreePub, CTreeSec},
    circuit::tx::{c_transfer, CTransferPub, CTransferSec},
    clap::Clap,
};
use std::{fs::File, io::Write};

use fawkes_crypto::engines::bn256::Fr;
use fawkes_crypto::backend::bellman_groth16::engines::Bn256;
use fawkes_crypto::ff_uint::Num;
use fawkes_crypto::backend::bellman_groth16::{verifier::{VK, verify}, prover::{Proof, prove}, setup::setup, Parameters};
use evm_verifier::generate_sol_data;
use fawkes_crypto::circuit::cs::CS;
use fawkes_crypto::rand::rngs::OsRng;
use libzeropool::helpers::sample_data::State;


#[derive(Clap)]
struct Opts {
    #[clap(subcommand)]
    command: SubCommand,
}

#[derive(Clap)]
enum SubCommand {
    /// Generate a SNARK proof
    Prove(ProveOpts),
    /// Verify a SNARK proof
    Verify(VerifyOpts),
    /// Generate trusted setup parameters
    Setup(SetupOpts),
    /// Generate verifier smart contract
    GenerateVerifier(GenerateVerifierOpts),
    /// Generate test object
    GenerateTestData(GenerateTestDataOpts),
}

/// A subcommand for generating a SNARK proof
#[derive(Clap)]
struct ProveOpts {
    /// Circuit for prooving
    #[clap(short = "c", long = "circuit", default_value = "c_transfer")]
    circuit: String,
    /// Snark trusted setup parameters file
    #[clap(short = "p", long = "params", default_value = "params.bin")]
    params: String,
    /// Input object JSON file
    #[clap(short = "o", long = "object", default_value = "object.json")]
    object: String,
    /// Output file for proof JSON
    #[clap(short = "r", long = "proof", default_value = "proof.json")]
    proof: String,
    /// Output file for public inputs JSON
    #[clap(short = "i", long = "inputs", default_value = "inputs.json")]
    inputs: String,
}

/// A subcommand for verifying a SNARK proof
#[derive(Clap)]
struct VerifyOpts {
    /// Snark verification key
    #[clap(short = "v", long = "vk", default_value = "verification_key.json")]
    vk: String,
    /// Proof JSON file
    #[clap(short = "r", long = "proof", default_value = "proof.json")]
    proof: String,
    /// Public inputs JSON file
    #[clap(short = "i", long = "inputs", default_value = "inputs.json")]
    inputs: String,
}

/// A subcommand for generating a trusted setup parameters
#[derive(Clap)]
struct SetupOpts {
    /// Circuit for parameter generation
    #[clap(short = "c", long = "circuit", default_value = "c_transfer")]
    circuit: String,
    /// Snark trusted setup parameters file
    #[clap(short = "p", long = "params", default_value = "params.bin")]
    params: String,
    /// Snark verifying key file
    #[clap(short = "v", long = "vk", default_value = "verification_key.json")]
    vk: String,
}

/// A subcommand for generating a Solidity verifier smart contract
#[derive(Clap)]
struct GenerateVerifierOpts {
    /// Snark verification key
    #[clap(short = "v", long = "vk", default_value = "verification_key.json")]
    vk: String,
    /// Smart contract name
    #[clap(short = "n", long = "name", default_value = "Verifier")]
    contract_name: String,
    /// Output file name
    #[clap(short = "s", long = "solidity", default_value = "verifier.sol")]
    solidity: String,
}

#[derive(Clap)]
struct GenerateTestDataOpts {
    /// Input object JSON file
    #[clap(short = "o", long = "object", default_value = "object.json")]
    object: String
}

fn tree_circuit<C:CS<Fr=Fr>>(public: CTreePub<C>, secret: CTreeSec<C>) {
    tree_update(&public, &secret, &*POOL_PARAMS);
}

fn tx_circuit<C:CS<Fr=Fr>>(public: CTransferPub<C>, secret: CTransferSec<C>) {
    c_transfer(&public, &secret, &*POOL_PARAMS);
}

fn cli_setup(o:SetupOpts) {
    let params = if o.circuit.eq("tree_update") {
        setup::<Bn256, _, _, _>(tree_circuit)
    } else {
        setup::<Bn256, _, _, _>(tx_circuit)
    };
    let vk = params.get_vk();
    let vk_str = serde_json::to_string_pretty(&vk).unwrap();

    let mut fp = File::create(o.params).unwrap();
    params.write(&mut fp).unwrap();
    std::fs::write(o.vk, &vk_str.into_bytes()).unwrap();
    println!("setup OK");
}

fn cli_generate_verifier(o: GenerateVerifierOpts) {
    let vk_str = std::fs::read_to_string(o.vk).unwrap();
    let vk :VK<Bn256> = serde_json::from_str(&vk_str).unwrap();
    let sol_str = generate_sol_data(&vk, o.contract_name);
    File::create(o.solidity).unwrap().write(&sol_str.into_bytes()).unwrap();
    println!("solidity verifier generated")
}

fn cli_verify(o:VerifyOpts) {
    let vk_str = std::fs::read_to_string(o.vk).unwrap();
    let proof_str = std::fs::read_to_string(o.proof).unwrap();
    let public_inputs_str = std::fs::read_to_string(o.inputs).unwrap();

    let vk:VK<Bn256> = serde_json::from_str(&vk_str).unwrap();
    let proof:Proof<Bn256> = serde_json::from_str(&proof_str).unwrap();
    let public_inputs:Vec<Num<Fr>> = serde_json::from_str(&public_inputs_str).unwrap();

    println!("Verify result is {}.", verify(&vk, &proof, &public_inputs))
}

fn cli_generate_test_data(o:GenerateTestDataOpts) {
    let mut rng = OsRng::default();
    let state = State::random_sample_state(&mut rng, &*POOL_PARAMS);
    let data = state.random_sample_transfer(&mut rng, &*POOL_PARAMS);
    let data_str = serde_json::to_string_pretty(&data).unwrap();
    std::fs::write(o.object, &data_str.into_bytes()).unwrap();
    println!("Test data generated")

}

fn cli_prove(o:ProveOpts) {
    let params_data = std::fs::read(o.params).unwrap();
    let mut params_data_cur = &params_data[..];

    let params = Parameters::<Bn256>::read(&mut params_data_cur, false, false).unwrap();
    let object_str = std::fs::read_to_string(o.object).unwrap();

    let (inputs, snark_proof) = if o.circuit.eq("tree_update") {
        let (public, secret) = serde_json::from_str(&object_str).unwrap();
        prove(&params, &public, &secret, tree_circuit)
    } else {
        let (public, secret) = serde_json::from_str(&object_str).unwrap();
        prove(&params, &public, &secret, tx_circuit)
    };


    let proof_str = serde_json::to_string_pretty(&snark_proof).unwrap();
    let inputs_str = serde_json::to_string_pretty(&inputs).unwrap();

    std::fs::write(o.proof, &proof_str.into_bytes()).unwrap();
    std::fs::write(o.inputs, &inputs_str.into_bytes()).unwrap();
    
    println!("Proved")
}


pub fn main() {
    let opts: Opts = Opts::parse();
    match opts.command {
        SubCommand::Prove(o) => cli_prove(o),
        SubCommand::Verify(o) => cli_verify(o),
        SubCommand::Setup(o) => cli_setup(o),
        SubCommand::GenerateVerifier(o) => cli_generate_verifier(o),
        SubCommand::GenerateTestData(o) => cli_generate_test_data(o)
    }    
}
