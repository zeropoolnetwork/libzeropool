mod evm_verifier;

use libzeropool::{
    POOL_PARAMS,
    circuit::tree::{tree_update, CTreePub, CTreeSec},
    circuit::tx::{c_transfer, CTransferPub, CTransferSec},
    circuit::delegated_deposit::{check_delegated_deposit_batch, CDelegatedDepositBatchPub, CDelegatedDepositBatchSec},
    clap::Clap,
};
use core::panic;
use std::{fs::File, io::Write};

use fawkes_crypto::engines::bn256::Fr;
use fawkes_crypto::backend::bellman_groth16::engines::Bn256;
use fawkes_crypto::ff_uint::Num;
use fawkes_crypto::backend::bellman_groth16::{verifier::{VK, verify}, prover::{Proof, prove}, setup::setup, Parameters};
use evm_verifier::generate_sol_data;
use fawkes_crypto::circuit::cs::CS;
use fawkes_crypto::rand::rngs::OsRng;
use libzeropool::helpers::sample_data::{State, random_sample_tree_update, random_sample_delegated_deposit};
use convert_case::{Case, Casing};

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
    /// Circuit for prooving (transfer|tree_update)
    #[clap(short = "c", long = "circuit", default_value = "transfer")]
    circuit: String,
    /// Snark trusted setup parameters file
    #[clap(short = "p", long = "params")]
    params: Option<String>,
    /// Input object JSON file
    #[clap(short = "o", long = "object")]
    object: Option<String>,
    /// Output file for proof JSON
    #[clap(short = "r", long = "proof")]
    proof: Option<String>,
    /// Output file for public inputs JSON
    #[clap(short = "i", long = "inputs")]
    inputs: Option<String>,
}

/// A subcommand for verifying a SNARK proof
#[derive(Clap)]
struct VerifyOpts {
    /// Circuit for verifying (transfer|tree_update)
    #[clap(short = "c", long = "circuit", default_value = "transfer")]
    circuit: String,
    /// Snark verification key
    #[clap(short = "v", long = "vk")]
    vk: Option<String>,
    /// Proof JSON file
    #[clap(short = "r", long = "proof")]
    proof: Option<String>,
    /// Public inputs JSON file
    #[clap(short = "i", long = "inputs")]
    inputs: Option<String>,
}

/// A subcommand for generating a trusted setup parameters
#[derive(Clap)]
struct SetupOpts {
    /// Circuit for parameter generation (transfer|tree_update)
    #[clap(short = "c", long = "circuit", default_value = "transfer")]
    circuit: String,
    /// Snark trusted setup parameters file
    #[clap(short = "p", long = "params")]
    params: Option<String>,
    /// Snark verifying key file
    #[clap(short = "v", long = "vk")]
    vk: Option<String>,
}

/// A subcommand for generating a Solidity verifier smart contract
#[derive(Clap)]
struct GenerateVerifierOpts {
    /// Circuit for verifying (transfer|tree_update)
    #[clap(short = "c", long = "circuit", default_value = "transfer")]
    circuit: String,
    /// Snark verification key
    #[clap(short = "v", long = "vk")]
    vk: Option<String>,
    /// Smart contract name
    #[clap(short = "n", long = "name")]
    contract_name: Option<String>,
    /// Output file name
    #[clap(short = "s", long = "solidity")]
    solidity: Option<String>,
}

#[derive(Clap)]
struct GenerateTestDataOpts {
    /// Circuit for testing (transfer|tree_update)
    #[clap(short = "c", long = "circuit", default_value = "transfer")]
    circuit: String,
    /// Input object JSON file
    #[clap(short = "o", long = "object")]
    object: Option<String>
}

fn tree_circuit<C:CS<Fr=Fr>>(public: CTreePub<C>, secret: CTreeSec<C>) {
    tree_update(&public, &secret, &*POOL_PARAMS);
}

fn tx_circuit<C:CS<Fr=Fr>>(public: CTransferPub<C>, secret: CTransferSec<C>) {
    c_transfer(&public, &secret, &*POOL_PARAMS);
}

fn delegated_deposit_circuit<C:CS<Fr=Fr>>(public: CDelegatedDepositBatchPub<C>, secret: CDelegatedDepositBatchSec<C>) {
    check_delegated_deposit_batch(&public, &secret, &*POOL_PARAMS);
}

fn cli_setup(o:SetupOpts) {
    let params_path = o.params.unwrap_or(format!("{}_params.bin", o.circuit));
    let vk_path = o.vk.unwrap_or(format!("{}_verification_key.json", o.circuit));
    

    let params = match o.circuit.as_str() {
        "tree_update" => setup::<Bn256, _, _, _>(tree_circuit),
        "transfer" => setup::<Bn256, _, _, _>(tx_circuit),
        "delegated_deposit" => setup::<Bn256, _, _, _>(delegated_deposit_circuit),
        _ => panic!("Wrong cicruit parameter")
    };

    let vk = params.get_vk();
    let vk_str = serde_json::to_string_pretty(&vk).unwrap();

    let mut fp = File::create(params_path).unwrap();
    params.write(&mut fp).unwrap();
    std::fs::write(vk_path, &vk_str.into_bytes()).unwrap();
    println!("setup OK");
}

fn cli_generate_verifier(o: GenerateVerifierOpts) {
    let circuit = o.circuit.clone();
    let vk_path = o.vk.unwrap_or(format!("{}_verification_key.json", circuit));
    let contract_name = o.contract_name.unwrap_or(format!("{}_verifier", circuit).to_case(Case::Pascal));
    let solidity_path = o.solidity.unwrap_or(format!("{}_verifier.sol", circuit));


    let vk_str = std::fs::read_to_string(vk_path).unwrap();
    let vk :VK<Bn256> = serde_json::from_str(&vk_str).unwrap();
    let sol_str = generate_sol_data(&vk, contract_name);
    File::create(solidity_path).unwrap().write(&sol_str.into_bytes()).unwrap();
    println!("solidity verifier generated")
}

fn cli_verify(o:VerifyOpts) {
    let proof_path = o.proof.unwrap_or(format!("{}_proof.json", o.circuit));
    let vk_path = o.vk.unwrap_or(format!("{}_verification_key.json", o.circuit));
    let inputs_path = o.inputs.unwrap_or(format!("{}_inputs.json", o.circuit));

    let vk_str = std::fs::read_to_string(vk_path).unwrap();
    let proof_str = std::fs::read_to_string(proof_path).unwrap();
    let public_inputs_str = std::fs::read_to_string(inputs_path).unwrap();

    let vk:VK<Bn256> = serde_json::from_str(&vk_str).unwrap();
    let proof:Proof<Bn256> = serde_json::from_str(&proof_str).unwrap();
    let public_inputs:Vec<Num<Fr>> = serde_json::from_str(&public_inputs_str).unwrap();

    println!("Verify result is {}.", verify(&vk, &proof, &public_inputs))
}

fn cli_generate_test_data(o:GenerateTestDataOpts) {
    let object_path = o.object.unwrap_or(format!("{}_object.json", o.circuit));
    let mut rng = OsRng::default();
    let data_str = match o.circuit.as_str() {
        "transfer" => {
            let state = State::random_sample_state(&mut rng, &*POOL_PARAMS);
            let data = state.random_sample_transfer(&mut rng, &*POOL_PARAMS);
            serde_json::to_string_pretty(&data).unwrap()
            
        },
        "tree_update" => {
            let data = random_sample_tree_update(&mut rng, &*POOL_PARAMS);
            serde_json::to_string_pretty(&data).unwrap()
        },
        "delegated_deposit" => {
            let data = random_sample_delegated_deposit(&mut rng, &*POOL_PARAMS);
            serde_json::to_string_pretty(&data).unwrap()
        },
        _ => panic!("Wrong cicruit parameter")
    };
    std::fs::write(object_path, &data_str.into_bytes()).unwrap();

    println!("Test data generated")

}

fn cli_prove(o:ProveOpts) {
    let params_path = o.params.unwrap_or(format!("{}_params.bin", o.circuit));
    let object_path = o.object.unwrap_or(format!("{}_object.json", o.circuit));
    let proof_path = o.proof.unwrap_or(format!("{}_proof.json", o.circuit));
    let inputs_path = o.inputs.unwrap_or(format!("{}_inputs.json", o.circuit));

    let params_data = std::fs::read(params_path).unwrap();
    let mut params_data_cur = &params_data[..];

    let params = Parameters::<Bn256>::read(&mut params_data_cur, false, false).unwrap();
    let object_str = std::fs::read_to_string(object_path).unwrap();

    let (inputs, snark_proof) = match o.circuit.as_str() {
        "transfer" => {
            let (public, secret) = serde_json::from_str(&object_str).unwrap();
            prove(&params, &public, &secret, tx_circuit)
        },
        "tree_update" => {
            let (public, secret) = serde_json::from_str(&object_str).unwrap();
            prove(&params, &public, &secret, tree_circuit)
        },
        "delegated_deposit" => {
            let (public, secret) = serde_json::from_str(&object_str).unwrap();
            prove(&params, &public, &secret, delegated_deposit_circuit)  
        },
        _ => panic!("Wrong cicruit parameter")
    };


    let proof_str = serde_json::to_string_pretty(&snark_proof).unwrap();
    let inputs_str = serde_json::to_string_pretty(&inputs).unwrap();

    std::fs::write(proof_path, &proof_str.into_bytes()).unwrap();
    std::fs::write(inputs_path, &inputs_str.into_bytes()).unwrap();
    
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
