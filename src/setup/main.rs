#[cfg(feature = "groth16")]
mod cli_groth16;
#[cfg(feature = "groth16")]
mod evm_verifier;
#[cfg(feature = "plonk")]
mod cli_plonk;

fn main() {
    #[cfg(feature = "groth16")]
    cli_groth16::main();
    #[cfg(feature = "plonk")]
    cli_plonk::main();
}