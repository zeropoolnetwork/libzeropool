#[cfg(feature = "r1cs")]
mod cli_r1cs;
#[cfg(feature = "r1cs")]
mod evm_verifier;
#[cfg(feature = "plonk")]
mod cli_plonk;

fn main() {
    #[cfg(feature = "r1cs")]
    cli_r1cs::main();
    #[cfg(feature = "plonk")]
    cli_plonk::main();
}