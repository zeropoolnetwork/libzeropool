use fawkes_crypto::backend::bellman_groth16::{verifier::VK, group::{G1Point, G2Point}};
use fawkes_crypto::backend::bellman_groth16::engines::Bn256;


pub fn generate_sol_data(vk:&VK<Bn256>) -> String {
    let tpl = String::from(include_str!("../../res/verifier_groth16.sol.tpl"));
    fn stringify_g1(p:&G1Point<Bn256>) -> String {
        format!("{}, {}", p.0.to_string(), p.1.to_string()).to_string()
    }

    fn stringify_g2(p:&G2Point<Bn256>) -> String {
        format!("[{}, {}], [{}, {}]", p.0.0.to_string(), p.0.1.to_string(), p.1.0.to_string(), p.1.1.to_string()).to_string()
    }

    let mut tpl = tpl.replace("<%vk_alfa1%>", &stringify_g1(&vk.alpha));
    tpl = tpl.replace("<%vk_beta2%>", &stringify_g2(&vk.beta));
    tpl = tpl.replace("<%vk_gamma2%>", &stringify_g2(&vk.gamma));
    tpl = tpl.replace("<%vk_delta2%>", &stringify_g2(&vk.delta));

    tpl = tpl.replace("<%vk_ic_length%>", &vk.ic.len().to_string());
    tpl = tpl.replace("<%vk_input_length%>", &(vk.ic.len() - 1).to_string());

    let mut vi = String::from("");
    for i in 0..vk.ic.len() {
        vi = format!("{}{}vk.IC[{}] = Pairing.G1Point({});\n", vi, if vi.is_empty() { "" } else { "        " }, i, &stringify_g1(&vk.ic[i]));
    }
    tpl = tpl.replace("<%vk_ic_pts%>", &vi);
    tpl
}