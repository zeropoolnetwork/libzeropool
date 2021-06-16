use fawkes_crypto::{ff_uint::{Num, PrimeField},native::poseidon::poseidon};
use crate::constants;
use crate::native::{boundednum::BoundedNum, params::PoolParams};
use std::fmt::Debug;


#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct Note<Fr:PrimeField> {
    pub d: BoundedNum<Fr, { constants::DIVERSIFIER_SIZE }>,
    pub p_d: Num<Fr>,
    pub b: BoundedNum<Fr, { constants::BALANCE_SIZE }>,
    pub t: BoundedNum<Fr, { constants::SALT_SIZE }>,
}

impl<Fr:PrimeField> Note<Fr> {
    pub fn hash<P:PoolParams<Fr=Fr>>(&self, params:&P) -> Num<Fr> {
        poseidon(&[self.d.to_num(), self.p_d, self.b.to_num(), self.t.to_num()], params.note())
    }
}

impl<Fr:PrimeField> Copy for Note<Fr> {}

impl<Fr:PrimeField> Eq for Note<Fr> {}

impl<Fr:PrimeField> PartialEq for Note<Fr> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.d.eq(&other.d) && 
        self.p_d.eq(&other.p_d) &&
        self.b.eq(&other.b) &&
        self.t.eq(&other.t)
    }
}