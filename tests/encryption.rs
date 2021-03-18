
use libzeropool::{POOL_PARAMS, native::params::PoolBN256};

use libzeropool::fawkes_crypto::{
    rand::{thread_rng, Rng},
    ff_uint::Num
};
use libzeropool::native::{
    note::Note,
    boundednum::BoundedNum,
    tx::{derive_key_pk_d},
    cypher
};


// #[test]
// fn test_encryption() {
//     let mut rng = thread_rng();
//     let esk = rng.gen();
//     let dk = rng.gen();

//     let mut note: Note<PoolBN256> = rng.gen();
//     note.v = BoundedNum::new(Num::from_uint_unchecked(note.v.to_num().to_uint()>>4));

//     let r_dk = rng.gen();
//     let r_pk_d = derive_key_pk_d(note.d.to_num(), r_dk, &*POOL_PARAMS).x;
//     note.pk_d = r_pk_d;

//     let msg = cypher::encrypt(esk, dk, note, &*POOL_PARAMS);
//     println!("Msg size: {}", msg.len());

//     let note1 = cypher::decrypt_out(dk, &msg, &*POOL_PARAMS).unwrap();
//     let note2 = cypher::decrypt_in(r_dk, &msg, &*POOL_PARAMS).unwrap();

//     assert!(note == note1, "Decryption for sender should be correct");
//     assert!(note == note2, "Decryption for receiver should be correct");
// }