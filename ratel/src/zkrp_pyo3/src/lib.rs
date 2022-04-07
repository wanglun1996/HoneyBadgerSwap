extern crate rand;
extern crate curve25519_dalek_ng;
extern crate merlin;
extern crate bulletproofs;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use pyo3::prelude::*;

#[pyfunction]
fn zkrp_prove(secret_value: u64) -> PyResult<(Vec<u8>, [u8;32])> {
    // Generators for Pedersen commitments.  These can be selected
    // independently of the Bulletproofs generators.
    let pc_gens = PedersenGens::default();

    // Generators for Bulletproofs, valid for proofs up to bitsize 64
    // and aggregation size up to 1.
    let bp_gens = BulletproofGens::new(64, 1);

    // The API takes a blinding factor for the commitment.
    let blinding = curve25519_dalek_ng::scalar::Scalar::random(&mut rand::thread_rng());

    // The proof can be chained to an existing transcript.
    // Here we create a transcript with a doctest domain separator.
    let mut prover_transcript = merlin::Transcript::new(b"zkrp");

    // Create a 32-bit rangeproof.
    let (proof, committed_value) = RangeProof::prove_single(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        secret_value,
        &blinding,
        32,
    ).expect("A real program could handle errors");

    Ok((proof.to_bytes(), *committed_value.as_bytes()))
}

/// Given `data` with `len >= 32`, return the first 32 bytes.
pub fn read32(data: &[u8]) -> [u8; 32] {
    let mut buf32 = [0u8; 32];
    buf32[..].copy_from_slice(&data[..32]);
    buf32
}

#[pyfunction]
fn zkrp_verify(proof_bytes: Vec<u8>, committed_value_bytes: [u8;32]) -> PyResult<bool> {
    // Generators for Pedersen commitments.  These can be selected
    // independently of the Bulletproofs generators.
    let pc_gens = PedersenGens::default();

    // Generators for Bulletproofs, valid for proofs up to bitsize 64
    // and aggregation size up to 1.
    let bp_gens = BulletproofGens::new(64, 1);

	let proof = RangeProof::from_bytes(proof_bytes.as_slice()).expect("Error: Proof deserialization failed!");
    let committed_value = curve25519_dalek_ng::ristretto::CompressedRistretto(read32(&committed_value_bytes));
    // Verification requires a transcript with identical initial state:
    let mut verifier_transcript = merlin::Transcript::new(b"zkrp");
    Ok(proof.verify_single(&bp_gens, &pc_gens, &mut verifier_transcript, &committed_value, 32).is_ok())
}

/// A Python module implemented in Rust.
#[pymodule]
fn zkrp_pyo3(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(zkrp_prove, m)?)?;
    m.add_function(wrap_pyfunction!(zkrp_verify, m)?)?;
    Ok(())
}
