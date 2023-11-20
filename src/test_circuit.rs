use ark_bls12_377::{Bls12_377, Fr};
use ark_ff::UniformRand;
use ark_groth16::Groth16;
use ark_r1cs_std::{
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    prelude::AllocVar,
};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, Result as ArkResult,
    SynthesisError,
};
use ark_serialize::CanonicalSerialize;
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use rand::thread_rng;

/// A very simple circuit proving that we know a secret `a` such that `a * a = a_square`.
#[derive(Clone)]
struct Circuit {
    // Private inputs
    a: Option<Fr>,

    // Public inputs
    a_square: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for Circuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> ArkResult<()> {
        let a_var = FpVar::new_witness(cs.clone(), || {
            self.a.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let a_square_var = FpVar::new_input(cs.clone(), || {
            self.a_square.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let a_sq_check_var = a_var.square()?;
        a_sq_check_var.enforce_equal(&a_square_var)?;

        Ok(())
    }
}

pub struct ZKPTest;

impl ZKPTest {
    pub fn run() -> Result<(), SynthesisError> {
        let rng = &mut thread_rng();

        let a = Fr::rand(rng);
        let a_square = a * a;
        let circuit = Circuit {
            a: Some(a),
            a_square: Some(a_square),
        };

        // The following code instantiates a local constraint system and checks the validity of the circuit.
        // This can be helpful for debugging.
        // It also prints the number of constraints.
        println!("Check circuit without proving");
        let cs = ConstraintSystem::new_ref();
        // The function consumes the circuit and constraint system, which is why we clone them.
        circuit.clone().generate_constraints(cs.clone()).unwrap();
        println!("Is satisfied: {}", cs.is_satisfied().unwrap());
        println!("Num constraints: {}", cs.num_constraints());

        // The setup creates the proving/verifying keys specific for this circuit.
        println!("Setup");
        let (pk, vk) = Groth16::<Bls12_377>::setup(circuit.clone(), rng)?;

        // Now we prove the circuit.
        println!("Proving");
        let proof = Groth16::<Bls12_377>::prove(&pk, circuit, rng)?;
        println!("Proof size: {}", proof.compressed_size());

        // When verifying the proof, we need to supply the public inputs.
        println!("Verification");
        assert!(Groth16::<Bls12_377>::verify(&vk, &[a_square], &proof).unwrap());

        Ok(())
    }
}
