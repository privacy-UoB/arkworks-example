use ark_bls12_377::Bls12_377;
use ark_ec::models::short_weierstrass::SWCurveConfig;
use ark_ff::{PrimeField, UniformRand};
use ark_groth16::Groth16;
use ark_r1cs_std::{
    eq::EqGadget,
    fields::{nonnative::NonNativeFieldVar, FieldVar},
    groups::{curves::short_weierstrass::GenericProjectiveVar, CurveVar},
    prelude::AllocVar,
    ToBitsGadget,
};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, Result as ArkResult, SynthesisError,
};
use ark_secp256r1::{Affine as P256Affine, Config as P256Config, Fq as P256Fq};
use ark_serialize::CanonicalSerialize;
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use rand::thread_rng;

// type ConstraintF = Fq;

#[derive(Clone)]
struct Circuit {
    // Signature
    r: Option<P256Fq>,
    s: Option<P256Fq>,

    // Message
    m: Option<P256Fq>,

    // Public Key
    pk: Option<P256Affine>,
}

// type P256AffineVar =

impl<ConstraintF: PrimeField> ConstraintSynthesizer<ConstraintF> for Circuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<ConstraintF>) -> ArkResult<()> {
        let r_var = NonNativeFieldVar::new_witness(cs.clone(), || {
            self.r.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let s_var = NonNativeFieldVar::new_witness(cs.clone(), || {
            self.s.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let m_var = NonNativeFieldVar::new_witness(cs.clone(), || {
            self.m.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let pk_var = GenericProjectiveVar::<
            P256Config,
            ConstraintF,
            NonNativeFieldVar<P256Fq, ConstraintF>,
        >::new_witness(cs.clone(), || {
            self.pk.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let g_var = GenericProjectiveVar::<
            P256Config,
            ConstraintF,
            NonNativeFieldVar<P256Fq, ConstraintF>,
        >::new_witness(cs, || Ok(P256Config::GENERATOR))?;

        let w_var = s_var.inverse()?;
        let u1_var = m_var * &w_var;
        let u2_var = r_var.clone() * &w_var;

        // Takes long:
        // let tmp1 = g_var.scalar_mul_le(u1_var.to_bits_le()?.iter())?;
        // let tmp2 = pk_var.scalar_mul_le(u2_var.to_bits_le()?.iter())?;
        // let r_point_var = tmp1 + tmp2;
        let r_point_var = g_var + pk_var;

        let r_point_var = r_point_var.to_affine()?;
        r_point_var.x.enforce_equal(&r_var)?;

        Ok(())
    }
}

pub struct ZKPTest;

impl ZKPTest {
    /// This function generates the parameters (proving and verifying keys) for the entire nano sync
    /// program. It does this by generating the parameters for each circuit, "from bottom to top". The
    /// order is absolutely necessary because each circuit needs a verifying key from the circuit "below"
    /// it. Note that the parameter generation can take longer than one hour, even two on some computers.
    pub fn setup() -> Result<(), SynthesisError> {
        let rng = &mut thread_rng();

        let circuit = Circuit {
            r: Some(P256Fq::rand(rng)),
            s: Some(P256Fq::rand(rng)),
            m: Some(P256Fq::rand(rng)),
            pk: Some(P256Affine::rand(rng)),
        };

        println!("Setup");
        let (pk, vk) = Groth16::<Bls12_377>::setup(circuit.clone(), rng)?;

        println!("Proving");
        let proof = Groth16::<Bls12_377>::prove(&pk, circuit, rng)?;
        println!("Proof size: {}", proof.compressed_size());

        println!("Verification");
        assert!(Groth16::<Bls12_377>::verify(&vk, &[], &proof).unwrap());

        Ok(())
    }
}
