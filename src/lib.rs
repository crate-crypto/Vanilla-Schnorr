#![allow(non_snake_case)]

use curve25519_dalek::constants;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use rand_os::OsRng;
use sha2::{Digest, Sha512};

// Proof represents a schnorr proof struct which
// will be used to construct a Schnorr signature
pub struct Proof {
    privkey: Scalar,
}

pub struct Signature {
    s: Scalar,
    R: CompressedRistretto,
}
#[derive(Debug, Clone)]
pub enum Error {
    // This error occurs when decompressing a point
    // leads to a failure
    PointDecompressionFailed,
    // This error occurs when the equality check used
    // by the verifier fails
    EqualityFailed,
}

impl Proof {
    //  creates a new proof struct that holds the private key information
    pub fn new(private_key: Scalar) -> Self {
        return Proof {
            privkey: private_key,
        };
    }

    // prove produces a signature on a message `msg`
    // that is verifiable given the public key corresponding
    // to the private key used in prove
    pub fn prove(self, msg: &str) -> Signature {
        // Setup RNG
        let mut csprng: OsRng = OsRng::new().unwrap();

        // Generate nonce scalar: r
        let nonce: Scalar = Scalar::random(&mut csprng);

        // Generate nonce point: R = rG
        let R = nonce * &constants::RISTRETTO_BASEPOINT_POINT;

        // challenge = H(message || R)
        let mut hasher = Sha512::default();
        hasher.input(msg);
        hasher.input(R.compress().as_bytes());
        let c = Scalar::from_hash(hasher);

        // s = r + c * private_key
        let s = nonce + c * self.privkey;

        Signature {
            s: s,
            R: R.compress(),
        }
    }
}

impl Signature {
    // Returns an error if verification fails
    pub fn verify(&self, public_key: CompressedRistretto, msg: &str) -> Result<(), Error> {
        // challenge = H(message || R)
        let mut hasher = Sha512::default();
        hasher.input(msg);
        hasher.input(self.R.as_bytes());
        let c = Scalar::from_hash(hasher);

        // Check sG = rG + c * (private_key)*G = R + c * public_key
        //
        // sG
        let sG = self.s * &constants::RISTRETTO_BASEPOINT_POINT;
        //
        //
        // R + c * public_key
        match (public_key.decompress(), self.R.decompress()) {
            (Some(pk), Some(R)) => {
                if !(sG == R + c * pk) {
                    return Err(Error::EqualityFailed);
                }
                Ok(())
            }
            // If either point cannot be decompressed we should fail verification
            _ => Err(Error::PointDecompressionFailed),
        }
    }
}

#[cfg(test)]
fn generate_keypair() -> (Scalar, CompressedRistretto) {
    // setup random generator
    let mut csprng: OsRng = OsRng::new().unwrap();
    // generate a private key
    let privkey: Scalar = Scalar::random(&mut csprng);
    // generate corresponding public key
    let public_key = (privkey * constants::RISTRETTO_BASEPOINT_POINT).compress();
    (privkey, public_key)
}

#[test]
fn test_correct_sig() {
    let (privkey, public_key) = generate_keypair();

    // sign message with private key
    let msg = "hello world";
    let proof: Proof = Proof::new(privkey);
    let signature = proof.prove(msg);

    assert!(signature.verify(public_key, msg).is_ok());
}

// sign message with private key however we verify with a different message
// this should fail verification
#[test]
fn test_false_msg() {
    let (privkey, public_key) = generate_keypair();

    // sign message with private key
    let msg = "hello world";
    let wrong_msg = "world hello";

    let proof: Proof = Proof::new(privkey);
    let signature = proof.prove(msg);

    assert!(signature.verify(public_key, wrong_msg).is_err());
}
// sign message with private key however we verify with a different public key
// this should fail verification
#[test]
fn test_wrong_public_key() {
    let (privkey, _) = generate_keypair();
    let (_, wrong_public_key) = generate_keypair();

    // sign message with private key
    let msg = "hello world";
    let proof: Proof = Proof::new(privkey);
    let signature = proof.prove(msg);

    assert!(signature.verify(wrong_public_key, msg).is_err());
}
