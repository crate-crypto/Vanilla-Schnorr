## Simple Schnorr Signature Scheme

This protocol allows a verifier to verify a signature was signed by a given entity to whom `the verifier has their public key` to.

## Implementation details

There are a few assumptions that this protocol makes:

-  (Standard) The verifier is able to derive the message and has access to the public key independent of the signature. Note that the public key is not included in the signature.

- The OS is not compromised. For generating nonces, the randomness is fetched from the underlying Operating System. There is a known attack on the Schnorr Signature Scheme that allows retrieval of the provers private key, if nonces are repeated or if a bad random number generator is used; check rewinding the transcript in proofs.

- No constant time guarantees are made from the prove function. In particular the scalar multiplication, hash to scalar and scalar addition depend on the underlying library, in this case this curve25519.

## Security Proof

The security of the Schnorr signature scheme reduces to the Schnorr identification protocol which itself reduces to the discrete logarithm being hard in the group that it is implemented in. Therefore, the Schnorr Signature scheme is secure if the discrete log is hard.

## Reference 

Paper: https://link.springer.com/chapter/10.1007/0-387-34805-0_22

## Extensions 

Schnorr signatures are aggregatable similar to BLS signatures. This protocol has been described in the MuSig paper, however it has not been implemented in this repo. However one should note that if aggregation is done improperly, an adversary can use a rogue public key to make it so that only he can sign for the multisig. This can be mitigated using the Knowledge of Secret Key scheme(KOSK), however this necesitates a trusted party. Interactive MuSig does not use KOSK so it is therefore proven secure in the plain public key model.