//! What every scenario file checks services with. Each scenario is its own test file, and so its
//! own process, because the self-test statuses are process-global. Every scenario runs with any
//! combination of the `aes`, `sha2`, `ecdsa` and `eccdh` features; the checks cover the enabled
//! ones.

#![allow(dead_code)]

#[cfg(feature = "aes")]
use bouncycastle_aes::AES128Key;
#[cfg(feature = "aes")]
use bouncycastle_cipher::modes::{Blocks, CBC, GCM};
#[cfg(feature = "aes")]
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::fips::SelfTestStatus;
#[cfg(any(feature = "aes", feature = "eccdh"))]
use bouncycastle_core::key_material::KeyMaterial;
#[cfg(feature = "aes")]
use bouncycastle_core::key_material::KeyType;
#[cfg(feature = "aes")]
use bouncycastle_core::symmetric_key::FromKeyMaterial;
#[cfg(feature = "sha2")]
use bouncycastle_core::traits::HashOneShot;
#[cfg(all(feature = "ecdsa", not(feature = "sha2")))]
use bouncycastle_sha2::SHA256;
#[cfg(feature = "sha2")]
use bouncycastle_sha2::{SHA224, SHA256, SHA384, SHA512, SHA512_256};
#[cfg(feature = "sha2")]
use std::panic::catch_unwind;

#[cfg(feature = "eccdh")]
use bouncycastle_core::errors::KeyAgreementError;
#[cfg(feature = "ecdsa")]
use bouncycastle_core::errors::SignatureError;
#[cfg(any(feature = "ecdsa", feature = "eccdh"))]
use bouncycastle_core::security_strength::SecurityStrength;
#[cfg(any(feature = "ecdsa", feature = "eccdh"))]
use bouncycastle_ec::P256;
#[cfg(feature = "eccdh")]
use bouncycastle_eccdh::keys::{ECCDHPrivateKey, ECCDHPublicKey};
#[cfg(feature = "ecdsa")]
use bouncycastle_ecdsa::keys::{ECDSAPrivateKey, ECDSAPublicKey};
#[cfg(any(feature = "ecdsa", feature = "eccdh"))]
use bouncycastle_rng::FixedSeedRNG;

/// An RNG for the EC key pairs that does not hash, so it can be made whatever SHA-2's status.
#[cfg(any(feature = "ecdsa", feature = "eccdh"))]
pub fn ec_rng() -> FixedSeedRNG<[u8; 64]> {
    let mut rng = FixedSeedRNG::new([0x5a; 64]);
    rng.set_security_strength(SecurityStrength::_256bit);
    rng
}

/// An ECDSA P-256 key pair, a deterministic signer and a verifier from the public constructors:
/// `Ok` or the error all three gave.
#[cfg(feature = "ecdsa")]
pub fn ecdsa_services() -> Result<(), SignatureError> {
    use bouncycastle_core::signature_key::{DeterministicSigningKey, VerifyingKey};
    use bouncycastle_core::traits::{SignaturePrivateKey, SignaturePublicKey};
    use bouncycastle_sha2::SHA256;
    // Decoding is not gated, so a key to make the signer and verifier from always exists.
    let sk = ECDSAPrivateKey::<P256, SHA256>::from_bytes(&[0x11; 32]).unwrap();
    let pk = ECDSAPublicKey::<P256, SHA256>::from_bytes(&ecdsa_p256_generator()).unwrap();
    let keygen = bouncycastle_ecdsa::keys::keygen::<P256, SHA256>(&mut ec_rng()).map(|_| ());
    let signer = sk.create_signer_deterministic(None).map(|_| ());
    let verifier = pk.create_verifier(None).map(|_| ());
    assert_eq!(keygen, signer, "every ECDSA service is gated alike");
    assert_eq!(keygen, verifier, "every ECDSA service is gated alike");
    keygen
}

/// The P-256 base point, SEC 1 uncompressed: a valid public key that needs no key generation.
#[cfg(feature = "ecdsa")]
fn ecdsa_p256_generator() -> [u8; 65] {
    use bouncycastle_ec::curve::Curve;
    use bouncycastle_ec::hazmat::p256_domain::{G_X_LIMBS, G_Y_LIMBS};
    type Fe = <P256 as Curve>::Fe;
    P256::encode_uncompressed(
        &<Fe as bouncycastle_ec::curve::FieldElement>::from_limbs(G_X_LIMBS),
        &<Fe as bouncycastle_ec::curve::FieldElement>::from_limbs(G_Y_LIMBS),
    )
}

/// An ECC CDH P-256 key pair and a raw agreement worker from the public constructors: `Ok` or
/// the error both gave.
#[cfg(feature = "eccdh")]
pub fn eccdh_services() -> Result<(), KeyAgreementError> {
    use bouncycastle_core::agreement_key::AgreementKey;
    use bouncycastle_core::traits::KeyAgreementPrivateKey;
    let sk = ECCDHPrivateKey::<P256>::from_bytes(&[0x11; 32]).unwrap();
    let keygen = bouncycastle_eccdh::keys::keygen::<P256>(&mut ec_rng()).map(|_| ());
    let agreement = AgreementKey::<(), 32>::create_agreement(&sk, ()).map(|_| ());
    assert_eq!(keygen, agreement, "every ECC CDH service is gated alike");
    keygen
}

/// An AES-GCM key and an AES-CBC key from the public constructor: `Ok` or the error both gave.
#[cfg(feature = "aes")]
pub fn aes_keys() -> Result<(), SymmetricCipherError> {
    let material =
        KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey).unwrap();
    let gcm = AES128Key::<GCM>::from_key_material(&material).map(|_| ());
    let cbc = AES128Key::<CBC<Blocks>>::from_key_material(&material).map(|_| ());
    assert_eq!(gcm, cbc, "every AES mode is gated alike");
    gcm
}

/// Whether each SHA-2 hash could be created: `[SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/256]`.
#[cfg(feature = "sha2")]
pub fn sha2_hashes() -> [bool; 5] {
    [
        catch_unwind(SHA224::new).is_ok(),
        catch_unwind(SHA256::new).is_ok(),
        catch_unwind(SHA384::new).is_ok(),
        catch_unwind(|| SHA512::hash(b"abc")).is_ok(),
        catch_unwind(SHA512_256::default).is_ok(),
    ]
}

/// Checks every enabled algorithm's services: all created when `refused` is `None`; all refused
/// otherwise, an AES key with `SelfTestNotPassed` of that status.
pub fn assert_services(refused: Option<SelfTestStatus>) {
    #[cfg(feature = "aes")]
    assert_eq!(
        aes_keys(),
        refused.map_or(Ok(()), |s| Err(SymmetricCipherError::SelfTestNotPassed(s)))
    );
    #[cfg(feature = "sha2")]
    assert_eq!(sha2_hashes(), [refused.is_none(); 5]);
    #[cfg(feature = "ecdsa")]
    assert_eq!(
        ecdsa_services(),
        refused.map_or(Ok(()), |s| Err(SignatureError::SelfTestNotPassed(s)))
    );
    #[cfg(feature = "eccdh")]
    assert_eq!(
        eccdh_services(),
        refused.map_or(Ok(()), |s| Err(KeyAgreementError::SelfTestNotPassed(s)))
    );
    let _ = refused;
}

/// Services made at one point and used at another: an AES-GCM key, a SHA-256 hash in progress,
/// and freshly generated ECDSA and ECC CDH key pairs.
pub struct Held {
    #[cfg(feature = "aes")]
    key: AES128Key<GCM>,
    #[cfg(feature = "sha2")]
    hash: SHA256,
    #[cfg(feature = "ecdsa")]
    ecdsa: (ECDSAPublicKey<P256, SHA256>, ECDSAPrivateKey<P256, SHA256>),
    #[cfg(feature = "eccdh")]
    eccdh: (ECCDHPublicKey<P256>, ECCDHPrivateKey<P256>),
}

/// Makes a [`Held`]; the services must be available.
pub fn held() -> Held {
    #[cfg(feature = "sha2")]
    let hash = {
        use bouncycastle_core::traits::Hash;
        let mut hash = SHA256::new();
        hash.do_update(b"ab");
        hash
    };
    Held {
        #[cfg(feature = "aes")]
        key: AES128Key::<GCM>::from_key_material(
            &KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
                .unwrap(),
        )
        .unwrap(),
        #[cfg(feature = "sha2")]
        hash,
        #[cfg(feature = "ecdsa")]
        ecdsa: bouncycastle_ecdsa::keys::keygen(&mut ec_rng()).unwrap(),
        #[cfg(feature = "eccdh")]
        eccdh: bouncycastle_eccdh::keys::keygen(&mut ec_rng()).unwrap(),
    }
}

impl Held {
    /// Whether each enabled held service still produces output, in the order AES-GCM encryption,
    /// SHA-256 update and final, an ECDSA signature that verifies, an ECC CDH agreement; `false`
    /// where it panicked or refused.
    pub fn usable(&self) -> Vec<bool> {
        let mut usable = Vec::new();
        #[cfg(feature = "aes")]
        usable.push({
            use bouncycastle_core::symmetric_key::AeadEncryptionKey;
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.key.encrypt_detached_nonce_out(&[0; 12], b"", &[0; 16], &mut [0; 16]).is_ok()
            }))
            .unwrap_or(false)
        });
        #[cfg(feature = "sha2")]
        usable.push({
            use bouncycastle_core::traits::Hash;
            let mut hash = self.hash.clone();
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                hash.do_update(b"c");
                hash.do_final() == SHA256::hash(b"abc")
            }))
            .unwrap_or(false)
        });
        #[cfg(feature = "ecdsa")]
        usable.push({
            use bouncycastle_core::signature_key::{DeterministicSigningKey, VerifyingKey};
            let (pk, sk) = &self.ecdsa;
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                sk.sign_deterministic(b"abc", None)
                    .is_ok_and(|sig| pk.verify(b"abc", None, &sig).is_ok())
            }))
            .unwrap_or(false)
        });
        #[cfg(feature = "eccdh")]
        usable.push({
            use bouncycastle_core::agreement_key::AgreementKey;
            use bouncycastle_core::traits::KeyAgreement;
            let (pk, sk) = &self.eccdh;
            let mut z = KeyMaterial::<32>::new();
            AgreementKey::<(), 32>::create_agreement(sk, ())
                .is_ok_and(|a| a.agree_out(pk, &mut z).is_ok())
        });
        usable
    }
}
