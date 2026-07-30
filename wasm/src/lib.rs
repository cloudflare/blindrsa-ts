// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

//! Client-side RSAPBSSA operations for @cloudflare/blindrsa-ts.
//!
//! Partially blind RSA derives a per-metadata public key whose exponent is
//! about half the size of the modulus. Browsers refuse such an exponent in
//! WebCrypto, so the client cannot delegate these operations to the platform.
//! Rather than reimplementing RSASSA-PSS in JavaScript, this exposes the
//! operations from `blind-rsa-signatures`, the same crate used by the Rust
//! Privacy Pass implementation.
//!
//! Only the client side is exposed: blinding, finalization and verification.
//! Key generation and blind signing stay with the issuer.
//!
//! Messages are passed already prepared, so any randomized prefix is part of
//! `prepared_msg`. That makes the `Deterministic` message preparation of the
//! crate the right one for every RSAPBSSA variant here, and the salt length
//! is the only parameter that still varies.

use blind_rsa_signatures::pbrsa::PartiallyBlindPublicKey;
use blind_rsa_signatures::reexports::rsa::traits::PublicKeyParts;
use blind_rsa_signatures::reexports::rsa::{BoxedUint, RsaPublicKey};
use blind_rsa_signatures::{
    BlindMessage, BlindSignature, BlindingResult, Deterministic, Error, SaltMode, Secret, Sha384,
    Signature,
    DefaultRng, PSSZero, PSS,
};
use wasm_bindgen::prelude::*;

/// Public key of a suite, before per-metadata derivation.
type PbPublicKey<S> = PartiallyBlindPublicKey<Sha384, S, Deterministic>;

// Modulus sizes the crate supports. RsaPublicKey::new does not police this,
// so an unusable key would otherwise surface much later as a signature that
// simply does not verify.
const MODULUS_BITS: std::ops::RangeInclusive<u32> = 1024..=4096;

fn derive<S: SaltMode>(n: &[u8], e: &[u8], info: &[u8]) -> Result<PbPublicKey<S>, Error> {
    let n = BoxedUint::from_be_slice(n, (n.len() * 8) as u32).map_err(|_| Error::InternalError)?;
    let e = BoxedUint::from_be_slice(e, (e.len() * 8) as u32).map_err(|_| Error::InternalError)?;
    if !MODULUS_BITS.contains(&n.bits()) {
        return Err(Error::UnsupportedParameters);
    }
    let pk = RsaPublicKey::new(n, e).map_err(|_| Error::UnsupportedParameters)?;
    PbPublicKey::<S>::new(pk).derive_public_key_for_metadata(info)
}

fn blind_impl<S: SaltMode>(
    n: &[u8],
    e: &[u8],
    info: &[u8],
    prepared_msg: &[u8],
) -> Result<Vec<u8>, Error> {
    let derived = derive::<S>(n, e, info)?;
    let result = derived.blind(&mut DefaultRng, prepared_msg, Some(info))?;
    let mut out = result.blind_message.to_vec();
    out.extend_from_slice(&result.secret);
    Ok(out)
}

fn finalize_impl<S: SaltMode>(
    n: &[u8],
    e: &[u8],
    info: &[u8],
    prepared_msg: &[u8],
    blind_sig: &[u8],
    inv: &[u8],
) -> Result<Vec<u8>, Error> {
    let derived = derive::<S>(n, e, info)?;
    // The crate carries the blinding secret inside BlindingResult; only the
    // secret is read when finalizing, and it is what this library calls `inv`.
    let result = BlindingResult {
        blind_message: BlindMessage(Vec::new()),
        secret: Secret(inv.to_vec()),
        msg_randomizer: None,
    };
    let sig = derived.finalize(
        &BlindSignature(blind_sig.to_vec()),
        &result,
        prepared_msg,
        Some(info),
    )?;
    Ok(sig.to_vec())
}

// Separates a bad signature from a bad key: the first is a false result, the
// second an error, so a caller cannot mistake one for the other. The crate
// reports both as UnsupportedParameters, hence the explicit length check and
// the key validation in `derive`.
fn verify_impl<S: SaltMode>(
    n: &[u8],
    e: &[u8],
    info: &[u8],
    prepared_msg: &[u8],
    signature: &[u8],
) -> Result<bool, Error> {
    let derived = derive::<S>(n, e, info)?;
    if signature.len() != derived.as_ref().size() {
        return Ok(false);
    }
    match derived.verify(
        &Signature(signature.to_vec()),
        None,
        prepared_msg,
        Some(info),
    ) {
        Ok(()) => Ok(true),
        Err(Error::VerificationFailed) => Ok(false),
        Err(e) => Err(e),
    }
}

// Dispatches on the salt length, the only suite parameter that reaches the
// type level here. PSS is 48 bytes for SHA-384, PSSZero is 0.
macro_rules! by_salt_length {
    ($salt_length:expr, $call:ident ( $($arg:expr),* $(,)? )) => {
        match $salt_length {
            48 => $call::<PSS>($($arg),*),
            0 => $call::<PSSZero>($($arg),*),
            _ => Err(Error::UnsupportedParameters),
        }
    };
}

/// Blinds a prepared message under the key derived from `info`.
///
/// Returns the blinded message followed by the blinding inverse, each of
/// modulus length.
#[wasm_bindgen]
pub fn blind(
    n: &[u8],
    e: &[u8],
    info: &[u8],
    prepared_msg: &[u8],
    salt_length: usize,
) -> Result<Vec<u8>, JsError> {
    by_salt_length!(salt_length, blind_impl(n, e, info, prepared_msg)).map_err(JsError::from)
}

/// Unblinds a blind signature and checks the result.
///
/// Returns an error when the resulting signature does not verify, which is
/// what the protocol requires of finalization.
#[wasm_bindgen]
pub fn finalize(
    n: &[u8],
    e: &[u8],
    info: &[u8],
    prepared_msg: &[u8],
    blind_sig: &[u8],
    inv: &[u8],
    salt_length: usize,
) -> Result<Vec<u8>, JsError> {
    by_salt_length!(
        salt_length,
        finalize_impl(n, e, info, prepared_msg, blind_sig, inv)
    )
    .map_err(JsError::from)
}

/// Verifies a signature under the key derived from `info`.
///
/// Every malformed or invalid signature is reported as false, so a caller
/// cannot tell those failure modes apart. An unusable key or suite is an
/// error instead.
#[wasm_bindgen]
pub fn verify(
    n: &[u8],
    e: &[u8],
    info: &[u8],
    prepared_msg: &[u8],
    signature: &[u8],
    salt_length: usize,
) -> Result<bool, JsError> {
    by_salt_length!(salt_length, verify_impl(n, e, info, prepared_msg, signature))
        .map_err(JsError::from)
}
