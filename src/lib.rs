//! Python bindings for passLair's core cryptographic primitives: password
//! encryption/decryption (ChaCha20-Poly1305) and key derivation (Argon2id).

pub mod helpers;

use argon2::password_hash::{
    Salt, SaltString,
    rand_core::{OsRng, RngCore},
};
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, Generate, KeyInit},
};
use helpers::{build_argon2, derive_hash_and_key, get_key, get_nonce, py_err};
use pyo3::{exceptions::PyValueError, prelude::*};

/// Encrypt `password` with ChaCha20-Poly1305 using `dek` as the key.
///
/// A fresh random nonce is generated internally on every call — never reuse
/// one yourself. Returns `(ciphertext, nonce)`; store both, you need the
/// nonce to decrypt later.
///
/// # Errors
/// Raises `ValueError` if `dek` is not exactly 32 bytes, or if encryption
/// fails.
#[pyfunction]
pub fn encrypt_password(password: &[u8], dek: &[u8]) -> PyResult<(Vec<u8>, Vec<u8>)> {
    let key = get_key(dek)?;
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce = Nonce::generate();
    Ok((
        cipher
            .encrypt(&nonce, password)
            .map_err(py_err("Encryption failed."))?,
        nonce.to_vec(),
    ))
}

/// Decrypt `encrypted_password` with ChaCha20-Poly1305 using `nonce` and
/// `dek`.
///
/// # Errors
/// Raises `ValueError` if `dek` is not 32 bytes, `nonce` is not 12 bytes, or
/// authentication fails — wrong key/nonce, or the ciphertext was tampered
/// with.
#[pyfunction]
pub fn decrypt_password(encrypted_password: &[u8], nonce: &[u8], dek: &[u8]) -> PyResult<Vec<u8>> {
    let key = get_key(dek)?;
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce = get_nonce(nonce)?;

    cipher
        .decrypt(&nonce, encrypted_password.as_ref())
        .map_err(py_err("Decryption failed."))
}

/// Derive a password hash and a 32-byte encryption key from `password` and
/// `salt` using Argon2id, with parameters pinned in
/// [`helpers::build_argon2`] so derived keys stay reproducible even if the
/// `argon2` crate's own defaults change in a future upgrade.
///
/// `salt` must be exactly `Salt::RECOMMENDED_LENGTH` (16) bytes — use the
/// salt returned by [`derive_new_keys`] when re-deriving keys for an
/// existing record.
///
/// # Errors
/// Raises `ValueError` if `salt` is the wrong length, or if hashing fails.
#[pyfunction]
pub fn derive_keys(password: &[u8], salt: &[u8]) -> PyResult<(Vec<u8>, Vec<u8>)> {
    if salt.len() != Salt::RECOMMENDED_LENGTH {
        return Err(PyValueError::new_err("Salt size is wrong."));
    }

    let salt = SaltString::encode_b64(salt).map_err(py_err("Encoding salt failed."))?;
    // let argon2 = Argon2::default();
    let argon2 = build_argon2()?;
    let (hash, key) = derive_hash_and_key(&argon2, &password, &salt)?;
    Ok((hash, key.to_vec()))
}

/// Generate a fresh random salt and derive keys from `password`, as
/// [`derive_keys`] does.
///
/// Returns `(salt, hash, key)`. Use this for a *new* record; use
/// [`derive_keys`] with the stored salt to re-derive the same key later.
///
/// # Errors
/// Raises `ValueError` under the same conditions as [`derive_keys`].
#[pyfunction]
pub fn derive_new_keys(password: &[u8]) -> PyResult<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    // Basically raw implementation of
    // SaltString::generate(&mut OsRng)
    // but in u8 format.
    let mut salt = [0u8; Salt::RECOMMENDED_LENGTH];
    OsRng.fill_bytes(&mut salt);
    let (hash, key) = derive_keys(password, &salt)?;
    Ok((salt.to_vec(), hash, key.to_vec()))
}

#[pymodule]
fn package(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(encrypt_password, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_password, m)?)?;
    m.add_function(wrap_pyfunction!(derive_keys, m)?)?;
    m.add_function(wrap_pyfunction!(derive_new_keys, m)?)?;
    Ok(())
}
