//! Internal helpers shared by the public `#[pyfunction]`s in `lib.rs`: input
//! validation, error mapping, and pinned Argon2 configuration.

use argon2::{Argon2, Params, PasswordHasher, password_hash::SaltString};
use chacha20poly1305::{ChaCha20Poly1305, Nonce, aead::Key};
use pyo3::{PyErr, PyResult, exceptions::PyValueError};

// Pinned explicitly (not `Params::default()` / `Params::DEFAULT_*`) so a
// future `argon2` crate upgrade can never silently change these and break
// reproducibility of already-derived keys. Matches OWASP's current minimum
// recommendation for Argon2id.
const M_COST: u32 = 19 * 1024; // 19 MB memory size
const T_COST: u32 = 2; // iterations
const P_COST: u32 = 1; // parallelism

/// Build a closure that discards whatever error it's given and returns a
/// `PyValueError` with a fixed, caller-facing `msg` instead — used via
/// `.map_err(py_err("..."))` to turn low-level crypto errors into a stable
/// Python-catchable exception without leaking internal error details.
pub fn py_err<E>(msg: &'static str) -> impl Fn(E) -> PyErr {
    move |_| PyValueError::new_err(msg)
}

/// Validate and convert a raw nonce into a ChaCha20-Poly1305 [`Nonce`].
///
/// # Errors
/// Raises `ValueError` if `nonce` is not exactly 12 bytes.
pub fn get_nonce(nonce: &[u8]) -> PyResult<Nonce> {
    Nonce::try_from(nonce).map_err(py_err("Invalid nonce."))
}

/// Validate and convert a raw DEK into a ChaCha20-Poly1305 [`Key`].
///
/// # Errors
/// Raises `ValueError` if `dek` is not exactly 32 bytes.
pub fn get_key(dek: &[u8]) -> PyResult<Key<ChaCha20Poly1305>> {
    Key::<ChaCha20Poly1305>::try_from(dek).map_err(py_err("Invalid key."))
}

/// Hash `password` into a PHC-formatted string and separately derive a raw
/// 32-byte key from it, using `argon2` and `salt`. Returns
/// `(hash_string_bytes, key_bytes)`.
///
/// # Errors
/// Raises `ValueError` if hashing, salt decoding, or key derivation fails.
pub fn derive_hash_and_key(
    argon2: &Argon2,
    password: &[u8],
    salt: &SaltString,
) -> PyResult<(Vec<u8>, Vec<u8>)> {
    if password.len() < 1 {
        return Err(PyValueError::new_err("Password too short."));
    }

    let hash = argon2
        .hash_password(password, salt)
        .map_err(py_err("Hashing password failed."))?
        .to_string()
        .into_bytes();

    let mut key = [0u8; 32];
    let mut salt_bytes = [0u8; 64];
    let decoded_salt = salt
        .decode_b64(&mut salt_bytes)
        .map_err(py_err("Decoding salt failed."))?;
    argon2
        .hash_password_into(password, decoded_salt, &mut key)
        .map_err(py_err("Deriving key failed"))?;
    Ok((hash, key.to_vec()))
}

/// Build an `Argon2id` instance using the pinned [`M_COST`]/[`T_COST`]/
/// [`P_COST`] parameters above, rather than the crate's own `Default`, so
/// derived keys can't silently change output on an `argon2` crate upgrade.
pub fn build_argon2() -> PyResult<Argon2<'static>> {
    let params = Params::new(M_COST, T_COST, P_COST, None)
        .map_err(py_err("Failed to create Argon params."))?;
    Ok(Argon2::from(params))
}
