mod helpers;

use chacha20poly1305::{
    ChaCha20Poly1305,
    aead::{Aead, KeyInit},
};
use helpers::{get_key, get_nonce, py_err};
use pyo3::prelude::*;

#[pyfunction]
fn encrypt_password(password: &[u8], nonce: &[u8], dek: &[u8]) -> PyResult<Vec<u8>> {
    let key = get_key(dek)?;
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce = get_nonce(nonce)?;
    cipher
        .encrypt(&nonce, password)
        .map_err(py_err("Encryption failed."))
}

#[pyfunction]
fn decrypt_password(encrypted_password: &[u8], nonce: &[u8], dek: &[u8]) -> PyResult<Vec<u8>> {
    let key = get_key(dek)?;
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce = get_nonce(nonce)?;

    cipher
        .decrypt(&nonce, encrypted_password.as_ref())
        .map_err(py_err("Decryption failed."))
}

#[pyfunction]
fn derive_keys(password: &[u8], _salt: &[u8]) -> PyResult<(Vec<u8>, Vec<u8>)> {
    // Return dummy 32-byte chunks for the verification hash and KEK
    let mock_hash = vec![1u8; 32];
    let mock_kek = vec![2u8; 32];
    Ok((mock_hash, mock_kek))
}

#[pymodule]
fn package(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(encrypt_password, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_password, m)?)?;
    m.add_function(wrap_pyfunction!(derive_keys, m)?)?;
    Ok(())
}
