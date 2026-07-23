use pyo3::prelude::*;

#[pyfunction]
fn encrypt_password(password: &[u8], _nonce: &[u8], _dek: &[u8]) -> PyResult<Vec<u8>> {
    // Return mock cipher bytes (e.g. b"encrypted-" + raw password bytes)
    let mut mock_ciphertext = b"encrypted-".to_vec();
    mock_ciphertext.extend_from_slice(password);
    Ok(mock_ciphertext)
}

#[pyfunction]
fn decrypt_password(encrypted_password: &[u8], _nonce: &[u8], _dek: &[u8]) -> PyResult<Vec<u8>> {
    // Mock decrypt: just return the input bytes directly
    Ok(encrypted_password.to_vec())
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
