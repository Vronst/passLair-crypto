use chacha20poly1305::{ChaCha20Poly1305, Nonce, aead::Key};
use pyo3::{PyErr, PyResult, exceptions::PyValueError};

pub fn py_err<E>(msg: &'static str) -> impl Fn(E) -> PyErr {
    move |_| PyValueError::new_err(msg)
}

pub fn get_nonce(nonce: &[u8]) -> PyResult<Nonce> {
    Nonce::try_from(nonce).map_err(py_err("Invalid nonce."))
}

pub fn get_key(dek: &[u8]) -> PyResult<Key<ChaCha20Poly1305>> {
    Key::<ChaCha20Poly1305>::try_from(dek).map_err(py_err("Invalid key."))
}
