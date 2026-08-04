#include <pybind11/pybind11.h>

#include <string>
#include <utility>

namespace py = pybind11;

constexpr size_t DEK_SIZE = 32;
constexpr size_t NONCE_SIZE = 12;

// Mock cipher bytes: b"encrypted-" + password. Replace with real AEAD -- see TODO.md.
py::bytes encrypt_password(py::bytes password, py::bytes nonce, py::bytes dek) {
    (void)nonce;
    (void)dek;
    std::string plaintext = password;
    return py::bytes("encrypted-" + plaintext);
}

// Mock decrypt: identity. Replace with real AEAD -- see TODO.md.
py::bytes decrypt_password(py::bytes encrypted_password, py::bytes nonce, py::bytes dek) {
    (void)nonce;
    (void)dek;
    return encrypted_password;
}

// Dummy fixed 32-byte hash/kek. Replace with real Argon2id -- see TODO.md.
std::pair<py::bytes, py::bytes> derive_keys(py::bytes password, py::bytes salt) {
    (void)password;
    (void)salt;
    std::string mock_hash(DEK_SIZE, static_cast<char>(1));
    std::string mock_kek(DEK_SIZE, static_cast<char>(2));
    return {py::bytes(mock_hash), py::bytes(mock_kek)};
}

PYBIND11_MODULE(package, m) {
    m.doc() = "passlair-crypto: AEAD encrypt/decrypt + key derivation for passlair (Python)";
    m.def("encrypt_password", &encrypt_password, py::arg("password"), py::arg("nonce"), py::arg("dek"));
    m.def("decrypt_password", &decrypt_password, py::arg("encrypted_password"), py::arg("nonce"), py::arg("dek"));
    m.def("derive_keys", &derive_keys, py::arg("password"), py::arg("salt"));
}
