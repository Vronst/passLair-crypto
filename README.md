# passlair-crypto

The cryptographic core of [passLair](https://github.com/Vronst/passLair): a small Rust
library, exposed to Python as a native extension module (via [PyO3](https://pyo3.rs)
and [maturin](https://www.maturin.rs)), that handles password encryption and key
derivation. It's consumed directly by the main `passLair` package — see
[`passlair.core.crypto`](https://github.com/Vronst/passLair/blob/main/src/passlair/core/crypto.py).

## What it does

- **Password encryption** — [`ChaCha20-Poly1305`](https://docs.rs/chacha20poly1305)
  AEAD encryption/decryption, with a fresh random nonce generated internally on every
  `encrypt_password` call.
- **Key derivation** — [`Argon2id`](https://docs.rs/argon2) hashing that produces both
  a PHC-formatted password hash (for verification) and a raw 32-byte key (for use as
  the encryption key above), from a password and a salt.

Argon2 parameters (`m=19456 KiB, t=2, p=1`) are pinned explicitly in
[`src/helpers.rs`](src/helpers.rs) rather than left at the `argon2` crate's defaults,
so a future crate upgrade can't silently change them and break already-derived keys.
The values match OWASP's current minimum recommendation for Argon2id.

## Installation

This crate isn't published to crates.io or PyPI — it's built from source as part of
the passLair workspace.

### As a Python package

```bash
pip install maturin
maturin develop --release   # builds and installs into the active virtualenv
# or: maturin build --release   # produces a wheel in target/wheels/
```

Requires Python >= 3.14 (see `pyproject.toml`). The built package is importable as
`passlair_crypto`.

### As a Rust crate

Not published; depend on it by path or git from within the workspace:

```toml
[dependencies]
passlair_crypto = { path = "../passLair-crypto" }
```

## Usage

All functions work on bytes — no string handling happens inside this library, so
encode/decode at your application boundary.

### Python

```python
from passlair_crypto import derive_new_keys, derive_keys, encrypt_password, decrypt_password

password = b"correct horse battery staple"

# Registration: derive a fresh salt, a storable hash, and an encryption key.
salt, password_hash, key = derive_new_keys(password)
# persist `salt` and `password_hash`; keep `key` in memory only.

# Encrypt a secret under that key.
ciphertext, nonce = encrypt_password(b"my-stored-secret", key)
# persist `ciphertext` and `nonce` alongside each other.

# ... later, e.g. on login ...
# Re-derive the same hash/key from the password and the stored salt.
same_hash, same_key = derive_keys(password, salt)
assert same_hash == password_hash  # verifies the password

plaintext = decrypt_password(ciphertext, nonce, same_key)
assert plaintext == b"my-stored-secret"
```

### Rust

```rust
use passlair_crypto::{derive_new_keys, derive_keys, encrypt_password, decrypt_password};

let password = b"correct horse battery staple";

let (salt, password_hash, key) = derive_new_keys(password)?;
let (ciphertext, nonce) = encrypt_password(b"my-stored-secret", &key)?;

let (same_hash, same_key) = derive_keys(password, &salt)?;
assert_eq!(same_hash, password_hash);

let plaintext = decrypt_password(&ciphertext, &nonce, &same_key)?;
assert_eq!(plaintext, b"my-stored-secret");
```

## API

| Function | Signature | Description |
|---|---|---|
| `derive_new_keys` | `(password: bytes) -> (salt, hash, key)` | Generates a fresh random salt and derives `hash`/`key` from `password`. Use for registration or password changes; persist `salt` and `hash`. |
| `derive_keys` | `(password: bytes, salt: bytes) -> (hash, key)` | Re-derives `hash`/`key` from `password` and a previously stored `salt`. Use for login/verification. `salt` must be exactly 16 bytes. |
| `encrypt_password` | `(password: bytes, key: bytes) -> (ciphertext, nonce)` | Encrypts `password` with ChaCha20-Poly1305 under `key`, generating a random nonce internally. `key` must be exactly 32 bytes. |
| `decrypt_password` | `(ciphertext: bytes, nonce: bytes, key: bytes) -> plaintext` | Decrypts `ciphertext` using `nonce` and `key`. `key` must be 32 bytes, `nonce` 12 bytes. |

All four raise `ValueError` (Python) / return `Err` (Rust) on invalid input lengths or
on cryptographic failure (e.g. tampered ciphertext, wrong key/nonce) — see the doc
comments in [`src/lib.rs`](src/lib.rs) for exact conditions.

## Security notes

- **Never reuse a nonce with the same key.** `encrypt_password` generates one for you
  on every call — always store the returned nonce alongside its ciphertext, and always
  use the matching pair.
- The key returned by `derive_new_keys`/`derive_keys` is used directly as the
  ChaCha20-Poly1305 key for `encrypt_password`/`decrypt_password` — there's no
  separate key-wrapping step.
- Error messages are intentionally generic (`"Decryption failed."`, `"Invalid key."`,
  etc.) — internal error details from the underlying crates are discarded rather than
  surfaced, to avoid leaking cryptographic internals to callers.

## Development

```bash
cargo test              # run the Rust test suite (unit + integration)
maturin develop          # rebuild and reinstall the Python extension after changes
```

CI (`.github/workflows/CiCd.yml`) runs `cargo test` on every push/PR via a shared
reusable workflow ([`Vronst/workflows`](https://github.com/Vronst/workflows)).

## License

MIT — see [LICENSE](LICENSE).
