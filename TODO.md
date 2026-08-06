# passlair-crypto: implementation TODO

Three `#[pyfunction]`s in `src/lib.rs` are currently mocked and need real
implementations. This doc is a checklist + hints, not code — you're doing the
Rust yourself.

## The contract (don't break this — passlair (Python) already calls these)

```rust
fn encrypt_password(password: &[u8], nonce: &[u8], dek: &[u8]) -> PyResult<Vec<u8>>
fn decrypt_password(encrypted_password: &[u8], nonce: &[u8], dek: &[u8]) -> PyResult<Vec<u8>>
fn derive_keys(password: &[u8], salt: &[u8]) -> PyResult<(Vec<u8>, Vec<u8>)>
```

- `dek`/`kek` are always 32 bytes (`DEK_SIZE = 32` in Python).
- `nonce` is always 12 bytes (`NONCE_SIZE = 12` in `core/crypto.py`), generated
  Python-side via `os.urandom(12)` for every single encrypt call — never
  reused, never passed in by the caller for decrypt except the one that was
  stored alongside the ciphertext.
- `derive_keys` returns `(hash, kek)`: `hash` is what gets stored in the DB
  (`StandardUser.master_password`) and compared on login; `kek` wraps/unwraps
  the DEK. Both must be 32 bytes. Same `(password, salt)` in ⇒ same
  `(hash, kek)` out, every time (login has to be able to recompute it).
- On bad input (auth tag fails to verify, etc.) return `Err(...)` — don't
  panic. A panic across the FFI boundary is undefined behavior with pyo3, not
  just an ugly crash.

## 1. Tooling / getting oriented

- [x] Build with `maturin develop` (via `uv run maturin develop` — pyo3
      projects use maturin, not plain `cargo build`, to produce the `.so`
      Python imports). Confirm this still works before touching anything.
- [x] `cargo test` for the Rust-side unit tests you'll add — these don't need
      Python/maturin at all, just `cargo test` in the crate root.
- [x] If you're new to Rust: skim [the Rust Book](https://doc.rust-lang.org/book/),
      ch. 9 (`Result`/error handling) and ch. 10 (traits) are the two most
      relevant chapters here. You mostly won't need lifetimes/generics beyond
      what pyo3's macros already handle for you.
- [x] Skim pyo3's own guide on [functions](https://pyo3.rs/latest/function.html)
      and [error handling](https://pyo3.rs/latest/exception.html) — you'll
      want `PyErr`/`PyValueError` for the `Err(...)` cases below.

--- so pyo3 will automatically handle Err() ---

## 2. AEAD encryption — `encrypt_password` / `decrypt_password`

You need an authenticated cipher (confidentiality + tamper detection), keyed
by the 32-byte DEK, using the given 12-byte nonce.

- [x] Add a RustCrypto AEAD crate: `cargo add aes-gcm` (AES-256-GCM) is the
      more "boring/standard" choice; `cargo add chacha20poly1305` works
      identically at the API level and doesn't need AES-NI hardware support.
      Either is fine — same 12-byte nonce, same 32-byte key, same API shape
      (`Aes256Gcm` vs `ChaCha20Poly1305`).
- [x] API shape to look for: `Key::<Aes256Gcm>::from_slice(dek)`,
      `Nonce::from_slice(nonce)`, then `.encrypt(nonce, plaintext)` /
      `.decrypt(nonce, ciphertext)` — both return `Result<Vec<u8>, aes_gcm::Error>`.
- [x] Map that `Result`'s `Err` to `PyResult`'s `Err` with
      `.map_err(|_| PyValueError::new_err("decryption failed"))` — don't leak
      the underlying crypto error details in the message (standard practice:
      auth failures shouldn't hint at *why* they failed).
- [ ] Note AES-GCM/ChaCha20-Poly1305 ciphertext already includes the auth tag
      appended — you don't manage that separately, the crate does it.
- [ ] Write a round-trip test (encrypt then decrypt gives back the original)
      and a tamper test (flip a byte in the ciphertext, decrypt must `Err`,
      not silently return garbage).

**Flag for later, don't fix now:** nonces here are fully random per-call
(`os.urandom(12)`), not a counter. Random 96-bit nonces have a birthday-bound
collision risk once you're encrypting billions of entries under the same key
— not a practical risk at this project's scale, but if you ever want to
close that gap, `XChaCha20Poly1305` (from the `chacha20poly1305` crate,
`XChaCha20Poly1305` type) uses a 192-bit nonce specifically so random
generation is safe at any volume. That needs `NONCE_SIZE` bumped to 24 in
`passlair/core/crypto.py` too, so it's a cross-repo decision — not something
to change unilaterally on the Rust side.

## 3. Key derivation — `derive_keys`

This is the password → (verification hash, KEK) step. It must be slow and
memory-hard (defends against offline brute-force if the DB leaks) — this is
*not* a place to use SHA-256 directly.

- [ ] Add the RustCrypto `argon2` crate: `cargo add argon2`. Use **Argon2id**
      (the crate's default variant) — it's the OWASP-recommended choice,
      resistant to both GPU-cracking and side-channel attacks.
- [ ] You need *two* 32-byte outputs from one (password, salt) pair. Simplest
      approach: Argon2's `hash_password_into` takes an output buffer of any
      length — ask for 64 bytes in one call, then split it: first 32 bytes =
      hash (stored, compared on login), last 32 = kek. Look at
      `Argon2::default().hash_password_into(password, salt, &mut output)`.
      (A more rigorous alternative some people use: derive one Argon2 output,
      then run it through HKDF-SHA256 twice with different `info` strings —
      `cargo add hkdf sha2` — to get domain-separated subkeys. Not required
      here; splitting one Argon2 output is standard practice and simpler.
      Your call.)
- [ ] Argon2's salt param in this crate often expects a specific wrapper type
      (`argon2::password_hash::Salt` in the high-level API) — you likely want
      the **low-level** `hash_password_into(pwd, salt: &[u8], out: &mut [u8])`
      API instead, since your salt is already a raw 16-byte value from
      Python, not something you're generating fresh here.
- [ ] Pick real parameters — don't leave the crate defaults unexamined.
      OWASP's current baseline is roughly: memory ≈ 19 MiB, iterations = 2,
      parallelism = 1 (minimum acceptable), or go higher (46 MiB+) if you
      want more margin and the server can afford it. `Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::new(m_cost, t_cost, p_cost, Some(output_len))?)`.
      Whatever you pick, write it down somewhere (comment or this file) —
      changing it later invalidates every stored hash.
- [ ] Determinism test: same `(password, salt)` in ⇒ byte-identical
      `(hash, kek)` out, every time — this is what login correctness depends
      on. Also test that a different password or different salt changes
      *both* outputs.

## 4. Memory hygiene (nice-to-have, not blocking)

- [ ] Consider `cargo add zeroize` and wrapping the raw `Vec<u8>` key
      material (DEK, KEK, Argon2 output buffer) so it's zeroed out when
      dropped instead of lingering in freed memory. Not critical for a first
      working version, but standard practice for anything touching key
      material in a language without a GC pass to worry about.

## 5. Error handling pass

- [ ] Every `Result` from `aes-gcm`/`chacha20poly1305`/`argon2` needs an
      explicit `.map_err(...)` into `PyErr` — don't `.unwrap()` or `.expect()`
      anywhere in these three functions. An `unwrap()` panic crossing the
      Python/Rust FFI boundary is UB with pyo3, not a catchable Python
      exception.

## 6. Once it's real: re-check the Python-side tests

Several integration tests currently assert on **nonces only** (not
ciphertext) with comments explaining this is because the crypto is mocked —
e.g. `tests/integration/core/interface/test_identity.py`
(`test_change_user_password`, `test_password_reset`) in the `passlair` repo.
Once real encryption lands here, go back and tighten those assertions (e.g.
`after.dek != before.dek` should actually hold now) — that's Python-side
follow-up, not part of this crate.
