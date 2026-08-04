# passlair-crypto: implementation TODO

Three `pybind11` functions in `src/lib.cpp` are currently mocked and need
real implementations. This doc is a checklist + hints, not code — you're
doing the C++ yourself.

## The contract (don't break this — passlair (Python) already calls these)

```cpp
py::bytes encrypt_password(py::bytes password, py::bytes nonce, py::bytes dek);
py::bytes decrypt_password(py::bytes encrypted_password, py::bytes nonce, py::bytes dek);
std::pair<py::bytes, py::bytes> derive_keys(py::bytes password, py::bytes salt);
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
- **Always use `py::bytes`, never `std::string`, for these parameters and
  return values.** pybind11's default `std::string` caster round-trips
  through Python `str` (UTF-8 text) and will throw on arbitrary binary data
  — a hash byte like `0xFF` isn't valid UTF-8. `py::bytes` maps directly to
  Python's `bytes` type with no encoding step. The mock already does this;
  keep doing it as you replace the bodies.
- On bad input (auth tag fails to verify, etc.), **throw**, don't abort or
  return garbage. pybind11 automatically translates C++ exceptions deriving
  from `std::exception` into Python exceptions at the FFI boundary — throw
  `std::invalid_argument`/`std::runtime_error` and it surfaces as a catchable
  Python exception. What you must never let happen is UB reaching that
  boundary: an out-of-bounds read/write, a use-after-free, or reading
  uninitialized memory won't throw anything catchable, it's just corruption
  or a crash. C++ gives zero automatic protection here, unlike a
  `panic = "abort"`-style guard — bounds/lifetime discipline is entirely on
  you.

## 1. Tooling / getting oriented

- [ ] Build: `cmake -S . -B build && cmake --build build -j`. First
      configure needs `pybind11` resolvable as a CMake package — it's
      declared in `pyproject.toml`'s `[build-system] requires`, so if
      you're building standalone (not via `uv sync`), `pip install
      pybind11` into your active environment first so
      `find_package(pybind11 CONFIG REQUIRED)` can find it.
- [ ] Install the built extension into `python/passlair_crypto/` for local
      dev (mirrors what `maturin develop` used to do):
      `cmake --install build --prefix python`.
- [ ] Confirm it imports: `uv run python -c "from passlair_crypto.package
      import encrypt_password; print(encrypt_password(b'hi', b'0'*12,
      b'1'*32))"` should print `b'encrypted-hi'`.
- [ ] Run the tests: `uv run --group test pytest tests/`.
- [ ] If you're new to C++: this project deliberately avoids raw
      `new`/`delete` and raw pointers — stick to `std::string`,
      `std::vector`, and RAII wrapper types throughout. If a library's C API
      forces a raw buffer on you (likely, for the crypto libs below), wrap
      it immediately in a `std::vector<unsigned char>` and never let the
      raw pointer outlive that scope.
- [ ] Skim pybind11's guide on
      [functions](https://pybind11.readthedocs.io/en/stable/basics.html)
      and [binary data](https://pybind11.readthedocs.io/en/stable/advanced/pycpp/utilities.html#bytes)
      — the second link is the `py::bytes` gotcha above, straight from the
      source.

## 2. AEAD encryption — `encrypt_password` / `decrypt_password`

You need an authenticated cipher (confidentiality + tamper detection), keyed
by the 32-byte DEK, using the given 12-byte nonce.

- [ ] Pick a library. Two reasonable choices:
      - **OpenSSL's EVP AEAD API** (`EVP_aes_256_gcm()` via
        `EVP_EncryptInit_ex`/`EVP_EncryptUpdate`/`EVP_EncryptFinal_ex` +
        `EVP_CIPHER_CTX_ctrl` for the tag) — the "boring/standard" choice.
        Lower-level, more ceremony; budget more time here.
      - **libsodium** (`crypto_aead_aes256gcm_encrypt`/`_decrypt`, or
        `crypto_aead_chacha20poly1305_ietf_*` for the non-AES option) —
        one function call per direction, tag handling built in. Easier to
        get right.
- [ ] Either way, the auth tag is appended to the ciphertext by the
      high-level API — you don't need to concatenate it yourself.
- [ ] On decrypt failure (bad tag), the C API returns an error code, not an
      exception — check it explicitly and `throw` (see contract section
      above). Don't let a failed decrypt fall through and return whatever
      garbage ended up in the output buffer.
- [ ] Write a round-trip test (encrypt then decrypt gives back the
      original) and a tamper test (flip a byte in the ciphertext, decrypt
      must throw, not silently return garbage) in `tests/`.

**Flag for later, don't fix now:** nonces here are fully random per-call
(`os.urandom(12)`), not a counter. Random 96-bit nonces have a birthday-bound
collision risk once you're encrypting billions of entries under the same key
— not a practical risk at this project's scale, but if it's ever addressed,
switching to a 192-bit nonce (e.g. `XChaCha20-Poly1305`, which libsodium and
OpenSSL 3.2+ both support) needs `NONCE_SIZE` bumped to 24 in
`passlair/core/crypto.py` too — a cross-repo decision, not something to
change unilaterally here.

## 3. Key derivation — `derive_keys`

This is the password → (verification hash, KEK) step. It must be slow and
memory-hard (defends against offline brute-force if the DB leaks) — this is
*not* a place to use SHA-256 directly.

- [ ] Use **Argon2id** via either libsodium's `crypto_pwhash_argon2id` (no
      new dependency if you already picked libsodium above) or the
      reference [phc-winner-argon2](https://github.com/P-H-C/phc-winner-argon2)
      C library directly.
- [ ] You need *two* 32-byte outputs from one (password, salt) pair.
      Simplest approach: ask for 64 output bytes in one call, then split —
      first 32 bytes = hash (stored, compared on login), last 32 = kek.
      Both libraries let you specify an arbitrary output length.
- [ ] Pick real parameters — don't leave library defaults unexamined.
      OWASP's current baseline is roughly: memory ≈ 19 MiB, iterations = 2,
      parallelism = 1 (minimum acceptable), or go higher (46 MiB+) for more
      margin. Write down whatever you pick (comment or this file) — changing
      it later invalidates every stored hash.
- [ ] Determinism test: same `(password, salt)` in ⇒ byte-identical
      `(hash, kek)` out, every time — this is what login correctness
      depends on. Also test that a different password or different salt
      changes *both* outputs.

## 4. Memory hygiene (nice-to-have, not blocking)

- [ ] `std::string`/`std::vector` do **not** zero their buffers on
      destruction — freed key material can linger in memory. Use
      `OPENSSL_cleanse()` (if using OpenSSL) or `sodium_memzero()` (if using
      libsodium) on any buffer holding a DEK, KEK, or Argon2 output before
      it goes out of scope. Nothing does this automatically for you — call
      it explicitly at every exit path, including exception paths (a small
      RAII wrapper whose destructor calls the cleanse function is the
      standard way to make that automatic instead of hoping every return
      path remembers).

## 5. Error handling pass

- [ ] Every crypto library call that can fail needs its return code checked
      and turned into a `throw`, not ignored. No bare `assert()` for
      anything reachable with attacker-controlled input — `assert` compiles
      to nothing in release builds (`NDEBUG`), so a check that only exists
      as an `assert` silently disappears in the build your users run.
- [ ] Compile with warnings-as-errors once the mocks are replaced
      (`-Wall -Wextra -Werror` at minimum) — C++ will let a lot of
      footguns (implicit narrowing conversions, uninitialized reads)
      through silently otherwise.

## 6. Once it's real: re-check the Python-side tests

Several integration tests currently assert on **nonces only** (not
ciphertext) with comments explaining this is because the crypto is mocked —
e.g. `tests/integration/core/interface/test_identity.py`
(`test_change_user_password`, `test_password_reset`) in the `passlair` repo.
Once real encryption lands here, go back and tighten those assertions (e.g.
`after.dek != before.dek` should actually hold now) — that's Python-side
follow-up, not part of this repo.
