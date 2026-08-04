# passlair-crypto

AEAD encrypt/decrypt and Argon2id key derivation, exposed to Python
(`passlair`) as `passlair_crypto.package` via a pybind11 extension module.
Currently mocked — see `TODO.md` for the implementation checklist.

## Build (local dev)

Requires `cmake` (>= 3.15) and a C++17 compiler. `pybind11` is resolved as a
build dependency automatically when building through `uv`/`pip`; for a
standalone CMake configure outside that flow, `pip install pybind11` into
your active environment first.

```sh
cmake -S . -B build
cmake --build build -j
cmake --install build --prefix python   # places package.*.so in python/passlair_crypto/, like `maturin develop` used to
```

## Try it / test it

```sh
uv run python -c "
from passlair_crypto.package import encrypt_password
print(encrypt_password(b'hi', b'0' * 12, b'1' * 32))
"
# -> b'encrypted-hi'

uv run --group test pytest tests/
```
