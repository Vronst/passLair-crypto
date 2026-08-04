# C++ unit tests

Pure-C++ tests for the crypto logic in `src/lib.cpp` — independent of the
Python bindings, analogous to what `cargo test` was for the old Rust crate.
`tests/test_package.py` (pytest) covers the Python-facing contract; this
directory is for testing internal C++ helpers directly (e.g. the AEAD/Argon2
wrapper functions from `TODO.md`, before they're wired up to `py::bytes`).

Empty for now — `CMakeLists.txt` here is a no-op until you add a `.cpp`
file. Uses [doctest](https://github.com/doctest/doctest) (fetched
automatically, header-only, no separate install needed).

## Adding your first test

```cpp
// tests/cpp/test_aead.cpp
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

TEST_CASE("placeholder") {
    CHECK(1 + 1 == 2);
}
```

Only one `.cpp` file in this test binary should define
`DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN` (it generates `main()`) — every other
test file just `#include <doctest/doctest.h>` and adds `TEST_CASE`s.

## Build and run

```sh
cmake -S . -B build-cpp-tests -DPASSLAIR_CRYPTO_BUILD_TESTS=ON
cmake --build build-cpp-tests -j
ctest --test-dir build-cpp-tests --output-on-failure
```

CI (`.github/workflows/CiCd.yml`) runs this automatically once it detects
any `.cpp` file here.
