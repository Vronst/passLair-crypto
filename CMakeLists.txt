cmake_minimum_required(VERSION 3.15)
project(passlair_crypto LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release)
endif()

find_package(pybind11 CONFIG REQUIRED)

pybind11_add_module(package src/lib.cpp)

install(TARGETS package DESTINATION passlair_crypto)

# Pure-C++ unit tests (independent of the Python bindings), analogous to
# `cargo test` on the old Rust side. Off by default so `uv sync`/wheel builds
# never need a test framework -- enable explicitly with
# -DPASSLAIR_CRYPTO_BUILD_TESTS=ON. See tests/cpp/README.md.
option(PASSLAIR_CRYPTO_BUILD_TESTS "Build C++ unit tests in tests/cpp/" OFF)
if(PASSLAIR_CRYPTO_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests/cpp)
endif()
