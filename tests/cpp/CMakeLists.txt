file(GLOB CPP_TEST_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")

if(CPP_TEST_SOURCES)
  include(FetchContent)
  FetchContent_Declare(
    doctest
    GIT_REPOSITORY https://github.com/doctest/doctest.git
    GIT_TAG v2.4.11
  )
  FetchContent_MakeAvailable(doctest)

  add_executable(cpp_tests ${CPP_TEST_SOURCES})
  target_link_libraries(cpp_tests PRIVATE doctest::doctest)
  target_include_directories(cpp_tests PRIVATE ${CMAKE_SOURCE_DIR}/src)

  include(${doctest_SOURCE_DIR}/scripts/cmake/doctest.cmake)
  doctest_discover_tests(cpp_tests)
else()
  message(STATUS "tests/cpp/: no .cpp files yet -- skipping cpp_tests target")
endif()
