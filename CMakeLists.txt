cmake_minimum_required(VERSION 3.20)

project(vigil_ids LANGUAGES NONE)

find_program(CARGO_EXECUTABLE cargo)

set(VIGIL_BINARY_DIR "${CMAKE_BINARY_DIR}/cargo")

if(CARGO_EXECUTABLE)
  add_custom_command(
    OUTPUT "${VIGIL_BINARY_DIR}/release/vigil-ids"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${VIGIL_BINARY_DIR}"
    COMMAND "${CARGO_EXECUTABLE}" build --release
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    COMMENT "Building Vigil IDS with Cargo"
    VERBATIM
  )

  add_custom_target(vigil_ids_build ALL
    DEPENDS "${VIGIL_BINARY_DIR}/release/vigil-ids"
  )
else()
  message(STATUS "Cargo not found; configuring a placeholder build target only")

  add_custom_target(vigil_ids_build ALL
    COMMAND "${CMAKE_COMMAND}" -E echo "Cargo is required to build Vigil IDS"
    VERBATIM
  )
endif()
