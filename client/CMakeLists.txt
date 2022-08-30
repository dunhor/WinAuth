
# Generate C++/WinRT headers
set(CPPWINRT_OUTPUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/Generated Files")
set(CPPWINRT_LIBRARY_INPUT ${CMAKE_CURRENT_BINARY_DIR}/../library/idl/Microsoft.Security.Authentication.OAuth.winmd)
set(CPPWINRT_OUTPUT "${CPPWINRT_OUTPUT_DIR}/winrt/base.h")

add_custom_command(
    OUTPUT "${CPPWINRT_OUTPUT}"
    DEPENDS "${CPPWINRT_LIBRARY_INPUT}"
    COMMAND
        ${CPPWINRT} -in "${WinSdkMetadataDir}" "${CPPWINRT_LIBRARY_INPUT}" -out "${CPPWINRT_OUTPUT_DIR}" -brackets -overwrite -verbose
    )
add_custom_target(CppWinRT-Client ALL DEPENDS "${CPPWINRT_OUTPUT}")

add_executable(client)
add_dependencies(client CppWinRT-Client)

target_compile_features(client PRIVATE cxx_std_20)

target_compile_definitions(client PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)

if (${CMAKE_CXX_COMPILER_ID} STREQUAL "Clang")
    # Enable use of _InterlockedCompareExchange128
    target_compile_options(client PRIVATE -mcx16)
endif()

target_include_directories(client PRIVATE
    "${CPPWINRT_OUTPUT_DIR}")

target_sources(client PRIVATE
    main.cpp)
