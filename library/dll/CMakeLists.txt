
# Generate C++/WinRT headers
set(CPPWINRT_OUTPUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/Generated Files")
set(CPPWINRT_COMPONENT_INPUT ${CMAKE_CURRENT_BINARY_DIR}/../idl/Microsoft.Security.Authentication.OAuth.winmd)
set(CPPWINRT_SDK_OUTPUT "${CPPWINRT_OUTPUT_DIR}/winrt/base.h")
set(CPPWINRT_COMPONENT_OUTPUT "${CPPWINRT_OUTPUT_DIR}/module.g.cpp")

add_custom_command(
    OUTPUT "${CPPWINRT_SDK_OUTPUT}" "${CPPWINRT_COMPONENT_OUTPUT}"
    DEPENDS "${CPPWINRT_COMPONENT_INPUT}"
    COMMAND
        ${CPPWINRT} -in "${WinSdkMetadataDir}" -out "${CPPWINRT_OUTPUT_DIR}" -brackets -overwrite -verbose
    COMMAND
        ${CPPWINRT} -in "${CPPWINRT_COMPONENT_INPUT}" -ref "${WinSdkMetadataDir}" -comp "${CPPWINRT_OUTPUT_DIR}" -out "${CPPWINRT_OUTPUT_DIR}" -brackets -overwrite -opt -verbose
    )
add_custom_target(CppWinRT-Api ALL DEPENDS "${CPPWINRT_SDK_OUTPUT}" "${CPPWINRT_COMPONENT_OUTPUT}")

add_library(Microsoft.Security.Authentication.OAuth SHARED)
add_dependencies(Microsoft.Security.Authentication.OAuth CppWinRT-Api)

target_compile_features(Microsoft.Security.Authentication.OAuth PRIVATE cxx_std_20)

target_compile_definitions(Microsoft.Security.Authentication.OAuth PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)

if (${CMAKE_CXX_COMPILER_ID} STREQUAL "Clang")
    # Enable use of _InterlockedCompareExchange128
    target_compile_options(Microsoft.Security.Authentication.OAuth PRIVATE -mcx16)
endif()

target_include_directories(Microsoft.Security.Authentication.OAuth PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${CPPWINRT_OUTPUT_DIR}")

target_precompile_headers(Microsoft.Security.Authentication.OAuth PRIVATE pch.h)

target_sources(Microsoft.Security.Authentication.OAuth PRIVATE
    "${CPPWINRT_COMPONENT_OUTPUT}"
    AuthManager.cpp
    AuthRequestParams.cpp)
