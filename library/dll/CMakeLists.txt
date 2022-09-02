
set(API_NAME Microsoft.Security.Authentication.OAuth)

# Generate C++/WinRT headers
set(CPPWINRT_OUTPUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/Generated Files")
set(CPPWINRT_COMPONENT_INPUT ${CMAKE_CURRENT_BINARY_DIR}/../idl/${API_NAME}.winmd)
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

add_library(${API_NAME} SHARED)
add_dependencies(${API_NAME} CppWinRT-Api)

target_compile_features(${API_NAME} PRIVATE cxx_std_20)

target_compile_definitions(${API_NAME} PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)

if (${CMAKE_CXX_COMPILER_ID} STREQUAL "Clang")
    # Enable use of _InterlockedCompareExchange128
    target_compile_options(${API_NAME} PRIVATE -mcx16)
endif()

target_include_directories(${API_NAME} PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${CPPWINRT_OUTPUT_DIR}")

target_precompile_headers(${API_NAME} PRIVATE pch.h)

target_sources(${API_NAME} PRIVATE
    AuthFailure.cpp
    AuthManager.cpp
    AuthRequestAsyncOperation.cpp
    AuthRequestParams.cpp
    AuthRequestResult.cpp
    AuthResponse.cpp
    module.cpp
    ${API_NAME}.def)

string(REPLACE "/" "\\" COPY_OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/../../client/${API_NAME}.dll)

add_custom_command(
    OUTPUT "${COPY_OUTPUT}"
    DEPENDS "${API_NAME}.dll"
    COMMAND
        copy "${API_NAME}.dll" "${COPY_OUTPUT}"
    )

add_custom_target(CopyWinAuthApi ALL DEPENDS "${COPY_OUTPUT}")
