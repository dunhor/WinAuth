cmake_minimum_required(VERSION 3.22)
project(WinAuth)

string(REGEX REPLACE "\\\\$" "" WinSdkVersion "$ENV{WindowsSDKVersion}")

set(WinSdkMetadataDir "$ENV{WindowsSdkDir}UnionMetadata\\${WinSdkVersion}")
set(WinSdkRefDir "$ENV{WindowsSdkDir}References\\${WinSdkVersion}")

# Download the cppwinrt nuget
if (NOT DEFINED CPPWINRT_VERSION)
    set(CPPWINRT_VERSION "2.0.220608.4")
endif()

find_program(NUGET nuget)
if (NOT NUGET)
    message(FATAL_ERROR "Unable to find the nuget CLI tool. Please install it from https://www.nuget.org/downloads and ensure it has been added to the PATH")
endif()

execute_process(COMMAND
    ${NUGET} install Microsoft.Windows.CppWinRT -Version ${CPPWINRT_VERSION} -OutputDirectory packages
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    RESULT_VARIABLE ret)
if (NOT ret EQUAL 0)
    message(FATAL_ERROR "Failed to install nuget package Microsoft.Windows.CppWinRT.${CPPWINRT_VERSION}")
endif()

set(CPPWINRT ${CMAKE_BINARY_DIR}/packages/Microsoft.Windows.CppWinRT.${CPPWINRT_VERSION}/bin/cppwinrt.exe)

add_subdirectory(library)

# Custom target for running clang-format
add_custom_target(format
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
    COMMAND scripts/run-clang-format.cmd)
