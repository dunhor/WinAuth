
string(REPLACE "/" "\\" MIDL_INPUT ${CMAKE_CURRENT_SOURCE_DIR}/Microsoft.Security.Authentication.OAuth.idl)
set(MIDL_OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/Microsoft.Security.Authentication.OAuth.winmd)

add_custom_command(
    OUTPUT ${MIDL_OUTPUT}
    DEPENDS ${MIDL_INPUT}
    COMMAND
        midlrt /nomidl /nologo /metadata_dir "${WinSdkMetadataDir}" /header NUL ${MIDL_INPUT}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    VERBATIM)

add_custom_target(WinAuthApi ALL DEPENDS ${MIDL_OUTPUT})
