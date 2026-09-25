# Run in script mode (`cmake -P`) by the add_custom_command in
# cmake/NetsentinelShaders.cmake. Turns a .metal source file into a
# generated C++ header holding its text as a raw string constant, so the
# shader ships as one file (edited normally, with real MSL syntax
# highlighting) instead of being duplicated by hand inside C++ source.
#
# Expects -DIN_FILE=... -DVAR_NAME=... -DOUT_FILE=... on the command line.

if(NOT DEFINED IN_FILE OR NOT DEFINED VAR_NAME OR NOT DEFINED OUT_FILE)
  message(FATAL_ERROR "EmbedShader.cmake requires IN_FILE, VAR_NAME, and OUT_FILE")
endif()

file(READ "${IN_FILE}" shader_contents)

file(WRITE "${OUT_FILE}"
"// Generated from ${IN_FILE} by cmake/EmbedShader.cmake — do not edit directly.
#pragma once

namespace netsentinel::gpu {

constexpr const char* ${VAR_NAME} = R\"NS_SHADER(
${shader_contents}
)NS_SHADER\";

}  // namespace netsentinel::gpu
")
