# netsentinel_embed_shader(<source.metal> <VAR_NAME> <output_header_path>)
#
# Registers a build-time (not configure-time) step that regenerates the
# header whenever the .metal source changes, so editing a shader and
# rebuilding is enough — no manual re-run of `cmake` needed.
function(netsentinel_embed_shader SRC_FILE VAR_NAME OUT_FILE)
  add_custom_command(
    OUTPUT "${OUT_FILE}"
    COMMAND "${CMAKE_COMMAND}"
            "-DIN_FILE=${SRC_FILE}"
            "-DVAR_NAME=${VAR_NAME}"
            "-DOUT_FILE=${OUT_FILE}"
            -P "${CMAKE_SOURCE_DIR}/cmake/EmbedShader.cmake"
    DEPENDS "${SRC_FILE}" "${CMAKE_SOURCE_DIR}/cmake/EmbedShader.cmake"
    COMMENT "Embedding shader ${SRC_FILE}"
    VERBATIM
  )
endfunction()
