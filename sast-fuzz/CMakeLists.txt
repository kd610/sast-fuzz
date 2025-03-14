include("${CMAKE_SOURCE_DIR}/cmake/find_llvm.cmake")

include("${CMAKE_SOURCE_DIR}/cmake/find_svf.cmake")

add_library(afl_config INTERFACE)

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(
        afl_config
        INTERFACE -g
                  -O0
                  -Wall
                  -Wno-pointer-sign
    )
else ()
    target_compile_options(
        afl_config
        INTERFACE -funroll-loops
                  -O3
                  -Wall
                  -Wno-pointer-sign
    )
endif ()

target_compile_definitions(
    afl_config
    INTERFACE _FORTIFY_SOURCE=2
              AFL_PATH=\"${CMAKE_INSTALL_PREFIX}/lib/afl\"
              BIN_PATH=\"${CMAKE_INSTALL_PREFIX}/bin\"
              DOC_PATH=\"${CMAKE_INSTALL_PREFIX}/share/doc/afl\"
)
target_link_libraries(afl_config INTERFACE ${CMAKE_DL_LIBS} m)

add_subdirectory(fuzzing)
add_subdirectory(code_instrumentation)
add_subdirectory(static_analysis)
add_subdirectory(utils)
