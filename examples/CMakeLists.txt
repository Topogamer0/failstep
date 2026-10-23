# Example programs: one intentionally buggy per problem category, each with a
# corrected version that failstep must report clean. Every example is built
# under the failstep override header and AddressSanitizer.

set(FAILSTEP_SIMPLE null_check leak hang abort_on_oom)

foreach(e ${FAILSTEP_SIMPLE})
    add_executable(ex_${e} ${e}.c)
    failstep_instrument(ex_${e})

    add_executable(ex_${e}_ok ${e}_ok.c)
    failstep_instrument(ex_${e}_ok)
endforeach()

# Correct handling that exits with an error status when memory runs out: must
# give zero problems by default (the runs are listed as info).
add_executable(ex_exit_on_oom exit_on_oom.c)
failstep_instrument(ex_exit_on_oom)

# The PHP2Shell-style long-lived server (continue mode).
add_executable(ex_server server_bug.c)
failstep_instrument(ex_server)

add_executable(ex_server_ok server_ok.c)
failstep_instrument(ex_server_ok)

# libFuzzer target (Clang only). -fsanitize=fuzzer is added on top of the
# address sanitizer that failstep_instrument already applies.
if(FAILSTEP_BUILD_FUZZERS)
    if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "FAILSTEP_BUILD_FUZZERS requires Clang")
    endif()
    add_executable(ex_fuzz fuzz_parse.c)
    failstep_instrument(ex_fuzz)
    target_compile_options(ex_fuzz PRIVATE -fsanitize=fuzzer)
    target_link_options(ex_fuzz PRIVATE -fsanitize=fuzzer)
endif()
