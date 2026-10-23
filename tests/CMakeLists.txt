# Unit tests (link the runtime directly) + integration tests that run the CLI
# against the example programs and assert the reported problem type.

# ---- unit tests -----------------------------------------------------------
add_executable(test_unit test_unit.c)
target_link_libraries(test_unit PRIVATE failstep::failstep)
target_compile_options(test_unit PRIVATE ${FAILSTEP_WARNINGS})
target_compile_definitions(test_unit PRIVATE FAILSTEP_PROJECT_VERSION="${PROJECT_VERSION}")
add_test(NAME unit COMMAND test_unit)

# ---- integration tests ----------------------------------------------------
find_package(Python3 COMPONENTS Interpreter)
if(NOT Python3_Interpreter_FOUND OR NOT FAILSTEP_BUILD_CLI OR NOT FAILSTEP_BUILD_EXAMPLES)
    message(STATUS "failstep: integration tests need Python3, the CLI and the examples")
    return()
endif()

set(EXPECT ${CMAKE_CURRENT_SOURCE_DIR}/expect.py)
set(CLI $<TARGET_FILE:failstep-cli>)
set(WD ${CMAKE_CURRENT_BINARY_DIR}/wd)

# fs_expect(<name> <mode> <problem|clean> <target-cmake-target> [TYPE t] [STEPS k]
#           [TIMEOUT s] [INFO_EXIT status [INFO_RUNS n]] [ARGS failstep-options...])
function(fs_expect name mode expect target)
    cmake_parse_arguments(E "" "TYPE;STEPS;TIMEOUT;INFO_EXIT;INFO_RUNS" "ARGS" ${ARGN})
    set(args --failstep ${CLI} --mode ${mode} --outdir ${WD}/${name} --expect ${expect})
    if(E_TYPE)
        list(APPEND args --type ${E_TYPE})
    endif()
    if(E_STEPS)
        list(APPEND args --steps ${E_STEPS})
    endif()
    if(E_TIMEOUT)
        list(APPEND args --timeout ${E_TIMEOUT})
    endif()
    if(DEFINED E_INFO_EXIT)
        list(APPEND args --info-exit ${E_INFO_EXIT})
    endif()
    if(E_INFO_RUNS)
        list(APPEND args --info-runs ${E_INFO_RUNS})
    endif()
    foreach(a ${E_ARGS})
        list(APPEND args "--arg=${a}")
    endforeach()
    add_test(NAME ${name}
        COMMAND ${Python3_EXECUTABLE} ${EXPECT} ${args} -- $<TARGET_FILE:${target}>)
endfunction()

# buggy examples: each must be reported with its category
fs_expect(null_check_bug sites problem ex_null_check TYPE null-deref)
fs_expect(hang_bug       sites problem ex_hang       TYPE hang TIMEOUT 3)
fs_expect(abort_bug      sites problem ex_abort_on_oom TYPE abnormal-exit)
fs_expect(server_bug     continue problem ex_server   TYPE asan-error STEPS 2)

# LeakSanitizer ships with AddressSanitizer only on Linux (not on Apple, not in
# MSVC's ASan), so the leak example is checked there.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    fs_expect(leak_bug enumerate problem ex_leak TYPE leak)
endif()

# fixed examples: each must come back clean
fs_expect(null_check_ok sites    clean ex_null_check_ok)
fs_expect(leak_ok       enumerate clean ex_leak_ok)
fs_expect(hang_ok       sites    clean ex_hang_ok TIMEOUT 3)
fs_expect(abort_ok      sites    clean ex_abort_on_oom_ok)
fs_expect(server_ok     continue clean ex_server_ok STEPS 2)

# orderly exits: stopping with an error status when memory runs out is not a
# bug. By default those runs are info only; --ok-exit / --strict-exit turn an
# unexpected status into a problem.
fs_expect(exit_clean      enumerate clean   ex_exit_on_oom INFO_EXIT 1 INFO_RUNS 2)
fs_expect(exit_ok_listed  enumerate clean   ex_exit_on_oom INFO_EXIT 1 ARGS --ok-exit 1,2)
fs_expect(exit_unexpected enumerate problem ex_exit_on_oom TYPE abnormal-exit ARGS --ok-exit 2)
fs_expect(exit_strict     enumerate problem ex_exit_on_oom TYPE abnormal-exit ARGS --strict-exit)
# a crash by signal stays a problem whatever exit statuses are declared expected
fs_expect(abort_ok_exit   sites     problem ex_abort_on_oom TYPE abnormal-exit ARGS --ok-exit 6,134)

# fuzz integration (Clang + libFuzzer)
if(FAILSTEP_BUILD_FUZZERS)
    # Deterministic replay of a known crashing input.
    add_test(NAME fuzz_crash
        COMMAND ${Python3_EXECUTABLE} ${EXPECT}
            --failstep ${CLI} --mode fuzz --outdir ${WD}/fuzz --expect problem --type null-deref
            -- $<TARGET_FILE:ex_fuzz> ${CMAKE_CURRENT_SOURCE_DIR}/fuzz_crash.bin)
    # A real fuzzing run: libFuzzer, steering which allocations fail, must find
    # the planted missing NULL check on its own (fixed seed, bounded runs).
    add_test(NAME fuzz_discover
        COMMAND ${Python3_EXECUTABLE} ${EXPECT}
            --failstep ${CLI} --mode fuzz --outdir ${WD}/fuzz_discover --expect problem --type null-deref
            -- $<TARGET_FILE:ex_fuzz> -seed=1 -runs=500000 -max_len=64
               -artifact_prefix=${WD}/fuzz_discover/)
endif()
