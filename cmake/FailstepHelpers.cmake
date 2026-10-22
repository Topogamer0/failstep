# FailstepHelpers.cmake -- helpers for building targets under failstep.
#
# failstep_instrument(<target> [NO_ASAN] [WRAP])
#
#   Routes <target>'s allocation calls through the failstep runtime and links
#   it. By default the target is also built with AddressSanitizer, so ASan stays
#   the underlying allocator and catches the corruption failstep provokes.
#
#   NO_ASAN   do not add AddressSanitizer (e.g. when another sanitizer is used,
#             or to measure plain NULL-dereference crashes).
#   WRAP      on GNU/Clang linkers, also divert the libc allocators with
#             -Wl,--wrap (for objects not compiled with the override header).

function(failstep_instrument target)
    cmake_parse_arguments(FI "NO_ASAN;WRAP" "" "" ${ARGN})

    get_target_property(_src_dir failstep SOURCE_DIR)
    if(NOT _src_dir)
        set(_src_dir "${CMAKE_CURRENT_LIST_DIR}/../../..")
    endif()

    target_link_libraries(${target} PRIVATE failstep::failstep)

    # Force-include the override header.
    if(MSVC)
        target_compile_options(${target} PRIVATE /FIfailstep/override.h)
    else()
        target_compile_options(${target} PRIVATE -include failstep/override.h)
    endif()

    # AddressSanitizer (optional).
    if(NOT FI_NO_ASAN)
        if(MSVC)
            target_compile_options(${target} PRIVATE /fsanitize=address /Zi)
        else()
            target_compile_options(${target} PRIVATE -fsanitize=address -g -fno-omit-frame-pointer)
            target_link_options(${target} PRIVATE -fsanitize=address)
        endif()
    else()
        if(NOT MSVC)
            target_compile_options(${target} PRIVATE -g -fno-omit-frame-pointer)
        endif()
    endif()

    # --wrap mode (GNU ld / lld only).
    if(FI_WRAP AND NOT MSVC AND NOT APPLE)
        target_link_options(${target} PRIVATE
            -Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc,--wrap=free
            -Wl,--wrap=strdup,--wrap=strndup,--wrap=aligned_alloc)
    endif()
endfunction()
