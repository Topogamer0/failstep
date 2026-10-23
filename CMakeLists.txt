cmake_minimum_required(VERSION 3.14)
project(failstep
    VERSION 0.1.1
    DESCRIPTION "Systematic allocation-failure testing for C, compatible with AddressSanitizer"
    LANGUAGES C)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

# ---- options --------------------------------------------------------------
option(FAILSTEP_BUILD_CLI "Build the failstep command-line tool" ON)
option(FAILSTEP_BUILD_EXAMPLES "Build the example programs" ON)
option(FAILSTEP_BUILD_TESTS "Build the tests" ON)
option(FAILSTEP_WERROR "Treat warnings in failstep's own code as errors" OFF)
option(BUILD_SHARED_LIBS "Build the runtime as a shared library" OFF)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "" FORCE)
endif()

# Warning flags used for failstep's own code (library, CLI, tests).
if(MSVC)
    set(FAILSTEP_WARNINGS /W4)
    if(FAILSTEP_WERROR)
        list(APPEND FAILSTEP_WARNINGS /WX)
    endif()
    # getenv/fopen/fscanf are used deliberately and portably; silence the
    # "consider using *_s" deprecations (C4996) for this project's own code.
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
else()
    set(FAILSTEP_WARNINGS -Wall -Wextra -pedantic)
    if(FAILSTEP_WERROR)
        list(APPEND FAILSTEP_WARNINGS -Werror)
    endif()
endif()

# ---- runtime library ------------------------------------------------------
# wrap.c provides the --wrap interceptors (GNU ld / lld only). It is excluded on
# Windows (no --wrap) and on Apple, whose linker rejects the undefined __real_*
# symbols when building a shared library and which has no --wrap anyway.
set(FAILSTEP_SOURCES src/runtime.c src/site.c)
if(NOT WIN32 AND NOT APPLE)
    list(APPEND FAILSTEP_SOURCES src/wrap.c)
endif()

add_library(failstep ${FAILSTEP_SOURCES})
add_library(failstep::failstep ALIAS failstep)
target_include_directories(failstep PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_include_directories(failstep PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_options(failstep PRIVATE ${FAILSTEP_WARNINGS})
set_target_properties(failstep PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    POSITION_INDEPENDENT_CODE ON)

if(BUILD_SHARED_LIBS AND WIN32)
    target_compile_definitions(failstep PRIVATE FAILSTEP_BUILDING_SHARED
        INTERFACE FAILSTEP_SHARED)
endif()

# backtrace + dladdr + pthread on POSIX
if(NOT WIN32)
    find_package(Threads REQUIRED)
    target_link_libraries(failstep PUBLIC Threads::Threads ${CMAKE_DL_LIBS})
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        # execinfo is in libc on glibc; nothing extra needed.
    endif()
endif()

# ---- helper for instrumenting a target ------------------------------------
# Applies the force-include override header and (optionally) AddressSanitizer to
# `target`, and links the failstep runtime. Used by the examples and tests, and
# installed so downstream projects can call it too.
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/FailstepHelpers.cmake)

# ---- CLI ------------------------------------------------------------------
if(FAILSTEP_BUILD_CLI)
    add_executable(failstep-cli cli/main.c cli/proc.c cli/analyze.c cli/report.c cli/util.c)
    set_target_properties(failstep-cli PROPERTIES OUTPUT_NAME failstep)
    target_include_directories(failstep-cli PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/cli ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_compile_options(failstep-cli PRIVATE ${FAILSTEP_WARNINGS})
    install(TARGETS failstep-cli RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

# ---- examples & tests -----------------------------------------------------
if(FAILSTEP_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

if(FAILSTEP_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# ---- install --------------------------------------------------------------
install(TARGETS failstep EXPORT failstep-targets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(DIRECTORY include/failstep DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(EXPORT failstep-targets
    NAMESPACE failstep::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/failstep)

configure_package_config_file(
    cmake/failstep-config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/failstep-config.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/failstep)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/failstep-config-version.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion)
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/failstep-config.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/failstep-config-version.cmake
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/FailstepHelpers.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/failstep)

# pkg-config
set(FAILSTEP_PC_LIBS "")
if(NOT WIN32)
    set(FAILSTEP_PC_LIBS "-lpthread -ldl")
endif()
configure_file(failstep.pc.in ${CMAKE_CURRENT_BINARY_DIR}/failstep.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/failstep.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
