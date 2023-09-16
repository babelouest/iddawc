#
# Iddawc library
#
# CMake file used to build all programs
#
# Copyright 2018 Silvio Clecio <silvioprog@gmail.com>
# Copyright 2019-2023 Nicolas Mora <mail@babelouest.org>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the MIT License
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#

cmake_minimum_required(VERSION 3.5)

project(iddawc C)

set(CMAKE_C_STANDARD 99)
if (NOT MSVC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror")
endif()

# library info

set(IDDAWC_LIBS )

set(PROJECT_DESCRIPTION "OAuth2/OIDC Client and RP library")
set(PROJECT_HOMEPAGE_URL "https://github.com/babelouest/iddawc/")
set(PROJECT_BUGREPORT_PATH "https://github.com/babelouest/iddawc/issues")
set(LIBRARY_VERSION_MAJOR "1")
set(LIBRARY_VERSION_MINOR "1")
set(LIBRARY_VERSION_PATCH "9")
set(ORCANIA_VERSION_REQUIRED "2.3.3")
set(YDER_VERSION_REQUIRED "1.4.20")
set(ULFIUS_VERSION_REQUIRED "2.7.14")
set(RHONABWY_VERSION_REQUIRED "1.1.12")

set(PROJECT_VERSION "${LIBRARY_VERSION_MAJOR}.${LIBRARY_VERSION_MINOR}.${LIBRARY_VERSION_PATCH}")
set(PROJECT_VERSION_MAJOR ${LIBRARY_VERSION_MAJOR})
set(PROJECT_VERSION_MINOR ${LIBRARY_VERSION_MINOR})
set(PROJECT_VERSION_PATCH ${LIBRARY_VERSION_PATCH})

if (${LIBRARY_VERSION_MAJOR} VERSION_LESS 10)
    set (LIBRARY_VERSION_MAJOR_PAD "0${LIBRARY_VERSION_MAJOR}")
else ()
    set (LIBRARY_VERSION_MAJOR_PAD "${LIBRARY_VERSION_MAJOR}")
endif ()
if (${LIBRARY_VERSION_MINOR} VERSION_LESS 10)
    set (LIBRARY_VERSION_MINOR_PAD "0${LIBRARY_VERSION_MINOR}")
else ()
    set (LIBRARY_VERSION_MINOR_PAD "${LIBRARY_VERSION_MINOR}")
endif ()
if (${LIBRARY_VERSION_PATCH} VERSION_LESS 10)
    set (LIBRARY_VERSION_PATCH_PAD "0${LIBRARY_VERSION_PATCH}")
else ()
    set (LIBRARY_VERSION_PATCH_PAD "${LIBRARY_VERSION_PATCH}")
endif ()
set(PROJECT_VERSION_NUMBER "${LIBRARY_VERSION_MAJOR_PAD}${LIBRARY_VERSION_MINOR_PAD}${LIBRARY_VERSION_PATCH_PAD}")

set(LIBRARY_VERSION "${LIBRARY_VERSION_MAJOR}.${LIBRARY_VERSION_MINOR}.${LIBRARY_VERSION_PATCH}")
set(LIBRARY_SOVERSION "${LIBRARY_VERSION_MAJOR}.${LIBRARY_VERSION_MINOR}")

# cmake modules

set(I_CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake-modules)
list(APPEND CMAKE_MODULE_PATH "${I_CMAKE_MODULE_PATH}")

set(IDWCC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/tools/idwcc)

include(GNUInstallDirs)
include(CheckSymbolExists)
include(CMakeDependentOption)
include(CMakePackageConfigHelpers)

# check if _GNU_SOURCE is available

if (NOT _GNU_SOURCE)
    check_symbol_exists(__GNU_LIBRARY__ "features.h" _GNU_SOURCE)

    if (NOT _GNU_SOURCE)
        unset(_GNU_SOURCE CACHE)
        check_symbol_exists(_GNU_SOURCE "features.h" _GNU_SOURCE)
    endif ()
endif ()

if (_GNU_SOURCE)
    add_definitions(-D_GNU_SOURCE)
endif ()

# directories and source

set(INC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)

include_directories(${INC_DIR})

set(LIB_SRC
        ${INC_DIR}/iddawc.h # allow many IDEs to find and edit it
        ${SRC_DIR}/iddawc.c)

set(PKGCONF_REQ "")
set(PKGCONF_REQ_PRIVATE "")

include(FindJansson)
set(JANSSON_MIN_VERSION 2.4)
find_package(Jansson ${JANSSON_MIN_VERSION} REQUIRED)
list(APPEND IDDAWC_LIBS Jansson::Jansson)

include(FindGnuTLS)
find_package(GnuTLS REQUIRED)
list(APPEND IDDAWC_LIBS GnuTLS::GnuTLS)

# static library

option(BUILD_STATIC "Build static library." OFF)

if (BUILD_STATIC)
    add_library(iddawc_static STATIC ${LIB_SRC})
    add_library(Iddawc::Iddawc-static ALIAS iddawc_static)
    target_include_directories(iddawc_static
        PUBLIC "$<BUILD_INTERFACE:${INC_DIR}>"
        PUBLIC "$<BUILD_INTERFACE:${PROJECT_BINARY_DIR}>"
        PUBLIC "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>")
    target_link_libraries(iddawc_static PUBLIC ${IDDAWC_LIBS})
    target_compile_definitions(iddawc_static PUBLIC O_STATIC_LIBRARY)
    set_target_properties(iddawc_static PROPERTIES
            PUBLIC_HEADER "${INC_DIR}/iddawc.h;${PROJECT_BINARY_DIR}/iddawc-cfg.h"
            OUTPUT_NAME iddawc
            EXPORT_NAME Iddawc-static)
    if (MSVC)
        set_target_properties(iddawc_static PROPERTIES
                OUTPUT_NAME iddawc-static)
    endif ()
    if (NOT MSVC)
        target_compile_options(iddawc_static PRIVATE -Wextra -Wconversion)
    endif ()
    set(iddawc_lib iddawc_static)
endif ()

# shared library

add_library(iddawc SHARED ${LIB_SRC})
add_library(Iddawc::Iddawc ALIAS iddawc)
target_include_directories(iddawc
    PUBLIC "$<BUILD_INTERFACE:${INC_DIR}>"
    PUBLIC "$<BUILD_INTERFACE:${PROJECT_BINARY_DIR}>"
    PUBLIC "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>")
target_link_libraries(iddawc PUBLIC ${IDDAWC_LIBS})
set_target_properties(iddawc PROPERTIES
        PUBLIC_HEADER "${INC_DIR}/iddawc.h;${PROJECT_BINARY_DIR}/iddawc-cfg.h"
        VERSION "${LIBRARY_VERSION}"
        SOVERSION "${LIBRARY_SOVERSION}"
        WINDOWS_EXPORT_ALL_SYMBOLS TRUE
        EXPORT_NAME Iddawc)
if (WIN32)
    set_target_properties(iddawc PROPERTIES SUFFIX "-${LIBRARY_VERSION_MAJOR}.dll")
endif ()
if (NOT MSVC)
    target_compile_options(iddawc PRIVATE -Wextra -Wconversion)
endif()
set(iddawc_lib iddawc)

find_package(Orcania ${ORCANIA_VERSION_REQUIRED} REQUIRED)
if ("${ORCANIA_VERSION_STRING}" VERSION_GREATER_EQUAL "${ORCANIA_VERSION_REQUIRED}")
    message(STATUS "Orcania found: ${ORCANIA_VERSION_STRING}")
else ()
    message( FATAL_ERROR "Orcania version required: ${ORCANIA_VERSION_REQUIRED} - version installed: ${ORCANIA_VERSION_STRING}")
endif ()

target_link_libraries(iddawc PUBLIC $<TARGET_NAME:Orcania::Orcania>)
if (BUILD_STATIC)
    if(TARGET Orcania::Orcania-static)
        target_link_libraries(iddawc_static PUBLIC $<TARGET_NAME:Orcania::Orcania-static>)
    else()
        target_link_libraries(iddawc_static PUBLIC $<TARGET_NAME:Orcania::Orcania>)
    endif()
endif ()

find_package(Yder ${YDER_VERSION_REQUIRED} REQUIRED)
if ("${YDER_VERSION_STRING}" VERSION_GREATER_EQUAL "${YDER_VERSION_REQUIRED}")
    message(STATUS "Yder found: ${YDER_VERSION_STRING}")
else ()
    message( FATAL_ERROR "Yder version required: ${YDER_VERSION_REQUIRED} - version installed: ${YDER_VERSION_STRING}")
endif ()

target_link_libraries(iddawc PUBLIC $<TARGET_NAME:Yder::Yder>)
if (BUILD_STATIC)
    if(TARGET Yder::Yder-static)
        target_link_libraries(iddawc_static PUBLIC $<TARGET_NAME:Yder::Yder-static>)
    else()
        target_link_libraries(iddawc_static PUBLIC $<TARGET_NAME:Yder::Yder>)
    endif()
endif ()

find_package(Ulfius ${ULFIUS_VERSION_REQUIRED} REQUIRED)
if ("${ULFIUS_VERSION_STRING}" VERSION_GREATER_EQUAL "${ULFIUS_VERSION_REQUIRED}")
    message(STATUS "Ulfius found: ${ULFIUS_VERSION_STRING}")
else ()
    message( FATAL_ERROR "Ulfius version required: ${ULFIUS_VERSION_REQUIRED} - version installed: ${ULFIUS_VERSION_STRING}")
endif ()

target_link_libraries(iddawc PUBLIC $<TARGET_NAME:Ulfius::Ulfius>)
if (BUILD_STATIC)
    if(TARGET Ulfius::Ulfius-static)
        target_link_libraries(iddawc_static PUBLIC $<TARGET_NAME:Ulfius::Ulfius-static>)
    else()
        target_link_libraries(iddawc_static PUBLIC $<TARGET_NAME:Ulfius::Ulfius>)
    endif()
endif ()

find_package(Rhonabwy ${RHONABWY_VERSION_REQUIRED} REQUIRED)
if ("${RHONABWY_VERSION_STRING}" VERSION_GREATER_EQUAL "${RHONABWY_VERSION_REQUIRED}")
    message(STATUS "Rhonabwy found: ${RHONABWY_VERSION_STRING}")
else ()
    message( FATAL_ERROR "Rhonabwy version required: ${RHONABWY_VERSION_REQUIRED} - version installed: ${RHONABWY_VERSION_STRING}")
endif ()

target_link_libraries(iddawc PUBLIC $<TARGET_NAME:Rhonabwy::Rhonabwy>)
if (BUILD_STATIC)
    if(TARGET Rhonabwy::Rhonabwy-static)
        target_link_libraries(iddawc_static PUBLIC $<TARGET_NAME:Rhonabwy::Rhonabwy-static>)
    else()
        target_link_libraries(iddawc_static PUBLIC $<TARGET_NAME:Rhonabwy::Rhonabwy>)
    endif()
endif ()

# build idwcc

option(BUILD_IDWCC "Build idwcc application." OFF)

if (BUILD_IDWCC)
    find_package(Threads REQUIRED)
    list(APPEND IDDAWC_LIBS ${CMAKE_THREAD_LIBS_INIT})
    include(FindZLIB)
    find_package(ZLIB REQUIRED)
    if (ZLIB_FOUND)
      list(APPEND IDDAWC_LIBS ${ZLIB_LIBRARIES})
      include_directories(${ZLIB_INCLUDE_DIRS})
    endif ()
    add_executable(idwcc ${IDWCC_DIR}/idwcc.c
                         ${INC_DIR}/iddawc.h
                         ${IDWCC_DIR}/http_compression_callback.c
                         ${IDWCC_DIR}/http_compression_callback.h
                         ${IDWCC_DIR}/static_compressed_inmemory_website_callback.c
                         ${IDWCC_DIR}/static_compressed_inmemory_website_callback.h
                         ${PROJECT_BINARY_DIR}/iddawc-cfg.h)
    set_target_properties(idwcc PROPERTIES SKIP_BUILD_RPATH TRUE COMPILE_OPTIONS "-Wextra;-Wconversion")
    add_dependencies(idwcc iddawc)
    target_link_libraries(idwcc iddawc ${IDDAWC_LIBS})
    install(TARGETS idwcc RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
    install(FILES ${IDWCC_DIR}/idwcc.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1 COMPONENT runtime)
    install(DIRECTORY ${IDWCC_DIR}/webapp/ DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/idwcc/webapp/ COMPONENT runtime)
endif ()

# documentation

option(BUILD_IDDAWC_DOCUMENTATION "Build the documentation." OFF)
if (BUILD_IDDAWC_DOCUMENTATION)
    find_package(Doxygen)
    if (DOXYGEN_FOUND)
        set(doxyfile_in ${CMAKE_CURRENT_SOURCE_DIR}/doc/doxygen.cfg)
        set(doxyfile ${CMAKE_CURRENT_BINARY_DIR}/doxyfile)

        configure_file(${doxyfile_in} ${doxyfile} @ONLY)

        add_custom_target(doc
                          COMMAND ${DOXYGEN_EXECUTABLE} ${doxyfile_in}
                          WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                          COMMENT "Generating documentation with Doxygen"
                          VERBATIM)

    else ()
        message(FATAL_ERROR "Doxygen is needed to build the documentation.")
    endif ()
endif ()

# build iddawc-cfg.h file
configure_file(${INC_DIR}/iddawc-cfg.h.in ${PROJECT_BINARY_DIR}/iddawc-cfg.h)
set (CMAKE_EXTRA_INCLUDE_FILES ${PROJECT_BINARY_DIR})
include_directories(${PROJECT_BINARY_DIR})

# tests

option(BUILD_IDDAWC_TESTING "Build the testing tree." OFF) # because we do not use include(CTest)

if (BUILD_IDDAWC_TESTING)
    find_package(Check REQUIRED)
    if (CHECK_FOUND)
        if (NOT WIN32 AND NOT APPLE)
            include(FindSubunit)
            find_package(Subunit REQUIRED)
        endif ()

        enable_testing()

        set(CMAKE_CTEST_COMMAND ctest -V)

        set(TEST_LIBS )

        set(TST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/test)
        list(APPEND TEST_LIBS Check::Check)
        list(APPEND TEST_LIBS Iddawc::Iddawc)
        if (NOT WIN32)
            find_package(Threads REQUIRED)
            list(APPEND TEST_LIBS ${CMAKE_THREAD_LIBS_INIT} m)
        endif ()
        if (NOT APPLE AND NOT WIN32)
            list(APPEND TEST_LIBS rt)
        endif ()
        if (NOT WIN32 AND NOT APPLE)
            list(APPEND TEST_LIBS Subunit::Subunit)
        endif ()

        set(TESTS
            core
            implicit
            id_token
            token
            load_config
            load_userinfo
            flow
            introspection
            revocation
            registration
            dpop
            api_request
            device
            par
            ciba
            session
            rar
        )

        configure_file(
                "${I_CMAKE_MODULE_PATH}/CTestCustom.cmake.in"
                "${CMAKE_CURRENT_BINARY_DIR}/CTestCustom.cmake"
                @ONLY)

        foreach (t ${TESTS})
            add_executable(${t} EXCLUDE_FROM_ALL ${TST_DIR}/${t}.c)
            target_include_directories(${t} PRIVATE ${TST_DIR})
            target_link_libraries(${t} PRIVATE ${TEST_LIBS})
            add_test(NAME ${t}
                     WORKING_DIRECTORY ${TST_DIR}
                     COMMAND ${t})
        endforeach ()

    endif ()

endif ()

# install target

if(IS_ABSOLUTE "${CMAKE_INSTALL_INCLUDEDIR}")
  set(PKGCONFIG_TARGET_INCLUDES "${CMAKE_INSTALL_INCLUDEDIR}")
else()
  set(PKGCONFIG_TARGET_INCLUDES "\${prefix}/${CMAKE_INSTALL_INCLUDEDIR}")
endif()

if(IS_ABSOLUTE "${CMAKE_INSTALL_LIBDIR}")
  set(PKGCONFIG_TARGET_LIBDIR "${CMAKE_INSTALL_LIBDIR}")
else()
  set(PKGCONFIG_TARGET_LIBDIR "\${prefix}/${CMAKE_INSTALL_LIBDIR}")
endif()

option(INSTALL_HEADER "Install the header files" ON) # Install iddawc.h or not

configure_file(libiddawc.pc.in libiddawc.pc @ONLY)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libiddawc.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

set(TARGETS iddawc)

if (INSTALL_HEADER)
    install(TARGETS ${TARGETS} EXPORT IddawcExports
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
            PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
else ()
    install(TARGETS ${TARGETS} EXPORT IddawcExports
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif ()

if (INSTALL_HEADER)
    set(IDDAWC_INSTALL_CMAKEDIR_DEFAULT "${CMAKE_INSTALL_LIBDIR}/cmake/Iddawc")
    if (WIN32 AND NOT MINGW)
        set(IDDAWC_INSTALL_CMAKEDIR_DEFAULT "cmake")
    endif ()
    set(IDDAWC_INSTALL_CMAKEDIR ${IDDAWC_INSTALL_CMAKEDIR_DEFAULT} CACHE STRING "Location where to install the cmake config files")

    install(EXPORT IddawcExports DESTINATION "${IDDAWC_INSTALL_CMAKEDIR}"
        NAMESPACE "Iddawc::"
        FILE "IddawcTargets.cmake")

    configure_package_config_file(cmake-modules/IddawcConfig.cmake.in IddawcConfig.cmake
        INSTALL_DESTINATION "${IDDAWC_INSTALL_CMAKEDIR}")
    write_basic_package_version_file(IddawcConfigVersion.cmake
        COMPATIBILITY AnyNewerVersion)

    install(FILES
                cmake-modules/FindGnuTLS.cmake
                cmake-modules/FindJansson.cmake
                "${PROJECT_BINARY_DIR}/IddawcConfig.cmake"
                "${PROJECT_BINARY_DIR}/IddawcConfigVersion.cmake"
            DESTINATION "${IDDAWC_INSTALL_CMAKEDIR}")
endif ()

# uninstall target

if (NOT TARGET uninstall)
    configure_file(
            "${I_CMAKE_MODULE_PATH}/CMakeUninstall.cmake.in"
            "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
            IMMEDIATE @ONLY)
    add_custom_target(uninstall
            COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
endif ()

# packaging

set(CPACK_PACKAGE_VERSION_MAJOR ${LIBRARY_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${LIBRARY_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${LIBRARY_VERSION_PATCH})

if (INSTALL_HEADER)
    set(PACKAGE_FILE_NAME
            "lib${CMAKE_PROJECT_NAME}-dev_${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH}")
else ()
    set(PACKAGE_FILE_NAME
            "lib${CMAKE_PROJECT_NAME}_${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH}")
endif ()
set(PACKAGE_IGNORED_FILES
        "${CMAKE_CURRENT_BINARY_DIR}/;/.git/;.gitignore;~$;${CPACK_SOURCE_IGNORE_FILES}")

set(CPACK_PACKAGE_NAME "libiddawc")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Handle the flow of OAuth2 and OpenID Connect authentication process from the client side")
set(CPACK_GENERATOR "TGZ;DEB")
set(CPACK_PACKAGE_VERSION_MAJOR ${LIBRARY_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${LIBRARY_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${LIBRARY_VERSION_PATCH})

option(BUILD_RPM "Build a RPM for your system" OFF)
if (BUILD_RPM)
  set(CPACK_GENERATOR "TGZ;DEB;RPM")
  set(CPACK_RPM_PACKAGE_LICENSE "LGPL")
  set(CPACK_RPM_PACKAGE_URL "http://babelouest.github.io/iddawc/")
endif ()

set(CPACK_DEBIAN_PACKAGE_MAINTAINER "mail@babelouest.org")
set(CPACK_DEBIAN_PACKAGE_DESCRIPTION ${PROJECT_DESCRIPTION})
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "https://github.com/babelouest/iddawc")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6 (>= 2.4), liborcania|liborcania-dev (>= ${ORCANIA_VERSION_REQUIRED}), libyder|libyder-dev (>= ${YDER_VERSION_REQUIRED}), libulfius|libulfius-dev (>= ${ULFIUS_VERSION_REQUIRED}), libgnutls28-dev|libgnutls-dev|libgnutls30 (>= 3.5.0)")
set(CPACK_PACKAGE_FILE_NAME ${PACKAGE_FILE_NAME})
set(CPACK_PACKAGE_FILE_NAME ${PACKAGE_FILE_NAME})

set(CPACK_SOURCE_GENERATOR "TGZ")
set(CPACK_SOURCE_PACKAGE_FILE_NAME ${PACKAGE_FILE_NAME})
set(CPACK_SOURCE_IGNORE_FILES ${PACKAGE_IGNORED_FILES})

include(CPack)

message(STATUS "Build testing tree:       ${BUILD_IDDAWC_TESTING}")
message(STATUS "Install the header files: ${INSTALL_HEADER}")
message(STATUS "Build idwcc:              ${BUILD_IDWCC}")
message(STATUS "Build Static library:     ${BUILD_STATIC}")
message(STATUS "Build RPM package:        ${BUILD_RPM}")
message(STATUS "Build documentation:      ${BUILD_IDDAWC_DOCUMENTATION}")
