#
# Iddawc library
#
# CMake file used to build all programs
#
# Copyright 2018 Silvio Clecio <silvioprog@gmail.com>
# Copyright 2019-2022 Nicolas Mora <mail@babelouest.org>
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

set(PROJECT_DESCRIPTION "OAuth2/OIDC client library")
set(PROJECT_HOMEPAGE_URL "https://github.com/babelouest/iddawc/")
set(PROJECT_BUGREPORT_PATH "https://github.com/babelouest/iddawc/issues")
set(LIBRARY_VERSION_MAJOR "1")
set(LIBRARY_VERSION_MINOR "1")
set(LIBRARY_VERSION_PATCH "8")
set(ORCANIA_VERSION_REQUIRED "2.3.2")
set(YDER_VERSION_REQUIRED "1.4.19")
set(ULFIUS_VERSION_REQUIRED "2.7.12")
set(RHONABWY_VERSION_REQUIRED "1.1.10")

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

# static library

option(BUILD_STATIC "Build static library." OFF)

if (BUILD_STATIC)
    add_library(iddawc_static STATIC ${LIB_SRC})
    target_compile_definitions(iddawc_static PUBLIC -DO_STATIC_LIBRARY)
    set_target_properties(iddawc_static PROPERTIES
            OUTPUT_NAME iddawc)
endif ()

# shared library

add_library(iddawc SHARED ${LIB_SRC})
set_target_properties(iddawc PROPERTIES
        COMPILE_OPTIONS "-Wextra;-Wconversion;-Werror=sign-conversion"
        PUBLIC_HEADER "${INC_DIR}/iddawc.h;${PROJECT_BINARY_DIR}/iddawc-cfg.h"
        VERSION "${LIBRARY_VERSION}"
        SOVERSION "${LIBRARY_SOVERSION}")

include(FindJansson)
set(JANSSON_MIN_VERSION 2.11)
find_package(Jansson ${JANSSON_MIN_VERSION} REQUIRED)
if (JANSSON_FOUND)
	set(LIBS ${LIBS} ${JANSSON_LIBRARIES})
	include_directories(${JANSSON_INCLUDE_DIRS})
endif ()

include(FindNettle)
find_package(Nettle REQUIRED)
if (NETTLE_FOUND)
	set(LIBS ${LIBS} ${NETTLE_LIBRARIES})
	include_directories(${NETTLE_INCLUDE_DIRS})
endif ()

include(FindGnuTLS)
find_package(GnuTLS REQUIRED)
if (GNUTLS_FOUND)
	set(LIBS ${LIBS} ${GNUTLS_LIBRARIES})
	include_directories(${GNUTLS_INCLUDE_DIRS})
endif ()
target_link_libraries(iddawc ${LIBS})

include(FindMHD)
find_package(MHD REQUIRED)

set(SEARCH_ORCANIA OFF CACHE BOOL "Force to false") # Avoid to search and download orcania
set(SEARCH_ORCANIA_U OFF CACHE BOOL "Force to false") # Avoid to search and download orcania
set(SEARCH_YDER OFF CACHE BOOL "Force to false") # Avoid to search and download yder during
set(SEARCH_ORCANIA_R OFF CACHE BOOL "Force to false") # Avoid to search and download orcania during
set(SEARCH_YDER_R OFF CACHE BOOL "Force to false") # Avoid to search and download yder during
set(SEARCH_ULFIUS_R OFF CACHE BOOL "Force to false") # Avoid to search and download ulfius during

option(DOWNLOAD_DEPENDENCIES "Download required dependencies" ON)

option(SEARCH_ORCANIA_I "Search for ORCANIA library" ON)
if (SEARCH_ORCANIA_I)
    set(Orcania_FIND_QUIETLY ON) # force to find Orcania quietly
    include(FindOrcania)
    find_package(Orcania ${ORCANIA_VERSION_REQUIRED} QUIET) # try to find orcania
    if (NOT ORCANIA_FOUND)
        if (DOWNLOAD_DEPENDENCIES)
            include(DownloadProject)
            download_project(PROJ orcania # ... otherwise, download archive
                             URL "https://github.com/babelouest/orcania/archive/v${ORCANIA_VERSION_REQUIRED}.tar.gz"
                             QUIET)
            add_subdirectory(${orcania_SOURCE_DIR} ${orcania_BINARY_DIR})
            include_directories(${orcania_SOURCE_DIR}/include)
            include_directories(${orcania_BINARY_DIR})
            add_dependencies(yder orcania)
            set(ORCANIA_LIBRARIES orcania)
            set(LIBS ${LIBS} ${ORCANIA_LIBRARIES})
        else ()
            message( FATAL_ERROR "Orcania not found")
        endif ()
    else()
        if ("${ORCANIA_VERSION_STRING}" VERSION_GREATER_EQUAL "${ORCANIA_VERSION_REQUIRED}")
            message(STATUS "Orcania found: ${ORCANIA_VERSION_STRING}")
            set(LIBS ${LIBS} ${ORCANIA_LIBRARIES})
            include_directories(${ORCANIA_INCLUDE_DIRS})
            include_directories(${orcania_BINARY_DIR})
        else ()
            message( FATAL_ERROR "Orcania version required: ${ORCANIA_VERSION_REQUIRED} - version installed: ${ORCANIA_VERSION_STRING}")
        endif ()
    endif ()
endif ()
target_link_libraries(iddawc ${ORCANIA_LIBRARIES})
set(LIBS ${LIBS} ${ORCANIA_LIBRARIES})

option(SEARCH_YDER_I "Search for Yder library" ON)
if (SEARCH_YDER_I)
    set(Yder_FIND_QUIETLY ON) # force to find Yder quietly
    include(FindYder)
    find_package(Yder ${YDER_VERSION_REQUIRED} QUIET) # try to find Yder
    if (NOT YDER_FOUND)
        if (DOWNLOAD_DEPENDENCIES)
            include(DownloadProject)
            download_project(PROJ yder # ... otherwise, download archive
                              URL "https://github.com/babelouest/yder/archive/v${YDER_VERSION_REQUIRED}.tar.gz"
                              QUIET)
            add_subdirectory(${yder_SOURCE_DIR} ${yder_BINARY_DIR})
            include_directories(${yder_SOURCE_DIR}/include)
            add_dependencies(iddawc yder)
            set(YDER_LIBRARIES yder orcania)
            include_directories(${yder_BINARY_DIR})
        else ()
            message( FATAL_ERROR "Yder not found")
        endif ()
    else()
        if ("${YDER_VERSION_STRING}" VERSION_GREATER_EQUAL "${YDER_VERSION_REQUIRED}")
            message(STATUS "Yder found: ${YDER_VERSION_STRING}")
            set(LIBS ${LIBS} ${YDER_LIBRARIES})
            include_directories(${YDER_INCLUDE_DIRS})
            include_directories(${yder_BINARY_DIR})
        else ()
            message( FATAL_ERROR "Yder version required: ${YDER_VERSION_REQUIRED} - version installed: ${YDER_VERSION_STRING}")
        endif ()
    endif ()
    target_link_libraries(iddawc ${LIBS} ${YDER_LIBRARIES})
endif ()
target_link_libraries(iddawc ${YDER_LIBRARIES})
set(LIBS ${LIBS} ${YDER_LIBRARIES})

option(SEARCH_ULFIUS_I "Search for Ulfius library" ON)
if (SEARCH_ULFIUS_I)
    set(Ulfius_FIND_QUIETLY ON)
    include(FindUlfius)
    find_package(Ulfius ${ULFIUS_VERSION_REQUIRED} QUIET)
    if (NOT ULFIUS_FOUND)
        if (DOWNLOAD_DEPENDENCIES)
            include(DownloadProject)
            option(CHECK_ORCANIA "specific param" off)
            option(CHECK_YDER "specific param" off)
            message(STATUS "Download Ulfius ${ULFIUS_VERSION_REQUIRED}")
            download_project(PROJ ulfius
                             URL "https://github.com/babelouest/ulfius/archive/v${ULFIUS_VERSION_REQUIRED}.tar.gz"
                             QUIET)
            add_subdirectory(${ulfius_SOURCE_DIR} ${ulfius_BINARY_DIR})
            include_directories(${yder_SOURCE_DIR}/include)
            include_directories(${orcania_SOURCE_DIR}/include)
            include_directories(${ulfius_SOURCE_DIR}/include)
            add_dependencies(iddawc ulfius)
            set(ULFIUS_LIBRARIES ulfius)
            include_directories(${ulfius_BINARY_DIR})
        else ()
            message( FATAL_ERROR "Ulfius not found")
        endif ()
    else ()
        if ("${ULFIUS_VERSION_STRING}" VERSION_GREATER_EQUAL "${ULFIUS_VERSION_REQUIRED}")
            message(STATUS "Ulfius found: ${ULFIUS_VERSION_STRING}")
            set(LIBS ${LIBS} ${ULFIUS_LIBRARIES})
            include_directories(${ULFIUS_INCLUDE_DIRS})
            include_directories(${yder_BINARY_DIR})
        else ()
            message( FATAL_ERROR "Ulfius version required: ${ULFIUS_VERSION_REQUIRED} - version installed: ${ULFIUS_VERSION_STRING}")
        endif ()
    endif ()
endif ()
target_link_libraries(iddawc ${ULFIUS_LIBRARIES})
set(LIBS ${LIBS} ${ULFIUS_LIBRARIES})

option(SEARCH_RHONABWY_I "Search for Rhonabwy library" ON)
if (SEARCH_RHONABWY_I)
    set(Rhonabwy_FIND_QUIETLY ON)
    include(FindRhonabwy)
    find_package(Rhonabwy ${RHONABWY_VERSION_REQUIRED} QUIET)
    if (NOT RHONABWY_FOUND)
        if (DOWNLOAD_DEPENDENCIES)
            include(DownloadProject)
            option(CHECK_ORCANIA "specific param" off)
            option(CHECK_YDER "specific param" off)
            option(CHECK_ULFIUS "specific param" off)
            message(STATUS "Download Rhonabwy ${RHONABWY_VERSION_REQUIRED}")
            download_project(PROJ rhonabwy
                    URL "https://github.com/babelouest/rhonabwy/archive/v${RHONABWY_VERSION_REQUIRED}.tar.gz"
                    QUIET)
            add_subdirectory(${rhonabwy_SOURCE_DIR} ${rhonabwy_BINARY_DIR})
            include_directories(${yder_SOURCE_DIR}/include)
            include_directories(${orcania_SOURCE_DIR}/include)
            include_directories(${ulfius_SOURCE_DIR}/include)
            include_directories(${rhonabwy_SOURCE_DIR}/include)
            add_dependencies(iddawc rhonabwy)
            set(RHONABWY_LIBRARIES rhonabwy)
            include_directories(${rhonabwy_BINARY_DIR})
        else ()
            message( FATAL_ERROR "Rhonabwy not found")
        endif ()
    else ()
        include_directories(${RHONABWY_INCLUDE_DIRS})
    endif ()
endif ()
target_link_libraries(iddawc ${RHONABWY_LIBRARIES})
set(LIBS ${LIBS} ${RHONABWY_LIBRARIES})

# build idwcc

option(BUILD_IDWCC "Build idwcc application." ON)

if (BUILD_IDWCC)
    find_package(Threads REQUIRED)
    set(LIBS ${LIBS} ${CMAKE_THREAD_LIBS_INIT})
    include(FindZLIB)
    find_package(ZLIB REQUIRED)
    if (ZLIB_FOUND)
      set(LIBS ${LIBS} ${ZLIB_LIBRARIES})
      include_directories(${ZLIB_INCLUDE_DIRS})
    endif ()
    add_executable(idwcc ${IDWCC_DIR}/idwcc.c ${INC_DIR}/iddawc.h ${IDWCC_DIR}/http_compression_callback.c ${IDWCC_DIR}/http_compression_callback.h ${IDWCC_DIR}/static_compressed_inmemory_website_callback.c ${IDWCC_DIR}/static_compressed_inmemory_website_callback.h ${PROJECT_BINARY_DIR}/iddawc-cfg.h)
    set_target_properties(idwcc PROPERTIES SKIP_BUILD_RPATH TRUE COMPILE_OPTIONS "-Wextra;-Wconversion;-Werror=sign-conversion")
    add_dependencies(idwcc iddawc)
    target_link_libraries(idwcc iddawc ${LIBS})
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
    include(FindCheck)
    find_package(Check REQUIRED)
    if (CHECK_FOUND)
		include(FindSubunit)
		find_package(Subunit REQUIRED)
        find_package(Threads REQUIRED)

        enable_testing()

        set(CMAKE_CTEST_COMMAND ctest -V)

        set(TST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/test)
        set(LIBS iddawc ${LIBS} ${CHECK_LIBRARIES} ${SUBUNIT_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} "-lm -lrt")

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
            target_include_directories(${t} PUBLIC ${TST_DIR})
            target_link_libraries(${t} PUBLIC ${LIBS})
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
    install(TARGETS ${TARGETS}
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
            PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
else ()
    install(TARGETS ${TARGETS}
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
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
