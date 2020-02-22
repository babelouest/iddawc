#
# Iddawc library
#
# CMake file used to build all programs
#
# Copyright 2018 Silvio Clecio <silvioprog@gmail.com>
# Copyright 2019 Nicolas Mora <mail@babelouest.org>
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

set(PROJECT_DESCRIPTION "Handle the flow of OAuth2 and OpenID Connect authentication process from the client side")
set(PROJECT_HOMEPAGE_URL "https://github.com/babelouest/iddawc/")
set(PROJECT_BUGREPORT_PATH "https://github.com/babelouest/iddawc/issues")
set(LIBRARY_VERSION_MAJOR "0")
set(LIBRARY_VERSION_MINOR "9")
set(LIBRARY_VERSION_PATCH "4")
set(ORCANIA_VERSION_REQUIRED "2.1.0")
set(YDER_VERSION_REQUIRED "1.4.9")
set(ULFIUS_VERSION_REQUIRED "2.6.5")
set(RHONABWY_VERSION_REQUIRED "0.9.3")
set(LIBJWT_VERSION_REQUIRED "1.11.0")

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

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake-modules)

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

# shared library

add_library(iddawc SHARED ${LIB_SRC})
set_target_properties(iddawc PROPERTIES
        COMPILE_OPTIONS -Wextra
        PUBLIC_HEADER "${INC_DIR}/iddawc.h;${PROJECT_BINARY_DIR}/iddawc-cfg.h"
        VERSION "${LIBRARY_VERSION}"
        SOVERSION "${LIBRARY_SOVERSION}")
target_link_libraries(iddawc ${LIBS})

include(FindLibJWT)
find_package(LibJWT ${LIBJWT_VERSION_REQUIRED} REQUIRED)
if (LIBJWT_FOUND)
        set(LIBS ${LIBS} ${LIBJWT_LIBRARIES})
        include_directories(${LIBJWT_INCLUDE_DIRS})
endif ()

include(FindJansson)
set(JANSSON_MIN_VERSION 2.11)
find_package(Jansson ${JANSSON_MIN_VERSION} REQUIRED)
if (JANSSON_FOUND)
	set(LIBS ${LIBS} ${JANSSON_LIBRARIES})
	include_directories(${JANSSON_INCLUDE_DIRS})
endif ()

include(FindGnuTLS)
find_package(GnuTLS REQUIRED)
if (GNUTLS_FOUND)
	set(LIBS ${LIBS} ${GNUTLS_LIBRARIES})
	include_directories(${GNUTLS_INCLUDE_DIRS})
endif ()

include(FindNettle)
find_package(Nettle REQUIRED)
if (NETTLE_FOUND)
	set(LIBS ${LIBS} ${NETTLE_LIBRARIES})
	include_directories(${NETTLE_INCLUDE_DIRS})
endif ()

set(SEARCH_ORCANIA OFF CACHE BOOL "Force to false") # Avoid to search and download orcania
set(SEARCH_ORCANIA_U OFF CACHE BOOL "Force to false") # Avoid to search and download orcania
set(SEARCH_YDER OFF CACHE BOOL "Force to false") # Avoid to search and download yder during
set(SEARCH_ORCANIA_R OFF CACHE BOOL "Force to false") # Avoid to search and download orcania during
set(SEARCH_YDER_R OFF CACHE BOOL "Force to false") # Avoid to search and download yder during
set(SEARCH_ULFIUS_R OFF CACHE BOOL "Force to false") # Avoid to search and download ulfius during

option(SEARCH_ORCANIA_I "Search for ORCANIA library" ON)
if (SEARCH_ORCANIA_I)
    set(Orcania_FIND_QUIETLY ON) # force to find Orcania quietly
    include(FindOrcania)
    find_package(Orcania ${ORCANIA_VERSION_REQUIRED} QUIET) # try to find orcania
    if (NOT ORCANIA_FOUND)
        include(DownloadProject)
        message(STATUS "Download Orcania ${ORCANIA_VERSION_REQUIRED}")
        download_project(PROJ orcania # ... otherwise, download archive
                URL "https://github.com/babelouest/orcania/archive/v${ORCANIA_VERSION_REQUIRED}.tar.gz"
                QUIET)
        add_subdirectory(${orcania_SOURCE_DIR} ${orcania_BINARY_DIR})
        include_directories(${orcania_SOURCE_DIR}/include)
        add_dependencies(iddawc orcania)
        set(ORCANIA_LIBRARIES orcania)
        include_directories(${orcania_BINARY_DIR})
    endif ()
    target_link_libraries(iddawc ${LIBS} ${ORCANIA_LIBRARIES})
    set(LIBS ${LIBS} ${ORCANIA_LIBRARIES})
endif ()

option(SEARCH_YDER_I "Search for Yder library" ON)
if (SEARCH_YDER_I)
    set(Yder_FIND_QUIETLY ON) # force to find Yder quietly
    include(FindYder)
    find_package(Yder ${YDER_VERSION_REQUIRED} QUIET) # try to find Yder
    if (NOT YDER_FOUND)
        include(DownloadProject)
        message(STATUS "Download Yder ${YDER_VERSION_REQUIRED}")
        option(CHECK_ORCANIA "specific param" off)
        download_project(PROJ yder # ... otherwise, download archive
                URL "https://github.com/babelouest/yder/archive/v${YDER_VERSION_REQUIRED}.tar.gz"
                QUIET)
        add_subdirectory(${yder_SOURCE_DIR} ${yder_BINARY_DIR})
        include_directories(${yder_SOURCE_DIR}/include)
        include_directories(${orcania_SOURCE_DIR}/include)
        add_dependencies(iddawc yder)
        set(YDER_LIBRARIES yder)
        include_directories(${yder_BINARY_DIR})
    endif ()
    target_link_libraries(iddawc ${LIBS} ${YDER_LIBRARIES})
    set(LIBS ${LIBS} ${YDER_LIBRARIES})
endif ()

option(SEARCH_ULFIUS_I "Search for Ulfius library" ON)
if (SEARCH_ULFIUS_I)
    set(Ulfius_FIND_QUIETLY ON)
    include(FindUlfius)
    find_package(Ulfius ${ULFIUS_VERSION_REQUIRED} QUIET)
    if (NOT ULFIUS_FOUND)
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
    endif ()
    target_link_libraries(iddawc ${LIBS} ${ULFIUS_LIBRARIES})
    set(LIBS ${LIBS} ${ULFIUS_LIBRARIES})
endif ()

option(SEARCH_RHONABWY_I "Search for Rhonabwy library" ON)
if (SEARCH_RHONABWY_I)
    set(Rhonabwy_FIND_QUIETLY ON)
    include(FindRhonabwy)
    find_package(Rhonabwy ${RHONABWY_VERSION_REQUIRED} QUIET)
    if (NOT RHONABWY_FOUND)
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
    endif ()
    target_link_libraries(iddawc ${LIBS} ${RHONABWY_LIBRARIES})
    set(LIBS ${LIBS} ${RHONABWY_LIBRARIES})
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
            flow)

        configure_file(
                "${CMAKE_MODULE_PATH}/CTestCustom.cmake.in"
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
            "${CMAKE_MODULE_PATH}/CMakeUninstall.cmake.in"
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
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6 (>= 2.4), libulfius|libulfius-dev (>= ${ULFIUS_VERSION_REQUIRED})")
set(CPACK_PACKAGE_FILE_NAME ${PACKAGE_FILE_NAME})
set(CPACK_PACKAGE_FILE_NAME ${PACKAGE_FILE_NAME})

set(CPACK_SOURCE_GENERATOR "TGZ")
set(CPACK_SOURCE_PACKAGE_FILE_NAME ${PACKAGE_FILE_NAME})
set(CPACK_SOURCE_IGNORE_FILES ${PACKAGE_IGNORED_FILES})

include(CPack)

message(STATUS "Build testing tree:       ${BUILD_IDDAWC_TESTING}")
message(STATUS "Install the header files: ${INSTALL_HEADER}")
message(STATUS "Build RPM package:        ${BUILD_RPM}")
message(STATUS "Build documentation:      ${BUILD_IDDAWC_DOCUMENTATION}")
