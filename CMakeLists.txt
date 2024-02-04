# SPDX-License-Identifier: Unlicense
# Author: Derrick Lyndon Pallas <derrick@pallas.us>

cmake_minimum_required(VERSION 3.7)
cmake_policy(SET CMP0076 NEW)

set(default_build_type "Release")
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
        set(CMAKE_BUILD_TYPE "${default_build_type}" CACHE
                STRING "Choose the type of build." FORCE)
        set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
                "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

set(CMAKE_C_STANDARD 17)

project(ioucontext)

# objects become the library
set(${PROJECT_NAME}_OBJECTS
	arena
	ares_dns
	fiber
	jump_queue
	operations
	reactor
	rustls_tls
	sockaddr
	stack
	timespec
	todo_sigjmp
	todo_ucontext
        )


# headers are installed
set(${PROJECT_NAME}_HEADERS
	arena
	ares_dns
	fiber
	ioucontext
	macros
	operations
	reactor
	rustls_tls
	sockaddr
	timespec
        )

# executables link the shared library and are installed
set(${PROJECT_NAME}_EXECUTABLES
	iou_cat
	iou_dns
	iou_port7
	iou_timers
	iou_tls
	iou_tlsd
        )

# tests link the static library and are not installed
set(${PROJECT_NAME}_TESTS
        )

add_library(${PROJECT_NAME} OBJECT)
foreach(object ${${PROJECT_NAME}_OBJECTS})
        target_sources(${PROJECT_NAME} PUBLIC ${object}.c)
endforeach(object)

include(CheckIncludeFile)
check_include_file(valgrind/memcheck.h HAVE_MEMCHECK_H)
if (HAVE_MEMCHECK_H)
	target_compile_definitions(${PROJECT_NAME} PRIVATE HAVE_MEMCHECK_H)
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

set_property(TARGET ${PROJECT_NAME} PROPERTY POSITION_INDEPENDENT_CODE 1)
add_library(${PROJECT_NAME}-static STATIC $<TARGET_OBJECTS:${PROJECT_NAME}>)
set_target_properties(${PROJECT_NAME}-static PROPERTIES OUTPUT_NAME ${PROJECT_NAME})
add_library(${PROJECT_NAME}-shared SHARED $<TARGET_OBJECTS:${PROJECT_NAME}>)
set_target_properties(${PROJECT_NAME}-shared PROPERTIES OUTPUT_NAME ${PROJECT_NAME} SOVERSION 0 VERSION 0.0.0)

find_library(LIBURING uring)
target_link_libraries(${PROJECT_NAME}-static ${LIBURING})
target_link_libraries(${PROJECT_NAME}-shared ${LIBURING})

find_library(LIBUCONTEXT ucontext)
if (${LIBUCONTEXT})
	target_link_libraries(${PROJECT_NAME}-static ${LIBUCONTEXT})
	target_link_libraries(${PROJECT_NAME}-shared ${LIBUCONTEXT})
endif()

find_library(LIBCARES cares)
target_link_libraries(${PROJECT_NAME}-static ${LIBCARES})
target_link_libraries(${PROJECT_NAME}-shared ${LIBCARES})

find_library(LIBRUSTLS rustls)
target_link_libraries(${PROJECT_NAME}-static ${LIBRUSTLS})
target_link_libraries(${PROJECT_NAME}-shared ${LIBRUSTLS})

install(TARGETS
        ${PROJECT_NAME}-static
        ${PROJECT_NAME}-shared
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
        )

foreach(executable ${${PROJECT_NAME}_EXECUTABLES})
        add_executable(${executable} ${executable}.c)
        target_link_libraries(${executable} ${PROJECT_NAME}-shared)
        install(TARGETS ${executable} RUNTIME DESTINATION bin)
endforeach(executable)

foreach(header ${${PROJECT_NAME}_HEADERS})
        install(FILES ${header}.h DESTINATION "include/${PROJECT_NAME}/")
endforeach(header)

enable_testing()
add_custom_target(all_tests)
foreach(test ${${PROJECT_NAME}_TESTS})
        add_executable(${test} EXCLUDE_FROM_ALL ${test}.c)
        target_link_libraries(${test} ${PROJECT_NAME}-static)
        add_test(NAME ${test} COMMAND $<TARGET_FILE:${test}>)
        add_dependencies(all_tests ${test})
endforeach(test)
build_command(CTEST_CUSTOM_PRE_TEST TARGET all_tests)
string(CONFIGURE \"@CTEST_CUSTOM_PRE_TEST@\" CTEST_CUSTOM_PRE_TEST_QUOTED ESCAPE_QUOTES)
file(WRITE "${CMAKE_BINARY_DIR}/CTestCustom.cmake" "set(CTEST_CUSTOM_PRE_TEST ${CTEST_CUSTOM_PRE_TEST_QUOTED})" "\n")
