# SPDX-License-Identifier: Unlicense
# Author: Derrick Lyndon Pallas <derrick@pallas.us>

cmake_minimum_required(VERSION 3.10)
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
	bitset
	eventcount
	fiber
	jump_queue
	mutex
	operations
	output
	queue
	reactor
	semaphore
	slotpool
	sockaddr
	stack
	timespec
	todo_null
	todo_sigjmp
	todo_ucontext
        )


# headers are installed
set(${PROJECT_NAME}_HEADERS
	arena
	eventcount
	fiber
	ioucontext
	macros
	mutex
	operations
	output
	queue
	reactor
	semaphore
	slotpool
	sockaddr
	timespec
        )

# executables link the shared library and are installed
set(${PROJECT_NAME}_EXECUTABLES
	iou_cat
	iou_port7
	iou_timers
        )

# tests link the static library and are not installed
set(${PROJECT_NAME}_TESTS
        )

add_library(${PROJECT_NAME} OBJECT)
foreach(object ${${PROJECT_NAME}_OBJECTS})
        target_sources(${PROJECT_NAME} PUBLIC ${object}.c)
endforeach(object)

include(CheckIncludeFile)

option(VALGRIND "Enable valgrind support" ON)
if(VALGRIND)
	check_include_file(valgrind/memcheck.h HAVE_MEMCHECK_H)
	if (HAVE_MEMCHECK_H)
		target_compile_definitions(${PROJECT_NAME} PRIVATE HAVE_MEMCHECK_H)
	endif()
	check_include_file(valgrind/helgrind.h HAVE_HELGRIND_H)
	if (HAVE_HELGRIND_H)
		target_compile_definitions(${PROJECT_NAME} PRIVATE HAVE_HELGRIND_H)
	endif()
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
if (LIBUCONTEXT)
	target_link_libraries(${PROJECT_NAME}-static ${LIBUCONTEXT})
	target_link_libraries(${PROJECT_NAME}-shared ${LIBUCONTEXT})
endif()

find_library(LIBCARES cares)
if (LIBCARES)
	add_library(${PROJECT_NAME}-cares SHARED)
	target_sources(${PROJECT_NAME}-cares PUBLIC iou-cares.c)
	set_target_properties(${PROJECT_NAME}-cares PROPERTIES OUTPUT_NAME ${PROJECT_NAME}-cares SOVERSION 0 VERSION 0.0.0)
	target_link_libraries(${PROJECT_NAME}-cares ${PROJECT_NAME}-shared ${LIBCARES})
	install(FILES iou-cares.h DESTINATION "include/${PROJECT_NAME}/")
	install(TARGETS ${PROJECT_NAME}-cares LIBRARY DESTINATION lib)
	foreach(executable iou_dns)
		add_executable(${executable} ${executable}.c)
		target_link_libraries(${executable} ${PROJECT_NAME}-cares ${PROJECT_NAME}-shared)
		install(TARGETS ${executable} RUNTIME DESTINATION bin)
	endforeach(executable)
endif()

find_library(LIBRUSTLS rustls)
if (LIBRUSTLS)
	add_library(${PROJECT_NAME}-rustls SHARED)
	target_sources(${PROJECT_NAME}-rustls PUBLIC iou-rustls.c)
	set_target_properties(${PROJECT_NAME}-rustls PROPERTIES OUTPUT_NAME ${PROJECT_NAME}-rustls SOVERSION 0 VERSION 0.0.0)
	target_link_libraries(${PROJECT_NAME}-rustls ${PROJECT_NAME}-shared ${LIBRUSTLS})
	install(FILES iou-rustls.h DESTINATION "include/${PROJECT_NAME}/")
	install(TARGETS ${PROJECT_NAME}-rustls LIBRARY DESTINATION lib)
	foreach(executable iou_tlsd)
		add_executable(${executable} ${executable}.c)
		target_link_libraries(${executable} ${PROJECT_NAME}-rustls ${PROJECT_NAME}-shared)
		install(TARGETS ${executable} RUNTIME DESTINATION bin)
	endforeach(executable)
endif()

if (LIBCARES AND LIBRUSTLS)
	foreach(executable iou_tls)
		add_executable(${executable} ${executable}.c)
		target_link_libraries(${executable} ${PROJECT_NAME}-cares ${PROJECT_NAME}-rustls ${PROJECT_NAME}-shared)
		install(TARGETS ${executable} RUNTIME DESTINATION bin)
	endforeach(executable)
endif()

find_library(LIBNGHTTP2 nghttp2)
if (LIBNGHTTP2)
	foreach(executable iou_h2c)
		add_executable(${executable} ${executable}.c)
		target_link_libraries(${executable} ${LIBNGHTTP2} ${PROJECT_NAME}-shared)
		install(TARGETS ${executable} RUNTIME DESTINATION bin)
	endforeach(executable)
endif()

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
