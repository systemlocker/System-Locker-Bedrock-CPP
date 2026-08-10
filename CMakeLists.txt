cmake_minimum_required(VERSION 3.20)

project(SystemLockerBedrock VERSION 0.1.0 LANGUAGES CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(SYSLOCKER_BEDROCK_BUILD_TESTS "Build the offline Bedrock test suite" ON)
option(SYSLOCKER_BEDROCK_BUILD_EXAMPLE "Build the Bedrock command-line example" ON)
option(SYSLOCKER_BEDROCK_BUILD_LIVE_TEST "Build the opt-in live-server test" OFF)

find_package(CURL REQUIRED)
find_package(OpenSSL 1.1.1 REQUIRED COMPONENTS Crypto)
find_package(Threads REQUIRED)

add_library(systemlocker_bedrock
    src/bedrock.cpp
    src/crypto.cpp
    src/curl_http.cpp
    src/response.cpp
)
add_library(SystemLocker::Bedrock ALIAS systemlocker_bedrock)
set_target_properties(systemlocker_bedrock PROPERTIES EXPORT_NAME Bedrock)

target_include_directories(systemlocker_bedrock
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party
)

target_link_libraries(systemlocker_bedrock
    PUBLIC CURL::libcurl OpenSSL::Crypto Threads::Threads
)

target_compile_definitions(systemlocker_bedrock PRIVATE SYSLOCKER_BEDROCK_BUILDING)

if(MSVC)
    target_compile_options(systemlocker_bedrock PRIVATE /W4 /permissive- /EHsc)
else()
    target_compile_options(systemlocker_bedrock PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(SYSLOCKER_BEDROCK_BUILD_EXAMPLE)
    add_executable(systemlocker_bedrock_cli examples/bedrock_cli.cpp)
    target_link_libraries(systemlocker_bedrock_cli PRIVATE SystemLocker::Bedrock)
endif()

if(SYSLOCKER_BEDROCK_BUILD_TESTS)
    enable_testing()
    add_executable(systemlocker_bedrock_tests
        tests/test_main.cpp
        tests/test_bedrock.cpp
        tests/test_crypto.cpp
    )
    target_include_directories(systemlocker_bedrock_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/tests
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party
    )
    target_link_libraries(systemlocker_bedrock_tests PRIVATE SystemLocker::Bedrock)
    add_test(NAME systemlocker_bedrock_tests COMMAND systemlocker_bedrock_tests)
endif()

if(SYSLOCKER_BEDROCK_BUILD_LIVE_TEST)
    add_executable(systemlocker_bedrock_live_test tests/live_test.cpp)
    target_link_libraries(systemlocker_bedrock_live_test PRIVATE SystemLocker::Bedrock)
endif()

install(TARGETS systemlocker_bedrock
    EXPORT SystemLockerBedrockTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT SystemLockerBedrockTargets
    FILE SystemLockerBedrockTargets.cmake
    NAMESPACE SystemLocker::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/SystemLockerBedrock
)

configure_package_config_file(
    cmake/SystemLockerBedrockConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/SystemLockerBedrockConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/SystemLockerBedrock
)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/SystemLockerBedrockConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/SystemLockerBedrockConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/SystemLockerBedrockConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/SystemLockerBedrock
)
