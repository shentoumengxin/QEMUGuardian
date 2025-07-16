cmake_minimum_required(VERSION 3.10)
project(Guardian CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_EXTENSIONS OFF) # Prefer strict C++ standard

set(BUILD_SHARED_LIBS ON)

find_package(CURL REQUIRED)

if (NOT CURL_FOUND)
    message(FATAL_ERROR "cURL library not found. Please install libcurl-dev or libcurl-devel.")
endif()

set(SOURCES
    main.cpp
    native_messaging.cpp
    common.cpp
    remote_scanner.cpp
)

add_executable(Guardian ${SOURCES})

target_include_directories(Guardian PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

target_include_directories(Guardian PRIVATE ${CURL_INCLUDE_DIRS})

target_link_libraries(Guardian PRIVATE
    ${CURL_LIBRARIES} # <--- Use CURL_LIBRARIES variable
)

if(WIN32)
    target_link_libraries(Guardian PRIVATE
        ws2_32
    )
endif()

# --- 8. Optional: Set Output Directory ---
# set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")