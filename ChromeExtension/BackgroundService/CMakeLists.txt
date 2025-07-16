cmake_minimum_required(VERSION 3.10)
project(Guardian CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(BUILD_SHARED_LIBS ON)

set(CURL_INCLUDE_DIR "E:/somesoftware/curl-8.14.1_2-win64-mingw/include")

set(CURL_LIBRARY "E:/somesoftware/curl-8.14.1_2-win64-mingw/lib/libcurl.dll.a") # <--- 根据实际文件调整

if(NOT EXISTS ${CURL_LIBRARY})
    message(FATAL_ERROR "CURL import library file not found at: ${CURL_LIBRARY}. Please check the path and filename.")
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

target_include_directories(Guardian PRIVATE ${CURL_INCLUDE_DIR})

if(WIN32)
    target_link_libraries(Guardian PRIVATE
        ${CURL_LIBRARY}
        ws2_32
    )
endif()

# --- 8. 可选：设置输出目录 ---
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")