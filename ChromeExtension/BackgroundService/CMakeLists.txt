cmake_minimum_required(VERSION 3.10)
project(Guardian CXX)

# --- 1. 设置 C++ 标准 ---
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# --- 2. 动态链接配置 (默认行为) ---
# 明确告诉 CMake 优先查找动态库 (这是 CMake 的默认行为，但明确设置总没错)
set(BUILD_SHARED_LIBS ON)

# --- 3. 移除 CURL_STATICLIB 宏 ---
# 移除此行，因为它是为静态链接准备的
# #add_compile_definitions(CURL_STATICLIB)

# --- 4. 指定外部库路径 ---
# 指定 cURL 的包含目录和导入库文件路径
# 请确保这些路径是正确的。
# 如果 libcurl.dll 在 system32 中，通常你不需要特别指定 libcurl.dll 本身。
# 你需要的是它的“导入库” (.lib 或 .dll.a) 文件，这个文件通常和头文件在同一个发布包里。
# 假设你的 curl-8.14.1_2-win64-mingw 包中包含了 libcurl.dll.a 或 libcurl.a 作为动态库的导入库
set(CURL_INCLUDE_DIR "E:/somesoftware/curl-8.14.1_2-win64-mingw/include")

# 重点：这里的 CURL_LIBRARY 应该指向用于动态链接的导入库。
# 它的名字通常是 libcurl.dll.a 或者仅仅是 libcurl.a (但它实际是导入库)。
# 请检查你下载的 cURL 包中 `E:/somesoftware/curl-8.14.1_2-win64-mingw/lib/` 目录下实际存在的导入库文件名。
set(CURL_LIBRARY "E:/somesoftware/curl-8.14.1_2-win64-mingw/lib/libcurl.dll.a") # <--- 根据实际文件调整
# 或者可能是：
# set(CURL_LIBRARY "E:/somesoftware/curl-8.14.1_2-win64-mingw/lib/libcurl.a") # 如果这个 .a 文件是动态库的导入库

# 检查导入库文件是否存在
if(NOT EXISTS ${CURL_LIBRARY})
    message(FATAL_ERROR "CURL import library file not found at: ${CURL_LIBRARY}. Please check the path and filename.")
endif()

# --- 5. 添加源文件 ---
set(SOURCES
    main.cpp
    native_messaging.cpp
    common.cpp
    remote_scanner.cpp
)

# --- 6. 添加可执行文件 ---
add_executable(Guardian ${SOURCES})

# --- 7. 配置目标：包含目录和链接库 ---
# 添加项目自己的包含目录 (如果 ${CMAKE_SOURCE_DIR}/include 存在你的自定义头文件)
target_include_directories(Guardian PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

# 添加 cURL 的包含目录，让编译器能找到 curl/curl.h
target_include_directories(Guardian PRIVATE ${CURL_INCLUDE_DIR})

# 链接库：所有必要的库都放在这里
# ${CURL_LIBRARY} 会链接到用于动态链接的导入库
# ws2_32 是 Winsock 库，Windows 网络程序必需
if(WIN32)
    target_link_libraries(Guardian PRIVATE
        ${CURL_LIBRARY}
        ws2_32
        # 动态链接 cURL 时，通常不再需要额外链接 GDI/LDAP/Crypto 等库，
        # 因为这些依赖会由 libcurl.dll 在加载时处理。
        # 如果你遇到链接错误，再考虑添加。
    )
endif()

# --- 8. 可选：设置输出目录 ---
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")