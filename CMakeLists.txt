cmake_minimum_required(VERSION 3.26)
project(test_ja4)
set(CMAKE_CXX_STANDARD 17)

include_directories(/usr/local/include)

find_library(CRYPTO_LIBRARY crypto)
if (NOT CRYPTO_LIBRARY)
    message(FATAL_ERROR "libcrypto not found")
endif()

add_executable(test_ja4 test_ja4.cpp
        ja4.cpp)

target_link_libraries(test_ja4
        ${CRYPTO_LIBRARY}
)