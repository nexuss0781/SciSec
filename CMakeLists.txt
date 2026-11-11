cmake_minimum_required(VERSION 3.16)
project(secsci_core VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(secsci SHARED
    cpp/src/sha2.cpp
    cpp/src/aes_gcm.cpp
    cpp/src/chacha20poly1305.cpp
    cpp/src/big.cpp
    cpp/src/gf521.cpp
    cpp/src/x25519.cpp
    cpp/src/drbg.cpp
    cpp/src/api.cpp
)
target_include_directories(secsci
    PUBLIC cpp/include
    PRIVATE cpp/src
)
target_compile_definitions(secsci PRIVATE SECSCI_BUILD)
set_target_properties(secsci PROPERTIES
    OUTPUT_NAME secsci
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)

if(MSVC)
    target_compile_options(secsci PRIVATE /W4 /permissive-)
else()
    target_compile_options(secsci PRIVATE -Wall -Wextra)
endif()

add_executable(secsci_selftest cpp/selftest.cpp)
target_link_libraries(secsci_selftest PRIVATE secsci)
target_include_directories(secsci_selftest PRIVATE cpp/include)

enable_testing()
add_test(NAME secsci_selftest COMMAND secsci_selftest)
