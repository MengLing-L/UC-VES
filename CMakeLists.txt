# Specify the minimum version for CMake
cmake_minimum_required(VERSION 3.2)

# Project's name 
project(libZKPPHE)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -pthread -O0 -g ")
find_package(OpenSSL REQUIRED)

include_directories(${OPENSSL_INCLUDE_DIR})

add_executable(uc_nonuc_nizk_comparison main/uc_nonuc_nizk_comparison.cpp)

target_link_libraries(uc_nonuc_nizk_comparison ${OPENSSL_LIBRARIES})
target_link_libraries(uc_nonuc_nizk_comparison -lgmp)


add_executable(escrow_protocol_comparison main/escrow_protocol_comparison.cpp)

target_link_libraries(escrow_protocol_comparison ${OPENSSL_LIBRARIES})
target_link_libraries(escrow_protocol_comparison -lgmp)