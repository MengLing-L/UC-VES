# Specify the minimum version for CMake
cmake_minimum_required(VERSION 3.2)

# Project's name 
project(libZKPPHE)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -pthread -O0 -g")
find_package(OpenSSL REQUIRED)

include_directories(${OPENSSL_INCLUDE_DIR})

  
add_executable(test_range_proof test/test_range_proof.cpp)

target_link_libraries(test_range_proof ${OPENSSL_LIBRARIES})

#add_executable(test_dlog test/test_dlog.cpp)

#target_link_libraries(test_dlog ${OPENSSL_LIBRARIES})

add_executable(test_encrypt_witness test/test_encrypt_witness.cpp)

target_link_libraries(test_encrypt_witness ${OPENSSL_LIBRARIES})

#add_executable(test_simulate_encrypt_signature test/test_simulate_encrypt_signature.cpp)

#target_link_libraries(test_simulate_encrypt_signature ${OPENSSL_LIBRARIES})

add_executable(test_sigma_dlog test/test_sigma_dlog.cpp)

target_link_libraries(test_sigma_dlog ${OPENSSL_LIBRARIES})

#add_executable(test_encrypt_witness_or_encrypt_signature test/test_encrypt_witness_or_encrypt_signature.cpp)

#target_link_libraries(test_encrypt_witness_or_encrypt_signature ${OPENSSL_LIBRARIES})

#add_executable(test_cocoframework test/test_cocoframework.cpp)

#target_link_libraries(test_cocoframework ${OPENSSL_LIBRARIES})
