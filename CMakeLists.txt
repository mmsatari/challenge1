cmake_minimum_required(VERSION 3.5.1)
project(cpp_challenge)

set(CMAKE_CXX_STANDARD 11)


add_executable(server src/openssl/server.cpp src/openssl/ssl_helper.cpp src/openssl/ssl_helper.h)
target_link_libraries(server crypto ssl)

add_executable(client src/openssl/client.cpp src/openssl/ssl_helper.cpp src/openssl/ssl_helper.h)
target_link_libraries(client crypto ssl)
