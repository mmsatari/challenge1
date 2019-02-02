cmake_minimum_required(VERSION 3.5.1)
project(pthread_challenge)

set(CMAKE_CXX_STANDARD 11)

add_executable(threads threads.cpp)
target_link_libraries(threads pthread)
