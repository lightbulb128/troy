project(Troy LANGUAGES CXX CUDA)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT DEFINED CMAKE_CUDA_ARCHITECTURES)
  set(CMAKE_CUDA_ARCHITECTURES 70 72 75 80 86)
endif()

cmake_minimum_required(VERSION 3.16)

find_package(SEAL 4.0 REQUIRED)

add_subdirectory(src)

add_executable(main main.cpp)
target_link_libraries(main SEAL::seal troy)

