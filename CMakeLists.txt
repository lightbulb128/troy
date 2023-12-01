project(Troy LANGUAGES C CXX CUDA)

set(CMAKE_CXX_STANDARD 17)
# set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -O3")
set(CMAKE_CUDA_FLAGS "${CMAKE_CUDA_FLAGS} --std=c++17")

if(NOT DEFINED CMAKE_CUDA_ARCHITECTURES)
  set(CMAKE_CUDA_ARCHITECTURES 70 72 75 80 86)
endif()

cmake_minimum_required(VERSION 3.16)

add_subdirectory(src)

# add TROY_TEST variable
option(TROY_TEST "Build tests" OFF)
option(TROY_COMPARE_SEAL "Build tests to compare efficiency with SEAL" OFF)

if(TROY_TEST)
  message(STATUS "Tests enabled")
  enable_testing()
  add_subdirectory("${PROJECT_SOURCE_DIR}/extern/googletest" "extern/googletest")
  add_subdirectory(test)
endif()