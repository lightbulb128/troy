enable_testing()

add_executable(troytest)
target_sources(troytest PRIVATE 
    modulus.cpp
)
target_link_libraries(troytest gtest gtest_main troy)

include(GoogleTest)
gtest_discover_tests(troytest)