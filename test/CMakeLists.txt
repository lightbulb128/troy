enable_testing()

add_executable(troytest)
target_sources(troytest PRIVATE 
    utils/common.cpp
    utils/galois.cpp
    utils/hash.cpp
    utils/ntt.cpp
    utils/numth.cpp
    utils/polyarithsmallmod.cpp
    utils/rns.cpp
    utils/uintarith.cpp
    utils/uintarithmod.cpp
    utils/uintarithsmallmod.cpp
    utils/uintcore.cpp
    context.cpp
    encryptionparams.cpp
    modulus.cpp
)
target_link_libraries(troytest gtest gtest_main troy)

include(GoogleTest)
gtest_discover_tests(troytest)