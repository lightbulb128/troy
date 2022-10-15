enable_testing()

find_package(SEAL 4.0 REQUIRED)

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

    batchencoder.cpp
    ckks.cpp
    context.cpp
    encryptionparams.cpp
    encryptor.cpp
    evaluator.cpp
    keygenerator.cpp
    modulus.cpp

    encryptor_cuda.cu
    evaluator_cuda.cu
)
target_link_libraries(troytest gtest gtest_main troy)

include(GoogleTest)
gtest_discover_tests(troytest)