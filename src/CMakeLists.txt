file(GLOB_RECURSE CURRENT_HEADERS *.h *.hpp *.cuh)
file(GLOB_RECURSE CURRENT_SOURCES *.cpp *.cu *.c)

source_group("Include" FILES ${CURRENT_HEADERS})
source_group("Source" FILES ${CURRENT_SOURCES})

add_library(troy STATIC ${CURRENT_HEADERS} ${CURRENT_SOURCES})

# set(gcc_like_cxx "$<COMPILE_LANG_AND_ID:CXX,ARMClang,AppleClang,Clang,GNU>")
# set(nvcc_cxx "$<COMPILE_LANG_AND_ID:CUDA,NVIDIA>")