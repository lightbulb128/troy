pybind11_add_module(pytroy binder.cpp)
target_link_libraries(pytroy PRIVATE troy)
target_compile_options(pytroy PUBLIC --compiler-options "-fPIC")
set_property(SOURCE binder.cpp PROPERTY LANGUAGE CUDA)