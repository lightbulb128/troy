

nvcc -x cu \
    -std=c++17 \
    -lpython3.8 \
    -I/usr/include/python3.8 \
    -I./extern/pybind11/include/ \
    -I./src -I/usr/include/python3.8 \
    --compiler-options -fPIC \
    -c binder/binder.cpp \
    -o build/binder.o

nvcc -shared \
    ./build/src/libtroy.a \
    build/binder.o \
    -o build/pytroy.cpython-38-x86_64-linux-gnu.so
    

    # ./build/src/libtroy.a \
#lib.linux-x86_64-3.8/pytroy.cpython-38-x86_64-linux-gnu.so
cp build/pytroy.cpython-38-x86_64-linux-gnu.so ./binder/pytroy.cpython-38-x86_64-linux-gnu.so