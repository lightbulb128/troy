echo "Making base library"

# obtain default python version
PYVER=$(python3 -c "import sys; print('{}.{}'.format(sys.version_info.major, sys.version_info.minor))")

# remove the dot in the version
PYVER_COMPACT=${PYVER//.}

echo Python version is $PYVER
echo Python version compact is $PYVER_COMPACT

mkdir -p build
cd build
cmake ..
make
cd ..

nvcc -x cu \
    -std=c++17 \
    -lpython${PYVER} \
    --compiler-options -fPIC \
    -I/usr/include/python${PYVER} \
    -I./extern/pybind11/include/ \
    -I./src -I/usr/include/python${PYVER} \
    --compiler-options -fPIC \
    -c binder/binder.cu \
    -o build/binder.o

echo "Binder.o generated"

nvcc -shared \
    ./build/src/libtroy.so \
    build/binder.o \
    -o build/pytroy.cpython-${PYVER_COMPACT}-x86_64-linux-gnu.so
    
echo "Shared lib generated"

    # ./build/src/libtroy.a \
#lib.linux-x86_64-3.8/pytroy.cpython-38-x86_64-linux-gnu.so
cp build/pytroy.cpython-${PYVER_COMPACT}-x86_64-linux-gnu.so ./binder/pytroy.cpython-${PYVER_COMPACT}-x86_64-linux-gnu.so
cp ./build/src/libtroy.so ./binder/libtroy.so

echo "Copied to ./binder"