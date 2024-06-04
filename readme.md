# troy := seal-cuda

## Notice

We have re-implemented this library and introduced a faster NTT-kernel and easier-to-use python packaging workflow. Be sure to checkout our new open-sourced repository at [troy-nova](https://github.com/lightbulb128/troy-nova).

The homomorphic encryption library implemented on GPU. Troy includes BFV, BGV, and CKKS schemes. Its implementation referred to the [Microsoft SEAL library](https://github.com/Microsoft/SEAL).
For reference, this library inherently includes a CPU version of the schemes, but you can just use the GPU part by using namespace `troyn`.

## Brief usage
The interfaces (classes, methods, etc.) are basicly the same as in SEAL, but you need to initialize the CUDA kernels (`troyn::KernelProvider::initialize()`) before using any of the GPU related classes. You can just call this at the beginning of your programs.

See `test/timetest.cu` for example.

## Code structures
* `src` includes the implementation of the library. Just include `troy_cuda.cuh` and you are ready to go.
* `test` includes the tests.
* `extern` includes third-party libraries: googletest and pybind11.
* `binder` includes the pybind11 code to encapsulate the C/C++/CUDA interfaces for python.
* `app` includes a high-level implementation for computing matrix multiplication and 2d-convolution in HE.

## How to run

1. Build the basic library
    ```
    mkdir build
    cd build
    cmake .. -DTROY_TEST=ON # or OFF(default), if you don't want to run tests
    make
    cd ..
    ```
2. Run tests
    ```
    cd build
    ctest
    ./test/timetest
    cd ..
    ```
3. Make the module for python
    ```
    bash makepackage.sh
    ```

## Comparing with CPU Microsoft SEAL-4.0

1. Make and install SEAL 4.0
    This requires `sudo` privilige to install the binary library file.
    ```
    bash install_seal.sh
    ```
2. CMake with `TROY_COMPARE_SEAL` and `TROY_TEST` on.
    ```
    cd build
    cmake .. -DTROY_TEST=ON -DTROY_COMPARE_SEAL=ON
    make
    cd ..
    ```
3. Testing
    ```
    cd build
    ./test/timetest
    ./test/timetest_seal
    ```
    
## Contribute
Feel free to fork / pull request.
Please cite this repository if you use it in your work.