git submodule update --init --recursive
cd extern/SEAL
mkdir build
cd build
cmake .. -DSEAL_THROW_ON_TRANSPARENT_CIPHERTEXT=OFF -DCMAKE_INSTALL_PREFIX=./install
make
make install
cd ../../..
