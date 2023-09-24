git submodule update --init --recursive
cd extern/SEAL
mkdir build
cd build
cmake .. -DSEAL_THROW_ON_TRANSPARENT_CIPHERTEXT=OFF
make
sudo make install
cd ../../..
