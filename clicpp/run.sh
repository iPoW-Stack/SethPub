sudo apt-get update
sudo apt-get install -y build-essential libssl-dev git autoconf libtool automake
sudo apt-get install libsecp256k1-dev nlohmann-json3-dev

git clone https://github.com/bitcoin-core/secp256k1.git
cd secp256k1
./autogen.sh
./configure --enable-module-recovery
make
sudo make install
sudo ldconfig
cd ..

wget https://raw.githubusercontent.com/yhirose/cpp-httplib/master/httplib.h

g++ -std=c++17 client.cc -o client \
    -I/usr/local/include \
    -L/usr/local/lib \
    -lsecp256k1 -lssl -lcrypto -lpthread

./client