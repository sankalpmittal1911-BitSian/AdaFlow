$SDE_INSTALL/bin/bf-p4c AdaFlow_11Features.p4
cmake $SDE/p4studio -DCMAKE_MODULE_PATH="$SDE/cmake" -DCMAKE_INSTALL_PREFIX="$SDE_INSTALL" -DP4_PATH="/home/c310/P4-Project/AdaFlow_11Features.p4" -DP4_NAME="AdaFlow_11Features" -DP4_LANG="p4_16" -DTOFINO=ON -DTOFINO2=OFF
make
make install
