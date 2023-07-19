$SDE_INSTALL/bin/bf-p4c Program.p4
cmake $SDE/p4studio -DCMAKE_MODULE_PATH="$SDE/cmake" -DCMAKE_INSTALL_PREFIX="$SDE_INSTALL" -DP4_PATH="/path/to/Program.p4" -DP4_NAME="Program" -DP4_LANG="p4_16" -DTOFINO=ON -DTOFINO2=OFF
make
make install
