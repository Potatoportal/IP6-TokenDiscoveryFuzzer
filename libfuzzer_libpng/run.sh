#! /bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Working dir: $SCRIPT_DIR"
cargo build --release
if [ ! -d "$SCRIPT_DIR/libpng-1.6.37" ]; then
    echo "Target library missing downloading from https://github.com/glennrp/libpng/archive/refs/tags/v1.6.37.tar.gz"
    wget https://github.com/glennrp/libpng/archive/refs/tags/v1.6.37.tar.gz
    tar -xvzf v1.6.37.tar.gz
    rm -r v1.6.37.tar.gz 

    cd libpng-1.6.37 || exit 1
    ./configure --enable-shared=no --with-pic=yes --enable-hardware-optimizations=yes
    make CC="$SCRIPT_DIR/target/release/libafl_cc" CXX="$SCRIPT_DIR/target/release/libafl_cxx" -j `nproc`
    cd ..
fi

echo "Building the fuzzer"
exec "$SCRIPT_DIR/target/release/libafl_cxx" "$SCRIPT_DIR/harness.cc" "$SCRIPT_DIR/libpng-1.6.37/.libs/libpng16.a" -I "$SCRIPT_DIR/libpng-1.6.37/" -o "fuzzer_libpng" -lz -lm
echo "Starting fuzzer"
exec "$SCRIPT_DIR/fuzzer_libpng"
