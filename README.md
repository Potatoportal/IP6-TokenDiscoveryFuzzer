# IP6-TokenDiscoveryFuzzer

This repository contains the implementation for a **Token-Based Fuzzer**, developed as part of a [bachelor thesis](./IP6_Doku%201.pdf). The work builds on research in [Token-Level Fuzzing](https://www.usenix.org/conference/usenixsecurity21/presentation/salls) and uses the open-source fuzzing framework [LibAFL](https://github.com/AFLplusplus/LibAFL).  

Our focus is on extending the concept of *tokens*—traditionally applied to text-based inputs—to **image formats**. Specifically, we explore how tokenization can be generalized to fuzz binary image-processing libraries such as **libpng** and **libmozjpeg**.

## Getting Started

This repository contains two fuzzers:  
- **libpng fuzzer**  
- **libmozjpeg fuzzer**

### Prerequisites
- Linux-based operating system (required for the provided scripts)  
- [Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html) (Rust package manager)  
- `wget`, `cmake`, `make` installed on your system  

---

### 1. Running the libpng Fuzzer
To run the **libpng** fuzzer:
```bash
cd libpng
./run.sh

```

### 2. Running the libmozjpeg Fuzzer

The **libmozjpeg** fuzzer requires downloading and compiling the `libmozjpeg` library before execution.

#### Step 1 — Download libmozjpeg
```bash
wget https://github.com/mozilla/mozjpeg/archive/v4.0.3.tar.gz
tar -xzvf v4.0.3.tar.gz
```

#### Step 2 — Build the Fuzzer Project
```bash
cargo build --release
```

#### Step 3 — Compile libmozjpeg
```bash
cd mozjpeg-4.0.3
cmake -DBUILD_SHARED_LIBS=OFF \
      -DCMAKE_C_COMPILER="$(pwd)/../target/release/libafl_cc" \
      -DCMAKE_CXX_COMPILER="$(pwd)/../target/release/libafl_cxx" \
      -G "Unix Makefiles" .
make -j"$(nproc)"
cd ..
```


#### Step 4 — Link and Build the Fuzzer
```bash
./target/release/libafl_cxx ./harness.cc ./mozjpeg-4.0.3/*.a -I ./mozjpeg-4.0.3/ -o fuzzer_mozjpeg
```

#### Step 5 — Run the Fuzzer
```bash
./fuzzer_mozjpeg
```

## Adding Token-Discovery to Your Project

[LibAFL](https://github.com/AFLplusplus/LibAFL) allows you to create **custom stages** for adding analysis or processing steps to your fuzzer.  

To use our token-discovery stage in your project:  

1. **Copy** the file [`test_stage.rs`](./test_stage.rs) into your project's `src` directory.  
2. **Add the following imports** to your main file:  

```rust
mod test_stage;
use test_stage::TestStage;
```

3. **Initialize the stage** with code like this:  

```rust
let test_stage: TestStage<_, _, BytesInput, _, _, CorpusPowerTestcaseScore, _, _, _> 
    = TestStage::new(mutator, &edges_observer);
```