# emssh fuzz corpus

This directory contains reusable fuzz artifacts for `emssh_fuzz_decode`.

## Files

- `corpus/`: initial seed corpus for decoder-oriented fuzzing.
- `emssh_fuzz.dict`: libFuzzer dictionary with SSH/SFTP protocol tokens.

## Local smoke run (non-libFuzzer mode)

```powershell
cmake -S . -B cmake-build-fuzz -DEMSSH_BUILD_FUZZERS=ON
cmake --build cmake-build-fuzz --config Debug --target emssh_fuzz_decode
cmake-build-fuzz\Debug\emssh_fuzz_decode.exe tests\fuzz\corpus\seed_ssh_ident.txt tests\fuzz\corpus\seed_sftp_ops.txt
```

## Local libFuzzer run (Clang/GCC)

```bash
cmake -S . -B build-fuzz -G Ninja \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DEMSSH_BUILD_EXAMPLES=OFF \
  -DEMSSH_BUILD_TESTS=OFF \
  -DEMSSH_BUILD_STDIO_FS=OFF \
  -DEMSSH_BUILD_TCP_SOCKET=OFF \
  -DEMSSH_BUILD_FUZZERS=ON \
  -DEMSSH_LIBFUZZER=ON
cmake --build build-fuzz --target emssh_fuzz_decode
./build-fuzz/emssh_fuzz_decode -dict=tests/fuzz/emssh_fuzz.dict tests/fuzz/corpus
```
